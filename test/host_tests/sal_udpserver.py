"""
mbed OS
Copyright (c) 2011-2016 ARM Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import sys
import socket
import select
import threading
from sys import stdout
from SocketServer import BaseRequestHandler, UDPServer, _eintr_retry
from mbed_host_tests import BaseHostTest

# The watchdog is used to terminate the udp helper thread in the 
# event of an error condition. This graceful cleanup is required in 
# particular for the test automation environment where failure to 
# terminate the thread will leaving a python process and the 
# inability of the automation system to reuse the server port.
# The value of the timeout is set to equal the minimum 
# MBED_HOSTTEST_TIMEOUT value of the target tests using this script
# (currently udp_echo_client.cpp). 
SAL_UDPSERVER_WATCHDOG_TIMOUT = 60.0

SalUdpServerDebug=False

class SalUdpServer(UDPServer):
    """ UDP Server derived class with a custom serve_forever() implementation 
    for implementing detection of shutdown command allowing graceful 
    termination of the host test script"""
     
    address_family = socket.AF_INET
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        UDPServer.__init__(self, server_address, RequestHandlerClass)
        self._shutdown_request = False
        
        # watchdog guards against the failure mode when the remote target fails 
        # to send any packets. If the watchdog reaches the high water mark, the 
        # server is terminated so as not to leave the server thread unterminated
        self.watchdog = 0.0

    def serve_forever(self, poll_interval=0.5):
        """Provide an override that can be shutdown from a request handler.
        The threading code in the BaseSocketServer class prevented this from working
        even for a non-threaded blocking server.
        """
        try:
            while not self._shutdown_request:
                r, w, e = _eintr_retry(select.select, [self], [], [], poll_interval)
                if self in r:
                    # reset watchdog
                    self.watchdog = 0.0
                    self._handle_request_noblock()
                
                else:
                    self.watchdog += poll_interval
                if self.watchdog > SAL_UDPSERVER_WATCHDOG_TIMOUT:
                    self._shutdown_request = True

        finally:
            self._shutdown_request = False


class SalUdpServerEchoCallback(BaseRequestHandler):
    """UDP Server callback handler for processing rx-ed data. Received data is 
    echoed back to the sender """

    def handle(self):
        """ One handle per connection
        """
        try:
            data, socket = self.request
            print("HOST: Received %d bytes of data" % len(data))
            
            if SalUdpServerDebug == True:
                print "HOST: sending the data back to transmitter at:" 
                print  self.client_address
                print "HOST: data:"
                print data
                print "HOST: %d bytes sendto() client %s" % (len, str(self.client_address))
                            
            if 'shutdown' in data:
                self.server._shutdown_request = True
            else:
                tx_bytes = socket.sendto(data, self.client_address)
                print("HOST: Sent %d bytes of data" % tx_bytes)
            
        except Exception as e:
            print("HOST: detected unexpected exception: %s" % str(e))
                

class SalUdpServerTest(BaseHostTest):
    """
    mbed greentea framework host test script for udp_echo_client server 
    side functionality. The test does the following:
      - creates a UDP Server for echo back to sender any packets received.
      - communicates the udp server {ipaddr, port} to the DUT via serial
        so the DUT can send packets to the udp server.
      - The DUT will send udp packets of various lengths and the UDP server 
        will echo them back again.
      - When finished, the DUT will send a shutdown command to the UDP 
        server causing the udp server thread to terminate, and this 
        function to return.    
    """
    
    name = 'sal_udpserver'

    def send_server_ip_port(self, selftest, ip_address, port_no):
        """send the udp server {ipaddr, port} to target via serial console."""

        self.watchdog = 0.0
        
        # Read 3 lines which are sent from client
        print "HOST: About to read 3 lines from target before sending UDP Server {ipaddr, port} tuple." 
        for i in range(0, 3):
            c = selftest.mbed.serial_readline()
            if c is None:
                selftest.print_result(self.RESULT_IO_SERIAL)
                return
            print "MBED: " + c.strip()

        print "HOST: Sending server IP Address to target..."
        connection_str = ip_address + ":" + str(port_no) + "\n"
        selftest.mbed.serial_write(connection_str)

        # mbed greentea framwork support the following for outputing serial console emitted 
        # from the target, but it doesnt work relibly for me.
        # selftest.dump_serial()
        # selftest.dump_serial_end()
        
        # until its fixed, the following emits the serial console trace
        while True:
            c = selftest.mbed.serial_readline()
            if c is None:
                selftest.print_result(self.RESULT_IO_SERIAL)
                return
            print "MBED: " + c.strip()
            
            # look for the end tag in serial output denoting the test has 
            # finished, and this can return.
            if c.strip() == "{{end}}":
                print "HOST: Terminating Test"
                break
        
            # null lines are periodically generated, which can be used to trigger the watchdog
            elif c.strip() == "":
                self.watchdog += 1.0
                if self.watchdog > SAL_UDPSERVER_WATCHDOG_TIMOUT:
                    break
            
            else:
                # reset watchdog
                self.watchdog = 0.0

        return selftest.RESULT_SUCCESS 

    def test(self, selftest):
        """ Method invoked by test framework to implement udp_echo_client 
        server side functionality."""
        
        # socket functions used are selected to promote portability across
        # windows, linux and mac.
        srv_ipaddr = socket.gethostbyname(socket.gethostname())
        self.udpserver = SalUdpServer((srv_ipaddr, 0), SalUdpServerEchoCallback)
        srv_port = self.udpserver.socket.getsockname()[1]

        print "HOST: Listening for UDP connections on %s:%d." %(srv_ipaddr, srv_port) 
        udp_thread = threading.Thread(target=self.udpserver.serve_forever)
        udp_thread.start()
        
        self.send_server_ip_port(selftest, srv_ipaddr, srv_port)
        
