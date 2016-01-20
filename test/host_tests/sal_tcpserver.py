# Copyright 2015 ARM Limited
#
# Licensed under the Apache License, Version 2.0
# See LICENSE file for details.

import sys
import socket
import select
import time
import threading
from SocketServer import BaseRequestHandler, TCPServer, _eintr_retry
from mbed_host_tests import BaseHostTest


class TCPServerV4(TCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        TCPServer.__init__(self, server_address, RequestHandlerClass)
        self._shutdown_request = False
        
        # watchdog guards against the failure mode when the remote target fails 
        # to send any packets. If the watchdog reaches the high water mark, the 
        # server is terminated so as not to leave the server thread unterminated
        self.watchdog = 0.0

    def serve_forever(self, poll_interval=0.5):
        """provide an override that can be shutdown from a request handler.
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
                
                
                if self.watchdog > 20.0:
                    self._shutdown_request = True
                
        finally:
            self._shutdown_request = False
        
        

class TCPHandler(BaseRequestHandler):
    MAX_RX_SIZE = 8192
    def handle(self):
        """ One handle per connection
        """
        print("HOST: Connection received...\n")
        while True:
            try:
                data = self.request.recv(self.MAX_RX_SIZE)
            except Exception as e:
                    print("HOST: detected unexpected exception: %s" % str(e))
                    break
                
            if not data: 
                break
            
            print("HOST: Received %s bytes of data\n" % len(data))
            
            # try not shutting down the connection and wait for the remote end to close it
            if data == "shutdown":
                print("HOST: Requesting server shutdown\n")
                # give the remote end time to close its connection, which is part of the test
                time.sleep(5)
                self.server._shutdown_request = True
                break

            self.request.sendall(data)
            

class SalTcpServerTest(BaseHostTest):
    ERR_SUCCESS = "success"
    name = 'sal_tcpserver'

    def send_server_ip_port(self, selftest, ip_address, port):
        """ Set up network host. Reset target and and send server IP via 
        serial to a mbed board."""

        self.watchdog = 0

        # Read 3 lines which are sent from client, This will be fixed in greentea
        for i in range(0, 3):
            c = selftest.mbed.serial_readline()
            if c is None:
                selftest.print_result(self.RESULT_IO_SERIAL)
                return
            selftest.notify("MBED: " + c.strip())


        selftest.notify("HOST: Sending server IP Address to target...")
        msg = ip_address + ":" + str(port) + "\n"
        selftest.mbed.serial_write(msg)
        
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
                self.watchdog += 1
                if self.watchdog > 10:
                    break
            
            else:
                # reset watchdog
                self.watchdog = 0

        
    def test(self, selftest):
        # Returning none will suppress host test from printing success code
        
        ret = self.ERR_SUCCESS
        srv_ipaddr = socket.gethostbyname(socket.gethostname())
        self.tcpserver = TCPServerV4((srv_ipaddr, 0), TCPHandler)
        srv_port = self.tcpserver.socket.getsockname()[1]
        self.tcp_thread = threading.Thread(target=self.tcpserver.serve_forever)
        self.tcp_thread.start()
        
        self.send_server_ip_port(selftest, srv_ipaddr, srv_port)
        #return ret

    def rampDown(self):
        self.tcpserver.server_close()

