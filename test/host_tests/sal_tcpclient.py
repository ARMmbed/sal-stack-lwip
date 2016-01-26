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
import time
import threading
import re
from mbed_host_tests import BaseHostTest


class SalTcpClientTest(BaseHostTest):
    # The test loops through a sending/receiving data. On loop i the 
    # test send 2^(4+i) bytes where i = {0, 1, ... TX_LOOP_MAX}
    # This is intended to be a data channel functional test rather than a 
    # stress test so the max tx data length of 4096 bytes is appropriate. 
    TX_LOOP_MAX = 8
    # This is the maximum receive size used throught the sal-stack-lwip tests.
    # Tests are intended to be functional tests rather than stress test, and 
    # the maximum tx data length is currently 8192. 
    RX_SIZE_MAX=8192

    """
    mbed greentea framework host test script for tcp_echo_server client 
    side functionality. The test does the following:
      - Receives over the serial port the target ipaddr, port of the 
        target tcp server
      - establishes a connection with the remoted tcp echo server
      - sends ever increasing data buffers using send() starting with
        a 16 byte buffer and doubling the size of the data sent on each 
        iteration through the loop. 
      - When finished, a command is send to the remote tcp server to 
        cause it to terminate. 
    """

    name = 'sal_tcpclient'

    def tcp_client_tx_rx(self, ipaddrs, port):
        "Thread entrypoint for sending and receiving data to/from the remote tcp echo server."
      
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ipaddrs, port))
        
        tx_data = "1234567890abcdef"
        for i in xrange(self.TX_LOOP_MAX):
            s.send(tx_data)
            print "Host: sent %u bytes of data" % len(tx_data)
            rx_data = s.recv(len(tx_data))
            tx_data += tx_data
            print "Host: recevied %u bytes of data" % len(rx_data)

        # command to get the remove tcp server to terminate
        data = "quit"
        s.send(data)
        # let remote target terminate the tcp connection
        while True:
            data = s.recv(self.RX_SIZE_MAX)
            if not data: 
                break
        s.close()

        
    def test(self, selftest):
        # Returning none will suppress host test from printing success code
        """ main greentea host test script entry point which implements the functionality of the test as described above."""
        
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
            
            # find remote tcp server IP address in serial console stream:
            elif ">>> EC" in c.strip():
                # The ipddress is embedded in a string of the form ">>> EC,w.x.y.z,port_num"
                # extract the ipaddress and tx/rx packets to/from the target tcp server

                find_string = ">>> EC,"
                ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", c.strip())
                srv_ipaddrs = str(ip[0])
                print srv_ipaddrs
                port = c.strip().replace(find_string, "", 1)
                port = port.replace(str(ip[0])+",", "", 1)
                print str(port)
                srv_port = int(port)
                print "HOST: target reported tcp server: %s:%d" %(srv_ipaddrs, srv_port)
                
                self.tcp_client_thread = threading.Thread(target=self.tcp_client_tx_rx, args=(srv_ipaddrs, srv_port))
                self.tcp_client_thread.start()

  