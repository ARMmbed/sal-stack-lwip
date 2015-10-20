/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2015 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sal/test/ctest_env.h"
#include "sal/test/sal_test_api.h"
#include "sal-stack-lwip/lwipv4_init.h"
#include "EthernetInterface.h"
#include "mbed-drivers/test_env.h"

void app_start(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    MBED_HOSTTEST_TIMEOUT(20);
    MBED_HOSTTEST_SELECT(tcpecho_client_ext_auto);
    MBED_HOSTTEST_DESCRIPTION(Socket Abstraction Layer TCP Echo Client test);
    MBED_HOSTTEST_START("SAL_TCP_ECHO_CLIENT");

    int tests_pass = 1;
    int rc;
    char ipbuffer[16];

    struct s_ip_address
    {
        int ip_1;
        int ip_2;
        int ip_3;
        int ip_4;
    } ip_addr = {0, 0, 0, 0};
    int port = 0;

    printf("MBED: TCPCllient waiting for server IP and port...\r\n");
    scanf("%d.%d.%d.%d:%d", &ip_addr.ip_1, &ip_addr.ip_2, &ip_addr.ip_3, &ip_addr.ip_4, &port);
    printf("MBED: Address received: %d.%d.%d.%d:%d\r\n", ip_addr.ip_1, ip_addr.ip_2, ip_addr.ip_3, ip_addr.ip_4, port);

    EthernetInterface eth;
    /* Initialise with DHCP, connect, and start up the stack */
    eth.init();
    eth.connect();
    printf("TCP client IP Address is %s\r\n", eth.getIPAddress());

    printf("MBED: TCPClient IP Address is %s\r\n", eth.getIPAddress());
    sprintf(ipbuffer, "%d.%d.%d.%d", ip_addr.ip_1, ip_addr.ip_2, ip_addr.ip_3, ip_addr.ip_4);

    do {
        socket_error_t err = lwipv4_socket_init();
        if (!TEST_EQ(err,SOCKET_ERROR_NONE)) {
            tests_pass = 0;
            break;
        }
        rc = socket_api_test_connect_close(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET4, ipbuffer, port);
        tests_pass = tests_pass && rc;

        rc = socket_api_test_echo_client_connected(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET4, SOCKET_STREAM, true, ipbuffer, port);
        tests_pass = tests_pass && rc;
    } while (0);
    notify_completion(tests_pass);
}
