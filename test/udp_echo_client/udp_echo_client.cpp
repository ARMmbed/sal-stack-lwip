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

#include "mbed-net-socket-abstract/test/ctest_env.h"
#include "mbed-net-socket-abstract/test/sal_test_api.h"
#include "mbed-net-lwip/lwipv4_init.h"
#include "mbed-net-lwip-eth/EthernetInterface.h"
#include "mbed/test_env.h"

#define TEST_SERVER     buffer
#define TEST_PORT0      port
#define TEST_PORT1      port
#define TEST_PORT2      port

namespace {
    char buffer[32] = {0};

    struct s_ip_address {
        int ip_1;
        int ip_2;
        int ip_3;
        int ip_4;
    };
}

int main () {
    MBED_HOSTTEST_TIMEOUT(20);
    MBED_HOSTTEST_SELECT(test_socket_server_udp);
    MBED_HOSTTEST_DESCRIPTION(UDP echo client);
    MBED_HOSTTEST_START("NET_6");

    s_ip_address ip_addr = {0, 0, 0, 0};
    int port = 0;
    printf("MBED: UDPCllient waiting for server IP and port...\r\n");
    scanf("%d.%d.%d.%d:%d", &ip_addr.ip_1, &ip_addr.ip_2, &ip_addr.ip_3, &ip_addr.ip_4, &port);
    printf("MBED: Address received: %d.%d.%d.%d:%d\r\n", ip_addr.ip_1, ip_addr.ip_2, ip_addr.ip_3, ip_addr.ip_4, port);

    int tests_pass = 1;
    int rc;
    EthernetInterface eth;
    /* Initialise with DHCP, connect, and start up the stack */
    eth.init();
    eth.connect();

    printf("MBED: UDPClient IP Address is %s\r\n", eth.getIPAddress());
    sprintf(buffer, "%d.%d.%d.%d", ip_addr.ip_1, ip_addr.ip_2, ip_addr.ip_3, ip_addr.ip_4);

    do {
        socket_error_t err = lwipv4_socket_init();
        if (!TEST_EQ(err,SOCKET_ERROR_NONE)) {
            tests_pass = 0;
            break;
        }
        rc = socket_api_test_create_destroy(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET6);
        tests_pass = tests_pass && rc;

        rc = socket_api_test_socket_str2addr(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET6);
        tests_pass = tests_pass && rc;
        // Need create/destroy for all subsequent tests
        // str2addr is required for connect test
        if (!tests_pass) break;

        rc = socket_api_test_connect_close(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET6, TEST_SERVER, TEST_PORT0);
        tests_pass = tests_pass && rc;

        rc = socket_api_test_echo_client_connected(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET4, SOCKET_STREAM, true, TEST_SERVER, TEST_PORT0);
        tests_pass = tests_pass && rc;

        rc = socket_api_test_echo_client_connected(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET4, SOCKET_DGRAM, true, TEST_SERVER, TEST_PORT1);
        tests_pass = tests_pass && rc;

        rc = socket_api_test_echo_client_connected(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET4, SOCKET_DGRAM, false, TEST_SERVER, TEST_PORT1);
        tests_pass = tests_pass && rc;

        rc = socket_api_test_echo_server_stream(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET4, eth.getIPAddress(), TEST_PORT2);
        tests_pass = tests_pass && rc;
    } while (0);

    MBED_HOSTTEST_RESULT(tests_pass);
    return !tests_pass;
}
