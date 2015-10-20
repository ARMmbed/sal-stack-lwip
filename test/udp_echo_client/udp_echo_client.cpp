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

#define TEST_SERVER "192.168.2.1"
#define TEST_PORT0 32767
#define TEST_PORT1 32766
#define TEST_PORT2 32765

void app_start(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    int tests_pass = 1;
    int rc;
    EthernetInterface eth;
    /* Initialise with DHCP, connect, and start up the stack */
    eth.init();
    eth.connect();
    notify_start();

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

        rc = socket_api_test_connect_close(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET6,TEST_SERVER, TEST_PORT0);
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
    notify_completion(tests_pass);
}
