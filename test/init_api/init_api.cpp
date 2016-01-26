/**
 * @file init_api.cpp
 *
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

/* The mbed greentea host test watchdog timeout value is set such that
 * the test case is expected to report the test {{end}} terminator
 * before the timeout value expires. If this is not the case, greentea
 * will terminate the test case and perform recovery actions.
 */
#ifndef INIT_API_MBED_HOSTTEST_TIMEOUT
#define INIT_API_MBED_HOSTTEST_TIMEOUT 60
#endif

/** @brief Main application entry point for the test case
 *
 *  This mbed greentea test case implements a test case for socket creation
 *  and the conversion of a dotted decimal string to a struct socket_addr.
 *  @return void
 */
void app_start(int, char**)
{
    int i = 0;
    int tests_pass = 1;
    int rc;
    /* DHCP lookup can take several seconds e.g. 10s (in some cases much longer)
     * Taking 10s as a reasonable figure
     *   5 * 10s = 50s,
     * 50s is shorter than INIT_API_MBED_HOSTTEST_TIMEOUT
     */
    const int max_dhcp_retries = 5;
    EthernetInterface eth;

    /* mbed greentea init */
    MBED_HOSTTEST_TIMEOUT(INIT_API_MBED_HOSTTEST_TIMEOUT);
    MBED_HOSTTEST_SELECT(default);
    MBED_HOSTTEST_DESCRIPTION(Socket Abstraction Layer construction and utility test);
    MBED_HOSTTEST_START("SAL_INIT_UTIL");

    /* Initialise with DHCP, connect, and start up the stack */
    eth.init();

    /* if the interface fails to get a dhcp lease then retry */
    for(i = 0; i < max_dhcp_retries; i++)
    {
       rc = eth.connect();
        /* break if we get a lease */
       if(rc == 0)
       {
           printf("TCP client IP Address is %s\r\n", eth.getIPAddress());
           break;
       }
       else
       {
           printf("DHCP failure number %d. Retrying DHCP.\r\n", i);
       }

    }
    if(i == max_dhcp_retries)
    {
        printf("Maximum number of DHCP retries (%d) exceeded. Terminating test.\r\n", i);
        tests_pass = 0;
        notify_completion(tests_pass);
        return;
    }

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

    } while (0);
    MBED_HOSTTEST_RESULT(tests_pass);
}
