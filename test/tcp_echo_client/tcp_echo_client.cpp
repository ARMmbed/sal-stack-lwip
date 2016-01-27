/**
 * @file tcp_echo_client.cpp
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
#include "sal/socket_api.h"

/*
 * Defines
 */
#ifndef TCP_EC_SOCKET_TEST_TIMEOUT
#define TCP_EC_SOCKET_TEST_TIMEOUT 1.0f
#endif

/* The mbed greentea host test watchdog timeout value is set such that
 * the test case is expected to report the test {{end}} terminator
 * before the timeout value expires. If this is not the case, greentea
 * will terminate the test case and perform recovery actions.
 */
#ifndef TCP_ECHO_CLIENT_MBED_HOSTTEST_TIMEOUT
#define TCP_ECHO_CLIENT_MBED_HOSTTEST_TIMEOUT 60
#endif

/*
 * Globals
 */
static struct socket *tcp_ec_client_socket_g;
static volatile bool tcp_ec_client_event_done_g;
static volatile bool tcp_ec_client_rx_done_g;
static volatile bool tcp_ec_client_tx_done_g;
static volatile struct socket_tx_info tcp_ec_client_tx_info_g;
static volatile struct socket_event tcp_ec_client_event_g;
static volatile int tcp_ec_closed;
static volatile int tcp_ec_connected;

volatile int tcp_ec_timeout_g;
static void onTimeout() {
    tcp_ec_timeout_g = 1;
}


/** @brief Pretty print a socket address and port with description
 *
 *  @param description  Client string to provide contextual information for
 *                      the ipaddr:port tuple
 *  @param addr         IP address data structure
 *  @param port         port number
 *  @return void
 */
static inline void tcp_ec_sock_addr_port_dump(const char* description, struct socket_addr* saddr, uint16_t port)
{
    if(saddr)
    {
        TEST_PRINT("%s:%s:%d\r\n", description, inet_ntoa(*saddr), port);
    }
}

/** @brief Callback function for handling tx/rx/etc event indications.
 *  @return void
 */
static void tcp_ec_client_cb()
{
    struct socket_event *e = tcp_ec_client_socket_g->event;
    event_flag_t event = e->event;
    switch (event) {
        case SOCKET_EVENT_RX_DONE:
            tcp_ec_client_rx_done_g = true;
            break;
        case SOCKET_EVENT_TX_DONE:
            tcp_ec_client_tx_done_g = true;
            tcp_ec_client_tx_info_g.sentbytes = e->i.t.sentbytes;
            break;
        case SOCKET_EVENT_DISCONNECT:
            tcp_ec_closed = 1;
            break;
        case SOCKET_EVENT_CONNECT:
            tcp_ec_connected = 1;
            break;
        default:
            memcpy((void *) &tcp_ec_client_event_g, (const void*)e, sizeof(e));
            tcp_ec_client_event_done_g = true;
            break;
    }
}

/** @brief Send a shutdown command to the host test script to terminate host PC
 *         test.
 *  @param srv_addr_s Dotted decimal ip addr string of the remote tcp echo
 *                    server.
 *  @param srv_port   Port number of the remote tcp echo relay server.
 *  @return int, 0 => success, !=0 => failure.
 */
static int tcp_ec_send_shutdown_host_script(const char* srv_addr_s, uint16_t srv_port)
{
    int ret = 0;
    struct socket s;
    socket_error_t err;
    struct socket_addr srv_saddr = {0, 0, 0, 0};
    struct socket_addr local_saddr = {0, 0, 0, 0};
    struct socket_addr local_saddr_chk = {0, 0, 0, 0};
    const struct socket_api *api = socket_get_api(SOCKET_STACK_LWIP_IPV4);
    mbed::Timeout to;
    const char* shutdown_cmd = "shutdown";
    uint16_t local_port = 0;
    uint16_t local_port_chk = 0;

    TEST_CLEAR();
    tcp_ec_client_socket_g = &s;

    /* Create the socket */
    err = api->init();
    if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
        TEST_RETURN();
    }
    s.impl = NULL;
    err = api->create(&s, SOCKET_AF_INET4, SOCKET_STREAM, &tcp_ec_client_cb);
    if (!TEST_EQ(err, SOCKET_ERROR_NONE))
    {
        TEST_EXIT();
    }
    err = api->bind(&s, &local_saddr, local_port);
    if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
        TEST_RETURN();
    }

    /* check socket is bound to to a local ip addr:port */
    api->get_local_addr(&s, &local_saddr_chk);
    api->get_local_port(&s, &local_port_chk);
    /* check that the local_saddr is not 0.0.0.0 */
    ret = socket_addr_is_any(&local_saddr);
    if(!TEST_EQ(ret, 0)) {
        TEST_PRINT("[FAIL] bind() failed as local address (%s) is INADDR_ANY\r\n", inet_ntoa(local_saddr_chk));
    }
    if(!TEST_EQ(local_port_chk, 0)) {
        TEST_PRINT("[FAIL] bind() failed as local port (%d) is 0\r\n", local_port_chk);
    }

    err = api->str2addr(&s, &srv_saddr, srv_addr_s);
    TEST_EQ(err, SOCKET_ERROR_NONE);
    tcp_ec_sock_addr_port_dump("server", &srv_saddr, srv_port);

    tcp_ec_timeout_g = 0;
    tcp_ec_connected = 0;
    to.attach(onTimeout, TCP_EC_SOCKET_TEST_TIMEOUT);
    err = api->connect(&s, &srv_saddr, srv_port);
    TEST_EQ(err, SOCKET_ERROR_NONE);
    if (err!=SOCKET_ERROR_NONE) {
        printf("err = %d\r\n", err);
    }
    while (!tcp_ec_connected && !tcp_ec_timeout_g)
    {
        __WFI();
    }
    to.detach();
    TEST_EQ(tcp_ec_timeout_g, 0);

    tcp_ec_client_tx_done_g = false;
    tcp_ec_client_rx_done_g = false;
    tcp_ec_timeout_g = 0;
    to.attach(onTimeout, TCP_EC_SOCKET_TEST_TIMEOUT);
    err = api->send(&s, shutdown_cmd, strlen(shutdown_cmd));
    if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
        TEST_PRINT("Failed to send shutdown command %u bytes. err=%s\r\n", strlen(shutdown_cmd), socket_strerror(err));
    }
    else
    {
        size_t tx_bytes = 0;
        do {
            /* Wait for the onSent callback */
            while (!tcp_ec_timeout_g && !tcp_ec_client_tx_done_g) {
                __WFI();
            }
            if (!TEST_EQ(tcp_ec_timeout_g,0)) {
                break;
            }
            if (!TEST_NEQ(tcp_ec_client_tx_info_g.sentbytes, 0)) {
                break;
            }
            tx_bytes += tcp_ec_client_tx_info_g.sentbytes;
            if (tx_bytes < strlen(shutdown_cmd)) {
                tcp_ec_client_tx_done_g = false;
                continue;
            }
            to.detach();
            TEST_EQ(tx_bytes, strlen(shutdown_cmd));
            break;
        } while (1);
    }

    /* this test depends on us closing the socket before the remote peer does
     * if the remote server were to close first then the closing a closed connection
     * would return an error. For this reason the sal_tcpserver waits 5s before terminating
     * the server */
    err = api->close(&s);
    TEST_EQ(err, SOCKET_ERROR_NONE);

    /* destroy the socket */
    err = api->destroy(&s);
    TEST_EQ(err, SOCKET_ERROR_NONE);

test_exit:
    TEST_RETURN();
    return 0;
}


/** @brief Main application entry point for the test case
 *
 *  This mbed greentea test case implements a tcp client which sends/receive
 *  data to/from to the tcp echo server (sal_tcpserver.py).
 *  @return void
 */
void app_start(int , char **)
{
    char* ptr = NULL;
    int i = 0;
    int tests_pass = 1;
    /* DHCP lookup can take several seconds e.g. 10s (in some cases much longer)
     * Taking 10s as a reasonable figure
     *   5 * 10s = 50s,
     * 50s is shorter than TCP_ECHO_CLIENT_MBED_HOSTTEST_TIMEOUT
     */
    const int max_dhcp_retries = 5;
    int rc;
    char ipbuffer[32];
    int port = 0;

    /* mbed greentea init */
    MBED_HOSTTEST_TIMEOUT(TCP_ECHO_CLIENT_MBED_HOSTTEST_TIMEOUT);
    MBED_HOSTTEST_SELECT(sal_tcpserver);
    MBED_HOSTTEST_DESCRIPTION(SalTcpServerTest);
    MBED_HOSTTEST_START("Socket Abstract Layer TCP Connection/Tx/Rx Socket Stream Test");

    printf("MBED: SAL TCP Client waiting for server IP and port...\r\n");
    scanf("%s", ipbuffer);
    if( (ptr = strchr(ipbuffer, ':')) != NULL )
    {
        port = atoi(ptr+1);
        *ptr = '\0';
        printf("MBED: Address received: %s:%d\r\n", ipbuffer, port);
    }
    else
    {
        printf("MBED: Failed to receive ip address:port\r\n");
        tests_pass = 0;
        notify_completion(tests_pass);
        return;
    }

    EthernetInterface eth;
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
        rc = socket_api_test_connect_close(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET4, ipbuffer, port);
        tests_pass = tests_pass && rc;

        rc = socket_api_test_echo_client_connected(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET4, SOCKET_STREAM, true, ipbuffer, port);
        tests_pass = tests_pass && rc;

        rc = tcp_ec_send_shutdown_host_script(ipbuffer, port);
        tests_pass = tests_pass && rc;

    } while (0);
    notify_completion(tests_pass);
}
