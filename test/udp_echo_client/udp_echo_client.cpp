/**
 * @file udp_echo_client.cpp
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
#include "sal/test/ctest_env.h"
#include "sal-stack-lwip/lwipv4_init.h"
#include "sal/socket_api.h"
#include "EthernetInterface.h"
#include "mbed-drivers/test_env.h"
#include "mbed-drivers/Timeout.h"
#include "mbed-drivers/Ticker.h"
#include "mbed-drivers/mbed.h"


/*
 * Defines
 */
#ifndef SOCKET_TEST_TIMEOUT
#define SOCKET_TEST_TIMEOUT 1.0f
#endif

#ifndef SOCKET_SENDBUF_BLOCKSIZE
#define SOCKET_SENDBUF_BLOCKSIZE 32
#endif

#ifndef SOCKET_SENDBUF_MAXSIZE
#define SOCKET_SENDBUF_MAXSIZE 4096
#endif

#ifndef SOCKET_SENDBUF_ITERATIONS
#define SOCKET_SENDBUF_ITERATIONS 8
#endif

/* The mbed greentea host test watchdog timeout value is set such that
 * the test case is expected to report the test {{end}} terminator
 * before the timeout value expires. If this is not the case, greentea
 * will terminate the test case and perform recovery actions.
 */
#ifndef UDP_ECHO_CLIENT_MBED_HOSTTEST_TIMEOUT
#define UDP_ECHO_CLIENT_MBED_HOSTTEST_TIMEOUT 60
#endif

/*
 * Globals
 */
static struct socket *udp_ec_client_socket_g;
static volatile bool udp_ec_client_event_done_g;
static volatile bool udp_ec_client_rx_done_g;
static volatile bool udp_ec_client_tx_done_g;
static volatile struct socket_tx_info udp_ec_client_tx_info_g;
static volatile struct socket_event udp_ec_client_event_g;

volatile int udp_ec_timeout_g;
static void onTimeout() {
    udp_ec_timeout_g = 1;
}

typedef struct udp_ec_tx_rx_context_t
{
    EthernetInterface* eth_if;
} udp_ec_tx_rx_context_t;


/** @brief Pretty print a socket address and port with description
 *
 *  @param description  Client string to provide contextual information for
 *                      the ipaddr:port tuple
 *  @param addr         IP address data structure
 *  @param port         port number
 *  @return void
 */
static inline void udp_ec_sock_addr_port_dump(const char* description, struct socket_addr* saddr, uint16_t port)
{
	if(saddr)
	{
        TEST_PRINT("%s:%s:%d\r\n", description, inet_ntoa(*saddr), port);
	}
}

/** @brief Callback function for handling tx/rx/etc event indications.
 *  @return void
 */
static void udp_ec_client_cb()
{
    struct socket_event *e = udp_ec_client_socket_g->event;
    event_flag_t event = e->event;
    switch (event) {
        case SOCKET_EVENT_RX_DONE:
            udp_ec_client_rx_done_g = true;
            break;
        case SOCKET_EVENT_TX_DONE:
            udp_ec_client_tx_done_g = true;
            udp_ec_client_tx_info_g.sentbytes = e->i.t.sentbytes;
            break;
        default:
            memcpy((void *) &udp_ec_client_event_g, (const void*)e, sizeof(e));
            udp_ec_client_event_done_g = true;
            break;
    }
}

/** @brief Send a shutdown command to the host test script to terminate host
 *         pc test script.
 *
 *  @param srv_addr_s Dotted decimal ip addr string of the remote udp echo
 *                    server.
 *  @param srv_port   Port number of the remote udp echo relay server.
 *  @return int, 0 => success, !=0 => failure.
 */
static int udp_ec_send_shutdown_host_script(const char* srv_addr_s, uint16_t srv_port)
{
    struct socket s;
    socket_error_t err;
    struct socket_addr srv_saddr = {0, 0, 0, 0};
    struct socket_addr local_saddr = {0, 0, 0, 0};
    const struct socket_api *api = socket_get_api(SOCKET_STACK_LWIP_IPV4);
    mbed::Timeout to;
    const char* shutdown_cmd = "shutdown";
    uint16_t local_port = 0;

    TEST_CLEAR();
    udp_ec_client_socket_g = &s;

    /* Create the socket */
    err = api->init();
    if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
        TEST_RETURN();
    }
    s.impl = NULL;
    err = api->create(&s, SOCKET_AF_INET4, SOCKET_DGRAM, &udp_ec_client_cb);
    if (!TEST_EQ(err, SOCKET_ERROR_NONE))
    {
        TEST_EXIT();
    }
	err = api->bind(&s, &local_saddr, local_port);
	if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
		TEST_RETURN();
	}

    err = api->str2addr(&s, &srv_saddr, srv_addr_s);
    TEST_EQ(err, SOCKET_ERROR_NONE);
	udp_ec_sock_addr_port_dump("server", &srv_saddr, srv_port);

    udp_ec_client_tx_done_g = false;
    udp_ec_client_rx_done_g = false;
    udp_ec_timeout_g = 0;
    to.attach(onTimeout, SOCKET_TEST_TIMEOUT);
	err = api->send_to(&s, shutdown_cmd, strlen(shutdown_cmd), &srv_saddr, srv_port);
	if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
        TEST_PRINT("Failed to send shutdown command %u bytes. err=%s\r\n", strlen(shutdown_cmd), socket_strerror(err));
    }
	else
    {
        size_t tx_bytes = 0;
        do {
            /* Wait for the onSent callback */
            while (!udp_ec_timeout_g && !udp_ec_client_tx_done_g) {
                __WFI();
            }
            if (!TEST_EQ(udp_ec_timeout_g,0)) {
                break;
            }
            if (!TEST_NEQ(udp_ec_client_tx_info_g.sentbytes, 0)) {
                break;
            }
            tx_bytes += udp_ec_client_tx_info_g.sentbytes;
            if (tx_bytes < strlen(shutdown_cmd)) {
                udp_ec_client_tx_done_g = false;
                continue;
            }
            to.detach();
            TEST_EQ(tx_bytes, strlen(shutdown_cmd));
            break;
        } while (1);
    }

	/* this test depends on us closing the socket before the remote peer does */
	err = api->close(&s);
	TEST_EQ(err, SOCKET_ERROR_NONE);

    /* destroy the socket */
    err = api->destroy(&s);
    TEST_EQ(err, SOCKET_ERROR_NONE);

test_exit:
    return 0;
}

/** @brief This function implements a udp transmitter/receiver to send udp
 *         packets to a udp echo relay, and then received them back again.
 *         The rx packet data is compared with that transmitted to verify
 *         its the same.
 *
 *  @param srv_ipaddr_s Dotted decimal ip addr string of the remote udp echo
 *                      server.
 *  @param srv_port Port number of the remote udp echo relay server.
 *  @param connect connect == false => sendto(), recv_from() will be used.
 *                 connect == true => connect(), send(), recv() will be used.
 *  @param context context data needed to check if tests have passed.
 *  @return int, 0 => success, !=0 => failure.
 */
static int udp_ec_tx_rx_from_test(const char* srv_ipaddr_s, uint16_t srv_port, bool connect, udp_ec_tx_rx_context_t* context)
{
    int ret = 0;
    uint16_t local_port = 0;
    uint16_t rxport = 0;
    struct socket s;
    struct socket_addr srv_saddr = {0, 0, 0, 0};
    struct socket_addr rx_saddr = {0, 0, 0, 0};
    struct socket_addr local_saddr = {0, 0, 0, 0};
    struct socket_addr test_saddr = {0, 0, 0, 0};
    socket_error_t err;
    const struct socket_api *api = socket_get_api(SOCKET_STACK_LWIP_IPV4);
    mbed::Timeout to;

    TEST_PRINT("server: %s:%d\r\n", srv_ipaddr_s, (int) srv_port);
    udp_ec_client_socket_g = &s;
    TEST_CLEAR();
    if (!TEST_NEQ(api, NULL))
    {
        /* Test cannot continue without API. */
        TEST_RETURN();
    }
    err = api->init();
    if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
        TEST_RETURN();
    }

    void *data = malloc(SOCKET_SENDBUF_MAXSIZE);
    /* Zero the socket implementation, reason unknown */
    s.impl = NULL;
    err = api->create(&s, SOCKET_AF_INET4, SOCKET_DGRAM, &udp_ec_client_cb);
    if (!TEST_EQ(err, SOCKET_ERROR_NONE))
    {
        TEST_EXIT();
    }

    err = api->str2addr(&s, &srv_saddr, srv_ipaddr_s);
    TEST_EQ(err, SOCKET_ERROR_NONE);
	udp_ec_sock_addr_port_dump("remote udp server", &srv_saddr, srv_port);

	err = api->bind(&s, &local_saddr, local_port);
	if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
	    TEST_PRINT("bind() failed to local ipaddr:port\r\n");
		TEST_RETURN();
	}

	udp_ec_client_event_g.event = SOCKET_EVENT_CONNECT;
	udp_ec_client_event_done_g = true;

	/* check the binding of the local interface*/
	api->get_local_addr(&s, &local_saddr);
	api->get_local_port(&s, &local_port);
    udp_ec_sock_addr_port_dump("udp local after bind()", &local_saddr, local_port);

    if(connect)
    {
        err = api->connect(&s, &srv_saddr, srv_port);
        if (!TEST_EQ(err, SOCKET_ERROR_NONE))
        {
            TEST_EXIT();
        }
        api->get_local_addr(&s, &local_saddr);
        api->get_local_port(&s, &local_port);
        udp_ec_sock_addr_port_dump("udp local after connect()", &local_saddr, local_port);

        /* check that the local_saddr is not 0.0.0.0 */
        ret = socket_addr_is_any(&local_saddr);
        if(!TEST_EQ(ret, 0)) {
            TEST_PRINT("[FAIL] connect() failed as connected local address (%s) is INADDR_ANY\r\n", inet_ntoa(local_saddr));
        }

        /* check that the local_saddr is is the correct i/f to get to srv_saddr
         * this implementation assumes there is only 1 ethernet interface */
        inet_aton(context->eth_if->getIPAddress(), &test_saddr);
        ret = socket_addr_cmp(&local_saddr, &test_saddr);
        if(!TEST_EQ(ret, 0)) {
            TEST_PRINT("[FAIL] connect() failed as connected local address (%s) doesnt match ethernet i/f ip address(%s)\r\n", inet_ntoa(local_saddr), context->eth_if->getIPAddress());
        }
    }

    /* Loop for several iteration sending progressively larger packets */
    for (size_t i = 0; i < SOCKET_SENDBUF_ITERATIONS; i++)
    {
        /* Fill some data into a buffer */
        const size_t nWords = SOCKET_SENDBUF_BLOCKSIZE * (1 << i) / sizeof(uint16_t);
        for (size_t j = 0; j < nWords; j++) {
            *((uint16_t*) data + j) = j;
        }
        /* Send the data */
        udp_ec_client_tx_done_g = false;
        udp_ec_client_rx_done_g = false;
        udp_ec_timeout_g = 0;
        to.attach(onTimeout, SOCKET_TEST_TIMEOUT);
        if(connect)
        {
            err = api->send(&s, data, nWords * sizeof(uint16_t));
        }
        else
        {
            err = api->send_to(&s, data, nWords * sizeof(uint16_t), &srv_saddr, srv_port);
        }

		if (!TEST_EQ(err, SOCKET_ERROR_NONE))
		{
            TEST_PRINT("Failed to send %u bytes. err=%s\r\n", nWords * sizeof(uint16_t), socket_strerror(err));
        }
		else
        {
            size_t tx_bytes = 0;
            do {
                /* Wait for the onSent callback */
                while (!udp_ec_timeout_g && !udp_ec_client_tx_done_g) {
                    __WFI();
                }
                if (!TEST_EQ(udp_ec_timeout_g,0)) {
                    break;
                }
                if (!TEST_NEQ(udp_ec_client_tx_info_g.sentbytes, 0)) {
                    break;
                }
                tx_bytes += udp_ec_client_tx_info_g.sentbytes;
                if (tx_bytes < nWords * sizeof(uint16_t)) {
                    udp_ec_client_tx_done_g = false;
                    continue;
                }
                to.detach();
                if(TEST_EQ(tx_bytes, nWords * sizeof(uint16_t)))
                {
                    TEST_PRINT("TARGET sent %d bytes\r\n", tx_bytes);
                }
                else
                {
                    TEST_PRINT("ERROR: TARGET did not send successfully\r\n");
                }

                break;
            } while (1);
        }
        udp_ec_timeout_g = 0;
        to.attach(onTimeout, SOCKET_TEST_TIMEOUT);
        memset(data, 0, nWords * sizeof(uint16_t));

        /* Wait for the onReadable callback */
        size_t rx_bytes = 0;
        do
        {
        	while (!udp_ec_timeout_g && !udp_ec_client_rx_done_g) {
                __WFI();
            }
            if (!TEST_EQ(udp_ec_timeout_g,0)) {
                break;
            }
            size_t len = SOCKET_SENDBUF_MAXSIZE - rx_bytes;

			memcpy(&rx_saddr, &srv_saddr, sizeof(rx_saddr));
            if(connect)
            {
                err = api->recv(&s, (void*) ((uintptr_t) data + rx_bytes), &len);
            }
            else
            {
            	err = api->recv_from(&s, (void*) ((uintptr_t) data + rx_bytes), &len, &rx_saddr, &rxport);
            }

            if (!TEST_EQ(err, SOCKET_ERROR_NONE)) {
                TEST_PRINT("[FAIL] failed to receive packet data\r\n");
                break;
            }
			/* BUG: note returned port is correct for the first packet of a udp receive
			 * but if its fragmented then the 2nd call to receive returns an incorrect ipaddr and port.
			 */
			int rc = memcmp(&rx_saddr.ipv6be, &srv_saddr.ipv6be, sizeof(rx_saddr.ipv6be));
			if(!TEST_EQ(rc, 0)) {
	            udp_ec_sock_addr_port_dump("[FAIL] transmitter address", &rx_saddr, rxport);
				TEST_PRINT("[FAIL] Possibly packet fragment received, or spurious packet\r\n");
			}
			if(!TEST_EQ(rxport, srv_port))
			{
                udp_ec_sock_addr_port_dump("[FAIL] transmitter port error:server_ipaddr:srv_port", &srv_saddr, srv_port);
                udp_ec_sock_addr_port_dump("[FAIL] transmitter port error:rx_saddr:rxport", &rx_saddr, rxport);
			}
            rx_bytes += len;
            if (rx_bytes < nWords * sizeof(uint16_t)) {
                /* continue to try to receive the rest of the data*/
                continue;
            }
            else if(rx_bytes== nWords * sizeof(uint16_t))
            {
                TEST_PRINT("TARGET received %d bytes\r\n", rx_bytes);
                udp_ec_client_rx_done_g = true;
                break;
            }
        } while (1);
        to.detach();

        if(!TEST_EQ(rx_bytes, nWords * sizeof(uint16_t))) {
            TEST_PRINT("[FAIL] Expected %u, got %u\r\n", nWords * sizeof(uint16_t), rx_bytes);
        }

        /* Validate that the two buffers are the same */
        bool match = true;
        size_t j;
        for (j = 0; match && j < nWords; j++) {
            match = (*((uint16_t*) data + j) == j);
        }
        if(!TEST_EQ(match, true)) {
            TEST_PRINT("Mismatch in %u byte packet at offset %u\r\n", nWords * sizeof(uint16_t), j * sizeof(uint16_t));
        }
    }

	udp_ec_client_event_done_g = false;
	err = api->close(&s);
	TEST_EQ(err, SOCKET_ERROR_NONE);

    err = api->destroy(&s);
    TEST_EQ(err, SOCKET_ERROR_NONE);

test_exit:
    free(data);
    TEST_RETURN();
}

/** @brief main() for udp_echo_client test, which tests the socket abstraction
 *         layer
 *
 *  udp socket interface by doing the following:
 *  - calling init(), create(), bind(), sendto(), recv_from(), close(),
 *    destroy(), and sending/receiving various size packets including len>mtu.
 *  - calling init(), create(), bind(), connect(), send(), recv(), close(),
 *    destroy(), and sending/receiving various size packets including len>mtu.
 *
 *  @return void
 */
void app_start(int, char**)
{
    char udp_srv_ipaddr_s[32];
    char* ptr = NULL;
    int i = 0;
    int rc;
    int port = 0;
    int tests_pass = 1;
    /* DHCP lookup can take several seconds e.g. 10s (in some cases much longer)
     * Taking 10s as a reasonable figure
     *   5 * 10s = 50s,
     * 50s is shorter than UDP_ECHO_CLIENT_MBED_HOSTTEST_TIMEOUT
     */
    const int max_dhcp_retries = 5;
    EthernetInterface eth;
    udp_ec_tx_rx_context_t context = {&eth};

    /* mbed greentea init */
    MBED_HOSTTEST_TIMEOUT(UDP_ECHO_CLIENT_MBED_HOSTTEST_TIMEOUT);
    MBED_HOSTTEST_SELECT(sal_udpserver);
    MBED_HOSTTEST_DESCRIPTION(SalUdpServerTest);
    MBED_HOSTTEST_START("Socket Abstract Layer UDP Connection/Tx/Rx Socket Dgram Test");

    scanf("%s", udp_srv_ipaddr_s);
    if( (ptr = strchr(udp_srv_ipaddr_s, ':')) != NULL )
    {
        port = atoi(ptr+1);
        *ptr = '\0';
        printf("MBED: Address received: %s:%d\r\n", udp_srv_ipaddr_s, port);
    }
    else
    {
        printf("MBED: Failed to receive ip address:port\r\n");
        tests_pass = 0;
        notify_completion(tests_pass);
        return;
    }

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

    notify_start();

    do {
        socket_error_t err = lwipv4_socket_init();
        if (!TEST_EQ(err,SOCKET_ERROR_NONE)) {
            tests_pass = 0;
            break;
        }
        printf("\r\n");
        printf("MBED: calling socket_api_test_create_destroy()\r\n");
        rc = socket_api_test_create_destroy(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET6);
        tests_pass = tests_pass && rc;

        printf("\r\n");
        printf("MBED: calling socket_api_test_socket_str2addr()\r\n");
        rc = socket_api_test_socket_str2addr(SOCKET_STACK_LWIP_IPV4, SOCKET_AF_INET6);
        tests_pass = tests_pass && rc;

        /* Need create/destroy for all subsequent tests */
        if (!tests_pass) break;

        printf("\r\n");
        printf("MBED: calling udp_ec_tx_rx_from_test(connect=false) udp test using bind(), sendto(), recv_from() \r\n");
        rc = udp_ec_tx_rx_from_test(udp_srv_ipaddr_s, port, false, &context);
        tests_pass = tests_pass && rc;

        printf("\r\n");
        printf("MBED: calling udp_ec_tx_rx_from_test(connect=true) udp test using bind(), connect(), send(), recv() \r\n");
        rc = udp_ec_tx_rx_from_test(udp_srv_ipaddr_s, port, true, &context);
        tests_pass = tests_pass && rc;

        rc = udp_ec_send_shutdown_host_script(udp_srv_ipaddr_s, port);
        tests_pass = tests_pass && rc;

    } while (0);
    notify_completion(tests_pass);
}
