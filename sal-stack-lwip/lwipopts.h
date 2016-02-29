/*
 * Copyright (c) 2012-2015, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#include "lwipopts_conf.h"

// Operating System
#define NO_SYS 1

#if NO_SYS == 0
#include "cmsis_os.h"

#define SYS_LIGHTWEIGHT_PROT        1

#define LWIP_RAW                    0

#define TCPIP_MBOX_SIZE             8
#define DEFAULT_TCP_RECVMBOX_SIZE   8
#define DEFAULT_UDP_RECVMBOX_SIZE   8
#define DEFAULT_RAW_RECVMBOX_SIZE   8
#define DEFAULT_ACCEPTMBOX_SIZE     8

#define TCPIP_THREAD_STACKSIZE      1024
#define TCPIP_THREAD_PRIO           (osPriorityNormal)

#define DEFAULT_THREAD_STACKSIZE    512

#define MEMP_NUM_SYS_TIMEOUT        16

#else // #if NO_SYS == 0

// TODO: this "probably" needs more options
#define SYS_LIGHTWEIGHT_PROT        1
#define LWIP_RAW                    1
#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0
#define MEMP_NUM_SYS_TIMEOUT        16
//#define LWIP_DEBUG

#endif // #if NO_SYS == 0

// 8-byte alignment to match ARM's ABI
#define MEM_ALIGNMENT               8

#define PBUF_POOL_SIZE              5
#define MEMP_NUM_TCP_PCB_LISTEN     4

#ifdef YOTTA_CFG_MBED_OS_NET_TCP_MAX_STREAMS
#define MEMP_NUM_TCP_PCB            (YOTTA_CFG_MBED_OS_NET_TCP_MAX_STREAMS)
#else
#define MEMP_NUM_TCP_PCB            4
#endif

#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT 1

#define MEMP_NUM_PBUF               8

#define TCP_QUEUE_OOSEQ             0
#define TCP_OVERSIZE                0

#define LWIP_DHCP                   1
#define LWIP_DNS                    1

// Support Multicast
#include "stdlib.h"
#define LWIP_IGMP                   1
#define LWIP_RAND()                 rand()

#define LWIP_COMPAT_SOCKETS         0
#define LWIP_POSIX_SOCKETS_IO_NAMES 0
#define LWIP_SO_RCVTIMEO            1
#define LWIP_TCP_KEEPALIVE          1

// Debug Options
// #define LWIP_DEBUG
#define UDP_LPC_EMAC                LWIP_DBG_ON
#define SYS_DEBUG                   LWIP_DBG_OFF
#define PPP_DEBUG                   LWIP_DBG_OFF
#define IP_DEBUG                    LWIP_DBG_ON
#define MEM_DEBUG                   LWIP_DBG_OFF
#define MEMP_DEBUG                  LWIP_DBG_OFF
#define PBUF_DEBUG                  LWIP_DBG_OFF
#define API_LIB_DEBUG               LWIP_DBG_OFF
#define API_MSG_DEBUG               LWIP_DBG_OFF
#define TCPIP_DEBUG                 LWIP_DBG_OFF
#define SOCKETS_DEBUG               LWIP_DBG_OFF
#define TCP_DEBUG                   LWIP_DBG_OFF
#define TCP_INPUT_DEBUG             LWIP_DBG_OFF
#define TCP_FR_DEBUG                LWIP_DBG_OFF
#define TCP_RTO_DEBUG               LWIP_DBG_OFF
#define TCP_CWND_DEBUG              LWIP_DBG_OFF
#define TCP_WND_DEBUG               LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG            LWIP_DBG_OFF
#define TCP_RST_DEBUG               LWIP_DBG_OFF
#define TCP_QLEN_DEBUG              LWIP_DBG_OFF
#define ETHARP_DEBUG                LWIP_DBG_OFF
#define NETIF_DEBUG                 LWIP_DBG_OFF
#define DHCP_DEBUG                  LWIP_DBG_OFF

#ifdef LWIP_DEBUG
#define MEMP_OVERFLOW_CHECK         1
#define MEMP_SANITY_CHECK           1
#else
#define LWIP_NOASSERT               1
#define LWIP_STATS                  0
#endif

#define LWIP_PLATFORM_BYTESWAP      1

#if LWIP_TRANSPORT_ETHERNET

/* MSS should match the hardware packet size */
#define TCP_MSS                     1460
#define TCP_SND_BUF                 (2 * TCP_MSS)
#define TCP_WND                     (2 * TCP_MSS)
#define TCP_SND_QUEUELEN            (2 * TCP_SND_BUF/TCP_MSS)

// Broadcast
#define IP_SOF_BROADCAST            1
#define IP_SOF_BROADCAST_RECV       1

#define LWIP_BROADCAST_PING         1

#define LWIP_CHECKSUM_ON_COPY       1

#define LWIP_NETIF_HOSTNAME         1
#define LWIP_NETIF_STATUS_CALLBACK  1
#define LWIP_NETIF_LINK_CALLBACK    1

#elif LWIP_TRANSPORT_PPP

#define TCP_SND_BUF                     (3 * 536)
#define TCP_WND                         (2 * 536)

#define LWIP_ARP 0

#define PPP_SUPPORT 1
#define CHAP_SUPPORT                    1
#define PAP_SUPPORT                     1
#define PPP_THREAD_STACKSIZE            4*192
#define PPP_THREAD_PRIO 0

#define MAXNAMELEN                      64     /* max length of hostname or name for auth */
#define MAXSECRETLEN                    64

#else
#error A transport mechanism (Ethernet or PPP) must be defined
#endif

#endif /* LWIPOPTS_H_ */
