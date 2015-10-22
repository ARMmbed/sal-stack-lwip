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

/**
 * \file asynch_socket.c
 * \brief The LwIP implementation of the abstract C socket API.
 * This file implements LwIP's Socket Abstraction Layer.  Some compromises were necessary
 * to make LwIP fit the model of the SAL.  In particular, receive causes a heap allocation
 * to obtain the pbuf wrapper so that receive pbufs can be chained together with source
 * information.
 */
#include <stddef.h>
#include <stdint.h>

#include <mbed-net-socket-abstract/socket_api.h>

#include "lwipv4_init.h"

#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/tcp_impl.h"
#include "lwip/timers.h"
#include "lwip/dns.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"

#define SOCKET_ABSTRACTION_LAYER_VERSION 1

static uint8_t lwipv4_socket_is_connected(const struct socket *sock);
/** Forward declaration of the socket api */
const struct socket_api lwipv4_socket_api;
/**
 * \defgroup lwip_utility_functions Utility Functions
 * @{
 */
/**
 * Interrupt handler for UDP receive events
 * @param arg user supplied argument (udp_pcb.recv_arg)
 * @param pcb the udp_pcb which received data
 * @param p the packet buffer that was received
 * @param addr the remote IP address from which the packet was received
 * @param port the remote port from which the packet was received
 */
static void irqUDPRecv(void * arg, struct udp_pcb * upcb,
        struct pbuf * p,
        struct ip_addr * addr,
        u16_t port);
/**
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb The connection pcb which received data
 * @param p The received data (or NULL when the connection has been closed!)
 * @param err An error code if there has been an error receiving
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!

 * @return
 */
static err_t irqTCPRecv(void * arg, struct tcp_pcb * tpcb,
        struct pbuf * p, err_t err);
/**
 * Interrupt handler for TCP Receive
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb The connection pcb for which data has been acknowledged
 * @param len The amount of bytes acknowledged
 * @return ERR_OK: try to send some data by calling tcp_output
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
static err_t irqTCPSent(void *arg,struct tcp_pcb *tpcb, uint16_t len);

/**
 * @}
 */

socket_error_t lwipv4_socket_init() {
    return socket_register_stack(&lwipv4_socket_api);
}

static inline void ipv4_addr_cpy(void * dest, struct ip_addr *addr) {
    *(struct ip_addr *) dest = *addr;
}

socket_error_t lwipv4_socket_error_remap(err_t lwip_err)
{
    socket_error_t err = SOCKET_ERROR_UNKNOWN;
    switch (lwip_err) {
    case ERR_OK:
        err = SOCKET_ERROR_NONE;
        break;
    case ERR_MEM:
        err = SOCKET_ERROR_BAD_ALLOC;
        break;
    case ERR_BUF:
        break;
    case ERR_TIMEOUT:
        err = SOCKET_ERROR_TIMEOUT;
        break;
    case ERR_RTE:
    case ERR_INPROGRESS:
    case ERR_WOULDBLOCK:
        err = SOCKET_ERROR_BUSY;
        break;
    case ERR_VAL:
        err = SOCKET_ERROR_VALUE;
        break;
    case ERR_USE:
        err = SOCKET_ERROR_ADDRESS_IN_USE;
        break;
    case ERR_ISCONN:
        err = SOCKET_ERROR_ALREADY_CONNECTED;
        break;
    case ERR_ABRT:
        err = SOCKET_ERROR_ABORT;
        break;
    case ERR_RST:
        err = SOCKET_ERROR_RESET;
        break;
    case ERR_CLSD:
        err = SOCKET_ERROR_CLOSED;
        break;
    case ERR_CONN:
        err = SOCKET_ERROR_NO_CONNECTION;
        break;
    case ERR_ARG:
        err = SOCKET_ERROR_BAD_ARGUMENT;
        break;
    case ERR_IF:
        err = SOCKET_ERROR_INTERFACE_ERROR;
        break;
    }
    return err;
}

static socket_error_t init()
{
    return SOCKET_ERROR_NONE;
}


static socket_api_handler_t lwipv4_socket_periodic_task(const struct socket * sock)
{
    switch(sock->family)
    {
        case SOCKET_STREAM:
            return sys_check_timeouts;
        default:
            break;
    }
    return NULL;
}
static uint32_t lwipv4_socket_periodic_interval(const struct socket * sock)
{
    switch(sock->family)
    {
        case SOCKET_STREAM:
            return TCP_TMR_INTERVAL;
        default:
            break;
    }
    return 0;
}

static void dnscb(const char *name, struct ip_addr *addr, void *arg) {
  struct socket *sock = (struct socket *)arg;
  socket_api_handler_t handler = (socket_api_handler_t) sock->handler;
  socket_event_t e;
  if (addr == NULL) {
      e.event = SOCKET_EVENT_ERROR;
      e.i.e = SOCKET_ERROR_DNS_FAILED;
  } else {
      e.event = SOCKET_EVENT_DNS;
      // Install IPv4 prefix
      socket_addr_set_ipv4_addr(&e.i.d.addr, addr->addr);
      e.i.d.domain = name;
  }
  sock->event = &e;
  handler();
  sock->event = NULL;
}

static socket_error_t lwipv4_socket_resolve(struct socket *sock, const char *address)
{
    struct ip_addr ia;
    // attempt to resolve with DNS or convert to ip addr
    err_t err = dns_gethostbyname(address, &ia, dnscb, sock);
    if (err == ERR_OK) {
        dnscb(address, &ia, sock);
    }
    if (err == ERR_INPROGRESS)
        err = ERR_OK;
    return lwipv4_socket_error_remap(err);
}
static void tcp_error_handler(void *arg, err_t err)
{
    struct socket *sock = (struct socket *) arg;
    struct socket_event e;
    socket_api_handler_t h = sock->handler;
    e.event = SOCKET_EVENT_ERROR;
    e.i.e = lwipv4_socket_error_remap(err);
    sock->event = &e;
    h();
    sock->event = NULL;
}
static socket_error_t lwipv4_socket_create(struct socket *sock, const socket_address_family_t af, const socket_proto_family_t pf, socket_api_handler_t const handler)
{
    switch (af) {
        case SOCKET_AF_INET4:
            break;
        default:
            return SOCKET_ERROR_BAD_FAMILY;
    }
    if (sock == NULL || handler == NULL)
        return SOCKET_ERROR_NULL_PTR;
    switch (pf) {
    case SOCKET_DGRAM:
    {
        struct udp_pcb *udp = udp_new();
        if (udp == NULL)
            return SOCKET_ERROR_BAD_ALLOC;
        sock->stack = SOCKET_STACK_LWIP_IPV4;
        sock->impl = (void *)udp;
        udp_recv((struct udp_pcb *)sock->impl, irqUDPRecv, (void *)sock);
        break;
    }
    case SOCKET_STREAM:
    {
      struct tcp_pcb *tcp = tcp_new();
      if (tcp == NULL)
        return SOCKET_ERROR_BAD_ALLOC;
      sock->impl = (void *)tcp;
      sock->stack = SOCKET_STACK_LWIP_IPV4;
      tcp_arg(tcp, (void*) sock);
      tcp_err(tcp, tcp_error_handler);
      break;
    }
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    sock->family = pf;
    sock->handler = (void*)handler;
    sock->rxBufChain = NULL;
    return SOCKET_ERROR_NONE;
}

static socket_error_t lwipv4_socket_accept(struct socket *sock, socket_api_handler_t handler) {
    if (sock == NULL || sock->impl == NULL)
        return SOCKET_ERROR_NULL_PTR;
    switch (sock->family) {
    case SOCKET_DGRAM:
        return SOCKET_ERROR_UNIMPLEMENTED;
    case SOCKET_STREAM:
    {
      struct tcp_pcb *tcp = (struct tcp_pcb *)sock->impl;
      tcp_accepted(tcp);
      tcp_arg(tcp, (void*) sock);
      tcp_err(tcp, tcp_error_handler);
      tcp_sent(tcp,irqTCPSent);
      tcp_recv(tcp, irqTCPRecv);
      break;
    }
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    sock->handler = (void*)handler;
    sock->rxBufChain = NULL;
    return SOCKET_ERROR_NONE;
}

static socket_error_t lwipv4_socket_close(struct socket *sock)
{
    err_t err = ERR_OK;
    if (sock == NULL || sock->impl == NULL)
        return SOCKET_ERROR_NULL_PTR;
    switch (sock->family) {
    case SOCKET_DGRAM:
        udp_disconnect((struct udp_pcb *)sock->impl);
        break;
    case SOCKET_STREAM:
        err = tcp_close((struct tcp_pcb *)sock->impl);
        break;
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    return lwipv4_socket_error_remap(err);
}
static void lwipv4_socket_abort(struct socket *sock)
{
    if (sock == NULL || sock->impl == NULL)
        return;
    switch (sock->family) {
    case SOCKET_DGRAM:
        udp_remove((struct udp_pcb *)sock->impl);
        break;
    case SOCKET_STREAM:
        tcp_abort((struct tcp_pcb *)sock->impl);
        break;
    default:
        break;
    }
}
static socket_error_t lwipv4_socket_destroy(struct socket *sock)
{
    if (sock == NULL) {
        return SOCKET_ERROR_NULL_PTR;
    }

    if (sock->rxBufChain != NULL) {
        pbuf_free((struct pbuf*) sock->rxBufChain);
        sock->rxBufChain = NULL;
    }
    if (sock->impl != NULL) {
        if (lwipv4_socket_is_connected(sock)) {
            lwipv4_socket_close(sock);
        } else {
            lwipv4_socket_abort(sock);
        }
    }
    return SOCKET_ERROR_NONE;
}

static err_t irqConnect(void * arg, struct tcp_pcb * tpcb, err_t err)
{
    struct socket *sock = (struct socket *) arg;
    socket_api_handler_t handler = (socket_api_handler_t) sock->handler;
    socket_event_t e;
    tcp_sent(tpcb,irqTCPSent);
    tcp_recv(tpcb, irqTCPRecv);

    if (err != ERR_OK)
    {
        e.event = SOCKET_EVENT_ERROR;
        e.i.e = lwipv4_socket_error_remap(err);
    }
    else
    {
        e.event = SOCKET_EVENT_CONNECT;
    }
    sock->event = &e;
    handler();
    sock->event = NULL;
    return ERR_OK;
}

static socket_error_t lwipv4_socket_connect(struct socket *sock, const struct socket_addr *address, const uint16_t port)
{
    err_t err = ERR_OK;
    if (!socket_addr_is_ipv4(address)) {
        return SOCKET_ERROR_BAD_ADDRESS;
    }
    switch (sock->family){
    case SOCKET_DGRAM:
        err = udp_connect((struct udp_pcb *)sock->impl, (void*)socket_addr_get_ipv4_addrp(address), port);
        break;
    case SOCKET_STREAM:
        err = tcp_connect((struct tcp_pcb *)sock->impl, (void*)socket_addr_get_ipv4_addrp(address), port, irqConnect);
        break;
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    return lwipv4_socket_error_remap(err);
}
static socket_error_t str2addr(const struct socket *sock, struct socket_addr *address, const char *addr)
{
    socket_error_t err = SOCKET_ERROR_NONE;
    switch(sock->stack)  {
    case SOCKET_STACK_LWIP_IPV4: {
        ip_addr_t a;
        if (ipaddr_aton(addr, &a) == -1) {
            err = SOCKET_ERROR_BAD_ADDRESS;
        } else {
            socket_addr_set_ipv4_addr(address, (uint32_t) a.addr);
        }
        break;
    }
    default:
        break;
    }
    return err;
}

static err_t irqAccept (void * arg, struct tcp_pcb * newpcb, err_t err)
{
    struct socket * s = (struct socket *)arg;
    struct socket_event e;
    socket_api_handler_t handler = s->handler;
    e.sock = s;
    if (err != ERR_OK) {
        e.event = SOCKET_EVENT_ERROR;
        e.i.e = lwipv4_socket_error_remap(err);
        err = ERR_OK;
        s->event = &e;
        handler();
        s->event = NULL;
    } else {
        e.event = SOCKET_EVENT_ACCEPT;
        e.i.a.newimpl = newpcb;
        e.i.a.reject = 0;
        s->event = &e;
        handler();
        s->event = NULL;
        if (e.i.a.reject) {
            err = ERR_ABRT;
            tcp_abort(newpcb);
        }
    }
    return err;
}
static err_t irqAcceptNull (void * arg, struct tcp_pcb * newpcb, err_t err)
{
    (void) arg;
    (void) err;
    tcp_abort(newpcb);
    return ERR_ABRT;
}
static socket_error_t start_listen(struct socket *socket, uint32_t backlog)
{
    struct tcp_pcb * pcb = socket->impl;
    (void) backlog;
    if (pcb->state != LISTEN) {
        socket->impl = tcp_listen(socket->impl);
        if (socket->impl == NULL) {
            return SOCKET_ERROR_BAD_ALLOC;
        }
    }
    tcp_arg(socket->impl, socket);
    tcp_accept(socket->impl, irqAccept);
    return SOCKET_ERROR_NONE;
}
static socket_error_t stop_listen(struct socket *socket)
{
    tcp_accept(socket->impl, irqAcceptNull);
    return SOCKET_ERROR_NONE;
}


static socket_error_t lwipv4_socket_bind(struct socket *sock, const struct socket_addr *address, const uint16_t port)
{
    err_t err = ERR_OK;
    ip_addr_t a;
    switch (sock->family){
    case SOCKET_DGRAM:
        a.addr = socket_addr_get_ipv4_addr(address);
        err = udp_bind((struct udp_pcb *)sock->impl, &a, port);
        break;
    case SOCKET_STREAM:
    a.addr = socket_addr_get_ipv4_addr(address);
        err = tcp_bind((struct tcp_pcb *)sock->impl, &a, port);
        break;
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    return lwipv4_socket_error_remap(err);
}

static void rx_core(struct socket * s, struct pbuf *p) {

    __disable_irq();
    if (s->rxBufChain == NULL) {
        s->rxBufChain = p;
    } else {
        pbuf_cat((struct pbuf *) s->rxBufChain, p);
    }
    __enable_irq();
}

void irqUDPRecv(void * arg, struct udp_pcb * upcb,
        struct pbuf * p,
        struct ip_addr * addr,
        u16_t port)
{
    (void) upcb;
    // These parameters are extracted from the IP and UDP headers.
    (void) addr;
    (void) port;
    struct socket *s = (struct socket *) arg;
    struct socket_event e;

    rx_core(s, p);

    e.event = SOCKET_EVENT_RX_DONE;
    s->event = &e;
    ((socket_api_handler_t)(s->handler))();
    s->event = NULL;
}

err_t irqTCPRecv(void * arg, struct tcp_pcb * tpcb, struct pbuf * p, err_t err)
{
    (void) tpcb;
    struct socket_event e;
    struct socket *s = (struct socket *) arg;

    if(err != ERR_OK) {
        e.event = SOCKET_EVENT_ERROR;
        e.i.e = lwipv4_socket_error_remap(err);
        s->event = &e;
        ((socket_api_handler_t)(s->handler))();
        s->event = NULL;
        return ERR_OK;
    }
    /* Check for a disconnect */
    if (p == NULL) {
        e.event = SOCKET_EVENT_DISCONNECT;
        s->event = &e;
        ((socket_api_handler_t) (s->handler))();
        s->event = NULL;
        /* Zero the impl, since a disconnect will cause a free */
        s->impl = NULL;
        return ERR_OK;
    }

    rx_core(s, p);

    e.event = SOCKET_EVENT_RX_DONE;
    s->event = &e;
    ((socket_api_handler_t)(s->handler))();
    s->event = NULL;
    return ERR_OK;
}

static uint8_t lwipv4_socket_is_connected(const struct socket *sock) {
    switch (sock->family) {
    case SOCKET_DGRAM:
        if (((struct udp_pcb *)sock->impl)->flags & UDP_FLAGS_CONNECTED)
            return 1;
        return 0;
    case SOCKET_STREAM:
    {
        struct tcp_pcb *tpcb = (struct tcp_pcb *)sock->impl;
        return (tpcb->state == ESTABLISHED);
    }
    default:
        break;
    }
    return 0;
}
static uint8_t lwipv4_socket_is_bound(const struct socket *sock) {
    switch (sock->family) {
    case SOCKET_DGRAM:
        return (((struct udp_pcb *)sock->impl)->local_port != 0);
    case SOCKET_STREAM:
        return (((struct tcp_pcb *)sock->impl)->local_port != 0);
    default:
        break;
    }
    return 0;
}

err_t irqTCPSent(void *arg,struct tcp_pcb *tpcb, uint16_t len) {
    // Notify the application that some bytes have been received by the remote host
    (void) tpcb;
    socket_event_t e;
    struct socket * s = (struct socket *)arg;
    socket_api_handler_t handler = s->handler;
    e.event = SOCKET_EVENT_TX_DONE;
    e.sock = s;
    e.i.t.sentbytes = len;
    s->event = &e;
    handler();
    s->event = NULL;
    return SOCKET_ERROR_NONE;
}

socket_error_t lwipv4_socket_send(struct socket *socket, const void * buf, const size_t len)
{
    err_t err = ERR_VAL;
    switch(socket->family) {
    case SOCKET_DGRAM: {
        struct pbuf *pb = pbuf_alloc(PBUF_TRANSPORT,len,PBUF_RAM);
        socket_event_t e;
        socket_api_handler_t handler = socket->handler;
        err = pbuf_take(pb, buf, len);
        if (err != ERR_OK)
            break;
        err = udp_send(socket->impl, pb);
        pbuf_free(pb);
        if (err != ERR_OK)
            break;
        //Notify the application that the transfer is queued at the MAC layer
        e.event = SOCKET_EVENT_TX_DONE;
        e.sock = socket;
        e.i.t.sentbytes = len;
        socket->event = &e;
        handler();
        socket->event = NULL;
        break;
    }
    case SOCKET_STREAM:
        err = tcp_write(socket->impl,buf,len,TCP_WRITE_FLAG_COPY);
        break;
    }
    return lwipv4_socket_error_remap(err);
}
socket_error_t lwipv4_socket_send_to(struct socket *socket, const void * buf, const size_t len, const struct socket_addr *addr, const uint16_t port)
{
    ip_addr_t a;
    err_t err = ERR_VAL;
    switch(socket->family) {
    case SOCKET_DGRAM: {
        struct pbuf *pb = pbuf_alloc(PBUF_TRANSPORT,len,PBUF_RAM);
        socket_event_t e;
        socket_api_handler_t handler = socket->handler;
        err = pbuf_take(pb, buf, len);
        if (err != ERR_OK)
        	break;
        a.addr = socket_addr_get_ipv4_addr(addr);
        err = udp_sendto(socket->impl, pb, &a, port);
        pbuf_free(pb);
        if (err != ERR_OK)
        	break;
        e.event = SOCKET_EVENT_TX_DONE;
        e.sock = socket;
        e.i.t.sentbytes = len;
        socket->event = &e;
        handler();
        socket->event = NULL;
        break;
    }
    case SOCKET_STREAM:
        err = ERR_USE;
        break;
    }
    return lwipv4_socket_error_remap(err);

}

static socket_error_t recv_validate(struct socket *socket, void * buf, size_t *len) {
    if(socket == NULL || len == NULL || buf == NULL || socket->impl == NULL) {
        return SOCKET_ERROR_NULL_PTR;
    }
    if (*len == 0) {
        return SOCKET_ERROR_SIZE;
    }
    if (socket->rxBufChain == NULL) {
        return SOCKET_ERROR_WOULD_BLOCK;
    }
    return SOCKET_ERROR_NONE;
}

static socket_error_t recv_copy_free(struct socket *socket, void * buf,
        size_t *len) {
    struct pbuf *p;
    size_t copied;

    p = (struct pbuf *) socket->rxBufChain;
    if (p == NULL) {
        return SOCKET_ERROR_WOULD_BLOCK;
    }

    switch (socket->family) {
        case SOCKET_STREAM: {
            /* Copy out of the pbuf chain */
            copied = pbuf_copy_partial(p, buf, *len, 0);
            /* Set the external length to the number of bytes copied */
            *len = copied;
            while (copied) {
                if (copied < p->len) {
                    /* advance the payload pointer by the number of bytes copied */
                    p->payload = (char *)p->payload + copied;
                    /* reduce the length by the number of bytes copied */
                    p->len -= copied;
                    /* break out of the loop */
                    copied = 0;
                } else {
                    struct pbuf *q;
                    uint16_t freelen = p->tot_len;
                    q = p->next;
                    /* decrement the number of bytes copied by the length of the buffer */
                    copied -= p->len;
                    /* Free the current pbuf */
                    /* NOTE: This operation is interrupt safe, but not thread safe. */
                    if (q != NULL) {
                        pbuf_ref(q);
                    }
                    socket->rxBufChain = q;
                    pbuf_free(p);
                    /* Update the TCP window */
                    tcp_recved(socket->impl, freelen);
                    p = q;
                }
            }
            break;
        }
        case SOCKET_DGRAM: {
            struct pbuf *q;
            size_t cplen = ((*len) < (p->len) ? (*len) : (p->len));
            copied = pbuf_copy_partial(p, buf, cplen, 0);
            *len = copied;
            q = p->next;
            /* NOTE: This operation is interrupt safe, but not thread safe. */
            if (q != NULL) {
                pbuf_ref(q);
            }
            socket->rxBufChain = q;
            pbuf_free(p);
            break;
        }
        default:
            break;
    }

    return SOCKET_ERROR_NONE;
}

socket_error_t lwipv4_socket_recv(struct socket *socket, void * buf, size_t *len)
{
    socket_error_t err = recv_validate(socket, buf, len);
    if (err != SOCKET_ERROR_NONE) {
        return err;
    }
    err = recv_copy_free(socket, buf, len);
    return err;
}

/*
 * Recv should not be called from an interrupt context, so the only time interrupts
 * must be disabled is when freeing a pbuf
 */
socket_error_t lwipv4_socket_recv_from(struct socket *socket, void * buf, size_t *len, struct socket_addr *addr, uint16_t *port)
{
    socket_error_t err = recv_validate(socket, buf, len);
    struct pbuf *p;
    if (err != SOCKET_ERROR_NONE) {
        return err;
    }
    if(addr == NULL || port == NULL) {
        return SOCKET_ERROR_NULL_PTR;
    }
    socket_addr_set_any(addr);
    p = (struct pbuf *)socket->rxBufChain;

    if (lwipv4_socket_is_connected(socket)) {
        if (socket->family == SOCKET_DGRAM) {
            struct udp_pcb * upcb = (struct udp_pcb *) socket->impl;
            socket_addr_set_ipv4_addr(addr, upcb->remote_ip.addr);
            *port = upcb->remote_port;
        } else if (socket->family == SOCKET_STREAM) {
            struct tcp_pcb * tpcb = (struct tcp_pcb *) socket->impl;
            socket_addr_set_ipv4_addr(addr, tpcb->remote_ip.addr);
            *port = tpcb->remote_port;
        }
    } else if (socket->family == SOCKET_DGRAM) {
        struct udp_hdr * udphdr;
        struct ip_hdr * iphdr;
        struct ip_addr srcip;
        /* roll back the pbuf by udp_hdr to find the source port. */
        pbuf_header(p, UDP_HLEN);
        udphdr = p->payload;
        /* roll back the pbuf by ip_hdr to find the source IP */
        pbuf_header(p, IP_HLEN);
        iphdr = p->payload;
        /* put the pbuf back where it was */
        pbuf_header(p, -UDP_HLEN - IP_HLEN);

        ip_addr_copy(srcip, iphdr->src);
        socket_addr_set_ipv4_addr(addr, srcip.addr);
        *port = ntohs(udphdr->src);
    }
    err = recv_copy_free(socket, buf, len);
    return err;
}

socket_error_t lwipv4_get_local_addr(const struct socket *socket, struct socket_addr *addr)
{
    if (socket == NULL || socket->impl == NULL || addr == NULL)
    {
        return SOCKET_ERROR_NULL_PTR;
    }
    if (!lwipv4_socket_is_bound(socket)) {
        return SOCKET_ERROR_NOT_BOUND;
    }
    struct ip_pcb *pcb = socket->impl;
    socket_addr_set_ipv4_addr(addr, pcb->local_ip.addr);
    return SOCKET_ERROR_NONE;
}
socket_error_t lwipv4_get_remote_addr(const struct socket *socket, struct socket_addr *addr)
{
    if (socket == NULL || socket->impl == NULL || addr == NULL)
    {
        return SOCKET_ERROR_NULL_PTR;
    }
    if (!lwipv4_socket_is_connected(socket)) {
        return SOCKET_ERROR_NO_CONNECTION;
    }
    struct ip_pcb *pcb = socket->impl;
    socket_addr_set_ipv4_addr(addr, pcb->remote_ip.addr);
    return SOCKET_ERROR_NONE;
}
socket_error_t lwipv4_get_local_port(const struct socket *socket, uint16_t *port)
{
    if (socket == NULL || socket->impl == NULL || port == NULL)
    {
        return SOCKET_ERROR_NULL_PTR;
    }
    if (!lwipv4_socket_is_bound(socket)) {
        return SOCKET_ERROR_NOT_BOUND;
    }
    switch (socket->family) {
        case SOCKET_STREAM: {
            struct tcp_pcb *pcb = (struct tcp_pcb *) socket->impl;
            *port = pcb->local_port;
            break;
        }
        case SOCKET_DGRAM: {
            struct udp_pcb *pcb = (struct udp_pcb *) socket->impl;
            *port = pcb->local_port;
            break;
        }
        default:
        break;
    }
    return SOCKET_ERROR_NONE;
}
socket_error_t lwipv4_get_remote_port(const struct socket *socket, uint16_t *port)
{
    if (socket == NULL || socket->impl == NULL || port == NULL)
    {
        return SOCKET_ERROR_NULL_PTR;
    }
    if (!lwipv4_socket_is_connected(socket)) {
        return SOCKET_ERROR_NO_CONNECTION;
    }
    switch (socket->family) {
        case SOCKET_STREAM: {
            struct tcp_pcb *pcb = (struct tcp_pcb *) socket->impl;
            *port = pcb->remote_port;
            break;
        }
        case SOCKET_DGRAM: {
            struct udp_pcb *pcb = (struct udp_pcb *) socket->impl;
            *port = pcb->remote_port;
            break;
        }
        default:
        break;
    }
    return SOCKET_ERROR_NONE;

}
socket_error_t lwipv4_socket_reject(struct socket *socket)
{
    lwipv4_socket_abort(socket);
    return SOCKET_ERROR_NONE;
}
socket_error_t lwipv4_socket_set_option(struct socket *socket, const socket_proto_level_t level,
        const socket_option_type_t type, const void *option, const size_t optionSize)
{
    (void) socket;
    (void) level;
    (void) type;
    (void) option;
    (void) optionSize;
    return SOCKET_ERROR_UNIMPLEMENTED;
}
socket_error_t lwipv4_socket_get_option(struct socket *socket, const socket_proto_level_t level,
        const socket_option_type_t type, void *option, const size_t optionSize)
{
    (void) socket;
    (void) level;
    (void) type;
    (void) option;
    (void) optionSize;
    return SOCKET_ERROR_UNIMPLEMENTED;
}

const struct socket_api lwipv4_socket_api = {
    .stack = SOCKET_STACK_LWIP_IPV4,
    .version = SOCKET_ABSTRACTION_LAYER_VERSION,
    .init = init,
    .create = lwipv4_socket_create,
    .destroy = lwipv4_socket_destroy,
    .close = lwipv4_socket_close,
    .periodic_task = lwipv4_socket_periodic_task,
    .periodic_interval = lwipv4_socket_periodic_interval,
    .resolve = lwipv4_socket_resolve,
    .connect = lwipv4_socket_connect,
    .str2addr = str2addr,
    .bind = lwipv4_socket_bind,
    .start_listen = start_listen,
    .stop_listen = stop_listen,
    .accept = lwipv4_socket_accept,
    .reject = lwipv4_socket_reject,
    .send = lwipv4_socket_send,
    .send_to = lwipv4_socket_send_to,
    .recv = lwipv4_socket_recv,
    .recv_from = lwipv4_socket_recv_from,
    .set_option = lwipv4_socket_set_option,
    .get_option = lwipv4_socket_get_option,
    .is_connected = lwipv4_socket_is_connected,
    .is_bound = lwipv4_socket_is_bound,
    .get_local_addr = lwipv4_get_local_addr,
    .get_remote_addr = lwipv4_get_remote_addr,
    .get_local_port = lwipv4_get_local_port,
    .get_remote_port = lwipv4_get_remote_port,
};
