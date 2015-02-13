/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright 2015 ARM Holdings PLC
 */

#include <stddef.h>
#include <stdint.h>

#include "socket_api.h"
#include "socket_buffer.h"

// TODO: Remove when yotta supports init
#include "lwipv4_init.h"

#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/tcp_impl.h"
#include "lwip/timers.h"
#include "lwip/dns.h"
#include "lwip/ip_addr.h"



uint32_t TCPSockets = 0;

const struct socket_api lwipv4_socket_api;
static uint8_t lwipv4_socket_tx_is_busy(const struct socket *sock);
static uint8_t lwipv4_socket_rx_is_busy(const struct socket *sock);

socket_error_t lwipv4_socket_init() {
    return socket_register_stack(&lwipv4_socket_api);
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
    case ERR_USE:
    case ERR_ISCONN:
    case ERR_ABRT:
    case ERR_RST:
    case ERR_CLSD:
    case ERR_CONN:
    case ERR_ARG:
    case ERR_IF:
    break;
    }
    return err;
}

static socket_error_t init()
{
    return SOCKET_ERROR_NONE;
}
static socket_error_t start_listen(struct socket *socket, const struct socket_addr *address, const uint16_t port, socket_api_handler_t const handler)
{
    (void)socket;
    (void)address;
    (void)port;
    (void)handler;
    return SOCKET_ERROR_UNKNOWN;
}
static socket_error_t stop_listen(struct socket *socket)
{
    (void)socket;
    return SOCKET_ERROR_UNKNOWN;
}

//static uint8_t family_remap(socket_proto_family_t family) {
//    uint8_t lwip_family = 0;
//    switch (family) {
//    case SOCKET_DGRAM:
//        lwip_family = SOCK_DGRAM;
//        break;
//    case SOCKET_STREAM:
//        lwip_family = SOCK_STREAM;
//        break;
//    case SOCKET_RAW:
//        lwip_family = SOCK_RAW;
//        break;
//    }
//    return lwip_family;
//}


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
      e.i.d.sock = sock;
      e.i.d.addr.type = SOCKET_STACK_LWIP_IPV4;
      e.i.d.addr.impl = addr;
      e.i.d.domain = name;
  }
  sock->event = &e;
  handler();
}

static socket_error_t lwipv4_socket_resolve(struct socket *sock, const char *address)
{
    struct ip_addr ia;
    // attempt to resolve with DNS or convert to ip addr
    err_t err = dns_gethostbyname(address, &ia, dnscb, sock);
    if (err == ERR_OK) {
        dnscb(address, &ia, sock);
    }
    return lwipv4_socket_error_remap(err);
}

static socket_error_t lwipv4_socket_create(struct socket *sock, socket_proto_family_t family, socket_api_handler_t handler)
{
    if (sock == NULL)
        return SOCKET_ERROR_NULL_PTR;
    switch (family) {
    case SOCKET_DGRAM:
    {
        struct udp_pcb *udp = udp_new();
        if (udp == NULL)
            return SOCKET_ERROR_BAD_ALLOC;
        sock->stack = SOCKET_STACK_LWIP_IPV4;
        sock->impl = (void *)udp;
        break;
    }
    case SOCKET_STREAM:
    {
      struct tcp_pcb *tcp = tcp_new();
      tcp = tcp_new();
      if (tcp == NULL)
        return SOCKET_ERROR_BAD_ALLOC;
      sock->stack = SOCKET_STACK_LWIP_IPV4;
      sock->impl = (void *)tcp;
      break;
    }
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    sock->family = family;
    sock->handler = (void*)handler;
    sock->status = SOCKET_STATUS_IDLE;
    return SOCKET_ERROR_NONE;
}

static socket_error_t lwipv4_socket_close(struct socket *sock)
{
    err_t err = ERR_OK;
    if (sock == NULL)
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
    if (sock == NULL)
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
    lwipv4_socket_abort(sock);
    return SOCKET_ERROR_NONE;
}

static err_t onConnect(void * arg, struct tcp_pcb * tpcb, err_t err)
{
    struct socket *sock = (struct socket *) arg;
    socket_api_handler_t handler = (socket_api_handler_t) sock->handler;
    socket_event_t e;
    (void) tpcb;
    if (err != ERR_OK)
    {
        e.event = SOCKET_EVENT_ERROR;
        e.i.e = lwipv4_socket_error_remap(err);
    }
    else
    {
        e.event = SOCKET_EVENT_CONNECT;
        sock->status |= SOCKET_STATUS_CONNECTED;
    }
    sock->event = &e;
    handler();
    return ERR_OK;
}

static socket_error_t lwipv4_socket_connect(struct socket *sock, const struct socket_addr *address, const uint16_t port)
{
    err_t err = ERR_OK;
    switch (sock->family){
    case SOCKET_DGRAM:
        err = udp_connect((struct udp_pcb *)sock->impl, address->impl, port);
        break;
    case SOCKET_STREAM:
        tcp_arg((struct tcp_pcb *)sock->impl, (void*) sock);
        err = tcp_connect((struct tcp_pcb *)sock->impl, address->impl, port, onConnect);
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
    case SOCKET_STACK_LWIP_IPV4:
        if (ipaddr_aton(addr, address->impl) == -1) {
            err = SOCKET_ERROR_BAD_ADDRESS;
            address->type = SOCKET_STACK_UNINIT;
        }
        address->type = sock->stack;
        break;
    default:
        break;
    }
    return err;
}

static socket_error_t lwipv4_socket_bind(struct socket *sock, const struct socket_addr *address, const uint16_t port)
{
    err_t err = ERR_OK;
    switch (sock->family){
    case SOCKET_DGRAM:
        err = udp_bind((struct udp_pcb *)sock->impl, address->impl, port);
        break;
    case SOCKET_STREAM:
        err = tcp_bind((struct tcp_pcb *)sock->impl, address->impl, port);
        break;
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    return lwipv4_socket_error_remap(err);
}

static err_t tcp_sent_callback(void * arg, struct tcp_pcb *pcb, uint16_t len)
{
  struct socket *sock = (struct socket *)arg;
  socket_api_handler_t handler = (socket_api_handler_t) sock->handler;
  (void) pcb;
  socket_event_t e;
  e.event = SOCKET_EVENT_TX_DONE;
  e.i.t.sentbytes = len;
  e.i.t.sock = sock;
  sock->event = &e; // TODO: (CThunk upgrade/Alpha2)
  handler();
  return ERR_OK;
}

// static err_t tcp_send_completion(void * arg, struct socket *sock, err_t err) {
//     (void) sock;
//   // if(err == ERR_OK) {
//   //   sock->status = (socket_status_t)(SOCKET_STATUS_TX_BUSY|(int)sock->status);
//   //   // Note: it looks like lwip sends do not require the buffer to persist.
//   //   socket_api_handler handler = (socket_api_handler)sock->handler;
//   //   socket_event_t e;
//   //   e.event = SOCKET_EVENT_TX_DONE;
//   //   e.i.t.free_buf = autofree;
//   //   e.i.t.buf = buf;
//   //   e.i.t.sock = sock;
//   //   sock->event = &e; // TODO: (CThunk upgrade/Alpha2)
//   //   handler();
//   //   if (e.i.t.free_buf) {
//   //     socket_buf_try_free(buf);
//   //   }
//   // }
//   return lwipv4_socket_error_remap(err);
// }

static socket_error_t lwipv4_socket_start_send(struct socket *sock, struct socket_buffer *buf, void *arg)
{
    // flags:
    //    buffer type: (void* vs pbuf)
    //    more (Don't care, except for streams)
    //    copy: specifies a transient buffer that needs to be copied into the stack

    err_t err = ERR_OK;
    switch (sock->family) {
    case SOCKET_DGRAM:
        // Check if *buf is a pbuf
        if (buf->type != SOCKET_BUFFER_LWIP_PBUF) {
            return SOCKET_ERROR_BAD_BUFFER;
        }
        err = udp_send((struct udp_pcb *)sock->impl, (struct pbuf *)buf->impl);
        break;
    case SOCKET_STREAM: {
        struct tcp_pcb * pcb = (struct tcp_pcb *)sock->impl;
        uint16_t available;
        void * dptr;
        size_t dsize;
        size_t dpos;
        // TODO: add support for pbufs
        if (buf->type != SOCKET_BUFFER_RAW) {
            return SOCKET_ERROR_BAD_BUFFER;
        }
        dptr  = ((struct socket_rawbuf *)(buf->impl))->buf;
        dsize = ((struct socket_rawbuf *)(buf->impl))->size;
        dpos  = ((struct socket_rawbuf *)(buf->impl))->pos;

        dptr = (void*)((uintptr_t)dptr + dpos);
        dsize -= dpos;

        tcp_sent(pcb, tcp_sent_callback); // specify callback
        available = tcp_sndbuf(pcb); //determine available size
        if (available < dsize) {
            return SOCKET_ERROR_SIZE;
        }
        err = tcp_write(pcb, dptr, dsize, buf->flags); //send data
        break;
    }
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    if(err == ERR_OK) {
        sock->status = (socket_status_t)(SOCKET_STATUS_TX_BUSY|(int)sock->status);
        // Note: it looks like lwip sends do not require the buffer to persist.
        socket_api_handler_t handler = (socket_api_handler_t)sock->handler;
        socket_event_t e;
        e.event = SOCKET_EVENT_TX_DONE;
        e.i.t.context = arg;
        e.i.t.free_buf = 1;
        e.i.t.buf = buf;
        e.i.t.sock = sock;
        sock->event = &e; // TODO: (CThunk upgrade/Alpha2)
        handler();
        if (e.i.t.free_buf) {
            sock->api->buf_api.try_free(buf);
        }
    }
    return lwipv4_socket_error_remap(err);
    return SOCKET_ERROR_NONE;
}

static void recv_free(void *arg, struct udp_pcb *pcb, struct pbuf *p,
        ip_addr_t *addr, u16_t port)
{
    (void) pcb;
    struct socket *s = (struct socket *)arg;
    socket_api_handler_t handler = (socket_api_handler_t)s->handler;
    socket_event_t e;
    e.event = SOCKET_EVENT_RX_DONE;
    e.i.r.buf.impl = (void *)p;
    e.i.r.buf.type = SOCKET_BUFFER_LWIP_PBUF;
    e.i.r.buf.api = &lwipv4_socket_api.buf_api;
    e.i.r.buf.flags = 0;
    e.i.r.sock = s;
    e.i.r.port = port;
    e.i.r.src.type = SOCKET_STACK_LWIP_IPV4;
    e.i.r.src.impl = addr;
    // Assume that the library will free the buffer unless the client
    // overrides the free.
    e.i.r.free_buf = 1;

    // Make sure the busy flag is cleared in case the client wants to start another receive
    s->status = (socket_status_t)((int)s->status & ~SOCKET_STATUS_RX_BUSY);

    s->event = &e; // TODO: (CThunk upgrade/Alpha3)
    handler();


    if(e.i.r.free_buf) {
        s->api->buf_api.free(&e.i.r.buf);
    }
}

static err_t tcp_recv_free(void * arg, struct tcp_pcb * tpcb,
               struct pbuf * p, err_t err) {
    (void) err;
    struct socket *s = (struct socket *)arg;
    socket_api_handler_t handler = (socket_api_handler_t)s->handler;
    socket_event_t e;
    e.event = SOCKET_EVENT_RX_DONE;
    e.i.r.buf.impl = (void *)p;
    e.i.r.buf.type = SOCKET_BUFFER_LWIP_PBUF;
    e.i.r.buf.api = &lwipv4_socket_api.buf_api;
    e.i.r.buf.flags = 0;
    e.i.r.sock = s;
    // Assume that the library will free the buffer unless the client
    // overrides the free.
    e.i.r.free_buf = 1;

    // Make sure the busy flag is cleared in case the client wants to start another receive
    s->status = (socket_status_t)((int)s->status & ~SOCKET_STATUS_RX_BUSY);

    s->event = &e; // TODO: (CThunk upgrade/Alpha3)
    handler();

    tcp_recved(tpcb, s->api->buf_api.get_size(&e.i.r.buf));
    if(e.i.r.free_buf) {
        s->api->buf_api.free(&e.i.r.buf);
    }
    return ERR_OK; //TODO: can this be improved?
}

static socket_error_t lwipv4_socket_start_recv(struct socket *sock) {
    err_t err = ERR_OK;

    if (lwipv4_socket_rx_is_busy(sock)) return SOCKET_ERROR_BUSY;
    switch (sock->family) {
    case SOCKET_DGRAM:
        sock->status = (socket_status_t)((int)sock->status | SOCKET_STATUS_RX_BUSY);
        udp_recv((struct udp_pcb *)sock->impl, recv_free, (void *)sock);
        break;
    case SOCKET_STREAM:
        sock->status = (socket_status_t)((int)sock->status | SOCKET_STATUS_RX_BUSY);
        tcp_recv((struct tcp_pcb *)sock->impl, tcp_recv_free);
        break;
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    if(err == ERR_OK)
        sock->status = (socket_status_t)((int)sock->status | SOCKET_STATUS_RX_BUSY);
    return lwipv4_socket_error_remap(err);

}

static uint8_t lwipv4_socket_is_connected(const struct socket *sock) {
    switch (sock->family) {
    case SOCKET_DGRAM:
        if (((struct udp_pcb *)sock->impl)->flags & UDP_FLAGS_CONNECTED)
            return 1;
        return 0;
    case SOCKET_STREAM:
        return !! (sock->status & SOCKET_STATUS_CONNECTED);
    default:
        break;
    }
    return 0;
}
static uint8_t lwipv4_socket_is_bound(const struct socket *sock) {
    switch (sock->family) {
    case SOCKET_DGRAM:
        if (((struct udp_pcb *)sock->impl)->local_port != 0)
            return 1;
        return 0;
    case SOCKET_STREAM:
        //TODO: TCP is bound
    default:
        break;
    }
    return 0;
}

static uint8_t lwipv4_socket_tx_is_busy(const struct socket *sock) {
    return !!(sock->status & SOCKET_STATUS_TX_BUSY);
}
static uint8_t lwipv4_socket_rx_is_busy(const struct socket *sock) {
    return !!(sock->status & SOCKET_STATUS_RX_BUSY);
}
#include "lwip_socket_buffer.h"

const struct socket_api lwipv4_socket_api = {
    .stack = SOCKET_STACK_LWIP_IPV4,
    .init = init,
    .buf_api = {
        //.stack_to_buf = ,
        .get_ptr = lwip_buf_get_ptr,
        .get_size = lwip_buf_get_size,
        .alloc = lwip_buf_alloc,
        .try_free = lwip_buf_try_free,
        .free = lwip_buf_free,
        .u2b = lwip_copy_from_user,
        .b2u = lwip_copy_to_user,
    },
    .create = lwipv4_socket_create,
    .destroy = lwipv4_socket_destroy,
    .close = lwipv4_socket_close,
    .abort = lwipv4_socket_abort,
    .periodic_task = lwipv4_socket_periodic_task,
    .periodic_interval = lwipv4_socket_periodic_interval,
    .resolve = lwipv4_socket_resolve,
    .connect = lwipv4_socket_connect,
    .str2addr = str2addr,
    .bind = lwipv4_socket_bind,
    .start_listen = start_listen,
    .stop_listen = stop_listen,
    .start_send = lwipv4_socket_start_send,
    .start_recv = lwipv4_socket_start_recv,
    .is_connected = lwipv4_socket_is_connected,
    .is_bound = lwipv4_socket_is_bound,
    .tx_busy = lwipv4_socket_tx_is_busy,
    .rx_busy = lwipv4_socket_rx_is_busy,
    .pbuf_type = SOCKET_BUFFER_LWIP_PBUF,
};
