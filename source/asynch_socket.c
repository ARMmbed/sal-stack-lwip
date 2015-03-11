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
static void irqUDPRecv(void * arg, struct udp_pcb * upcb,
        struct pbuf * p,
        struct ip_addr * addr,
        u16_t port);
static err_t irqTCPRecv(void * arg, struct tcp_pcb * tpcb,
        struct pbuf * p, err_t err);

struct pbuf_wrapper {
	struct pbuf_wrapper *next;
	struct pbuf *p;
	struct ip_addr *addr;
	size_t offset;
	uint16_t port;
};

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

//static err_t irqAccept (void * arg, struct tcp_pcb * newpcb, err_t err)
//{
//	struct socket * s = (struct socket *)arg;
//    socket_event_t e;
//    if (err != ERR_OK) {
//        e.event = SOCKET_EVENT_ERROR;
//        e.i.e = lwipv4_socket_error_remap(err);
//        err = ERR_OK;
//        s->event = &e;
//        handler(&e);
//        s->event = NULL;
//    } else {
//        handler_t handler = s->handler;
//        e.event = SOCKET_EVENT_ACCEPT;
//        e.i.a.sock = s;
//        e.i.a.newimpl = newpcb;
//        e.i.a.reject = 0;
//        s->event = &e;
//        handler(&e);
//        s->event = NULL;
//        if (e.i.a.reject) {
//            err = ERR_ABRT;
//            tcp_abort(newpcb);
//        }
//    }
//    return err;
//}
//static err_t irqAcceptNull (void * arg, struct tcp_pcb * newpcb, err_t err)
//{
//    (void) arg;
//    (void) err;
//    tcp_abort(newpcb);
//    return ERR_ABRT;
//}
//static socket_error_t start_listen(struct socket *socket)
//{
//    struct tcp_pcb * pcb = socket->impl;
//    if (pcb->state != LISTEN) {
//        socket->impl = tcp_listen(socket->impl);
//        if (socket->impl == NULL) {
//            return SOCKET_ERROR_BAD_ALLOC;
//        }
//    }
//    tcp_arg(socket->impl, socket);
//    tcp_accept(socket->impl, irqAccept);
//    return SOCKET_ERROR_NONE;
//}
//static socket_error_t stop_listen(struct socket *socket)
//{
//    tcp_accept(socket->impl, irqAcceptNull);
//    return SOCKET_ERROR_UNKNOWN;
//}

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
      ipv4_addr_cpy(e.i.d.addr.storage, addr);
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
    if (err == SOCKET_ERROR_BUSY)
    	err = SOCKET_ERROR_NONE;
    return lwipv4_socket_error_remap(err);
}
static void tcp_error_handler(void *arg, err_t err)
{
    struct socket *sock = (struct socket *) arg;
    struct socket_event e;
    socket_api_handler_t h = sock->handler;
    e.event = SOCKET_EVENT_ERROR;
    e.i.e = lwipv4_socket_error_remap(err);
    sock->event = &e; // TODO: (CThunk upgrade/Alpha3)
    h();
    sock->event = NULL;
}
static socket_error_t lwipv4_socket_create(struct socket *sock, const socket_address_family_t af, const socket_proto_family_t pf, socket_api_handler_t const handler)
{
	(void)af;
    if (sock == NULL)
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
      tcp = tcp_new();
      if (tcp == NULL)
        return SOCKET_ERROR_BAD_ALLOC;
      tcp_arg((struct tcp_pcb *)sock->impl, (void*) sock);
      sock->stack = SOCKET_STACK_LWIP_IPV4;
      sock->impl = (void *)tcp;
      tcp_err(tcp, tcp_error_handler);
      tcp_recv((struct tcp_pcb *)sock->impl, irqTCPRecv);
      break;
    }
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    sock->family = pf;
    sock->handler = (void*)handler;
    sock->status = SOCKET_STATUS_IDLE;
    sock->rxBufChain = NULL;
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
	struct pbuf_wrapper * pw;
	if (sock == NULL) {
		return SOCKET_ERROR_NULL_PTR;
	}
	pw = (struct pbuf_wrapper *) sock->rxBufChain;
	while (pw != NULL) {
		struct pbuf_wrapper * next_pw = pw->next;
		pbuf_free(pw->p);
		free(pw);
		pw = next_pw;
	}

    lwipv4_socket_abort(sock);
    return SOCKET_ERROR_NONE;
}

static err_t irqConnect(void * arg, struct tcp_pcb * tpcb, err_t err)
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
    sock->event = NULL;
    return ERR_OK;
}

static socket_error_t lwipv4_socket_connect(struct socket *sock, const struct socket_addr *address, const uint16_t port)
{
    err_t err = ERR_OK;
    switch (sock->family){
    case SOCKET_DGRAM:
        err = udp_connect((struct udp_pcb *)sock->impl, (void*)address->storage, port);
        break;
    case SOCKET_STREAM:
        err = tcp_connect((struct tcp_pcb *)sock->impl, (void*)address->storage, port, irqConnect);
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
        if (ipaddr_aton(addr, (void*)address->storage) == -1) {
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
        err = udp_bind((struct udp_pcb *)sock->impl, (void *)address->storage, port);
        break;
    case SOCKET_STREAM:
        err = tcp_bind((struct tcp_pcb *)sock->impl, (void *)address->storage, port);
        break;
    default:
        return SOCKET_ERROR_BAD_FAMILY;
    }
    if (err == ERR_OK) {
        sock->status |= SOCKET_STATUS_BOUND;
    }
    return lwipv4_socket_error_remap(err);
}

void irqUDPRecv(void * arg, struct udp_pcb * upcb,
        struct pbuf * p,
        struct ip_addr * addr,
        u16_t port)
{
	(void) upcb;
	struct socket *s = (struct socket *) arg;
	struct pbuf_wrapper *w;
	struct pbuf_wrapper *new_wrap = NULL;
	struct socket_event e;

	__disable_irq();
	new_wrap = malloc(sizeof(struct pbuf_wrapper));
	if (new_wrap == NULL) {
		e.event = SOCKET_EVENT_ERROR;
		e.i.e = SOCKET_ERROR_BAD_ALLOC;
		s->event = &e;
		((socket_api_handler_t)(s->handler))();
		s->event = NULL;
		return;
	}
	new_wrap->next = NULL;
	new_wrap->addr = addr;
	new_wrap->port = port;
	new_wrap->p = p;
	new_wrap->offset = 0;

	if (s->rxBufChain == NULL) {
		s->rxBufChain = new_wrap;
	} else {
		w = (struct pbuf_wrapper *)s->rxBufChain;
		while (w->next != NULL) {
			w = w->next;
		}
		w->next = new_wrap;
	}

	e.event = SOCKET_EVENT_RX_DONE;
	s->event = &e;
	((socket_api_handler_t)(s->handler))();
	s->event = NULL;
	__enable_irq();
}

err_t irqTCPRecv(void * arg, struct tcp_pcb * tpcb,
        struct pbuf * p, err_t err) {
	(void) tpcb;
	struct socket *s = (struct socket *) arg;
	struct pbuf_wrapper *w = (struct pbuf_wrapper *)s->rxBufChain;
	struct pbuf_wrapper *new_wrap = NULL;
	struct socket_event e;

	if(err != ERR_OK) {
		e.event = SOCKET_EVENT_ERROR;
		e.i.e = lwipv4_socket_error_remap(err);
		s->event = &e;
		((socket_api_handler_t)(s->handler))();
		s->event = NULL;
		return ERR_OK;
	}

	while (w->next != NULL) {
		w = w->next;
	}
	new_wrap = malloc(sizeof(struct pbuf_wrapper));
	if (new_wrap == NULL) {
		e.event = SOCKET_EVENT_ERROR;
		e.i.e = SOCKET_ERROR_BAD_ALLOC;
		s->event = &e;
		((socket_api_handler_t)(s->handler))();
		s->event = NULL;
		return ERR_OK;
	}
	w->next = new_wrap;
	w = w->next;
	w->p = p;
	w->offset = 0;
	w->next = NULL;

	e.event = SOCKET_EVENT_RX_DONE;
	s->event = &e;
	((socket_api_handler_t)(s->handler))();
	s->event = NULL;
	return ERR_OK;
}

//static socket_error_t lwipv4_socket_start_recv(struct socket *sock) {
//    err_t err = ERR_OK;
//
//    if (lwipv4_socket_rx_is_busy(sock)) return SOCKET_ERROR_BUSY;
//    switch (sock->family) {
//    case SOCKET_DGRAM:
//        sock->status = (socket_status_t)((int)sock->status | SOCKET_STATUS_RX_BUSY);
//        udp_recv((struct udp_pcb *)sock->impl, recv_free, (void *)sock);
//        break;
//    case SOCKET_STREAM:
//        sock->status = (socket_status_t)((int)sock->status | SOCKET_STATUS_RX_BUSY);
//        tcp_recv((struct tcp_pcb *)sock->impl, tcp_recv_free);
//        break;
//    default:
//        return SOCKET_ERROR_BAD_FAMILY;
//    }
//    if(err == ERR_OK)
//        sock->status = (socket_status_t)((int)sock->status | SOCKET_STATUS_RX_BUSY);
//    return lwipv4_socket_error_remap(err);
//
//}

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

socket_error_t lwipv4_socket_send(struct socket *socket, const void * buf, const size_t len)
{
	err_t err = ERR_VAL;
	switch(socket->family) {
    case SOCKET_DGRAM: {
    	struct pbuf *pb = pbuf_alloc(PBUF_TRANSPORT,len,PBUF_RAM);
    	err = pbuf_take(pb, buf, len);
    	if (err != ERR_OK) break;
    	err = udp_send(socket->impl, pb);
    	pbuf_free(pb);
    	break;
    }
    case SOCKET_STREAM:
    	break;
	}
	return lwipv4_socket_error_remap(err);
}
socket_error_t lwipv4_socket_send_to(struct socket *socket, const void * buf, const size_t len, const struct socket_addr *addr, const uint16_t port)
{
	err_t err = ERR_VAL;
	switch(socket->family) {
    case SOCKET_DGRAM: {
    	struct pbuf *pb = pbuf_alloc(PBUF_TRANSPORT,len,PBUF_RAM);
    	err = pbuf_take(pb, buf, len);
    	if (err != ERR_OK) break;
    	err = udp_sendto(socket->impl, pb, (void *)addr->storage, port);
    	pbuf_free(pb);
    	break;
    }
    case SOCKET_STREAM:
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
	struct pbuf_wrapper * pw = (struct pbuf_wrapper *) socket->rxBufChain;
	size_t copied;
	size_t cplen = ((*len) < (pw->p->len) ? (*len) : (pw->p->len));

	copied = pbuf_copy_partial(pw->p, buf, cplen, 0);
	if (!copied) {
		return SOCKET_ERROR_SIZE;
	}
	*len = copied;
	if (socket->family ==  SOCKET_STREAM ) {
		tcp_recved(socket->impl, copied);
	}

	//TODO: free up to n bytes

	if(copied + pw->offset >= pw->p->len) {
		socket->rxBufChain = pw->next;
		pbuf_free(pw->p);
		free(pw);
	} else {
		pw->offset += copied;
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

socket_error_t lwipv4_socket_recv_from(struct socket *socket, void * buf, size_t *len, struct socket_addr *addr, uint16_t *port)
{
	socket_error_t err = recv_validate(socket, buf, len);
	ip_addr_t * ia;
	if (err != SOCKET_ERROR_NONE) {
		return err;
	}
	if(addr == NULL || port == NULL) {
		return SOCKET_ERROR_NULL_PTR;
	}
	ia = (ip_addr_t *)addr->storage;
	addr->type = SOCKET_STACK_UNINIT;

	if (lwipv4_socket_is_connected(socket)) {
		if (socket->family == SOCKET_DGRAM) {
			struct udp_pcb * upcb = (struct udp_pcb *) socket->impl;
			*ia = upcb->remote_ip;
			*port = upcb->remote_port;
			addr->type = SOCKET_STACK_LWIP_IPV4;
	    } else if (socket->family == SOCKET_STREAM) {
			struct tcp_pcb * tpcb = (struct tcp_pcb *) socket->impl;
			*ia = tpcb->remote_ip;
			*port = tpcb->remote_port;
			addr->type = SOCKET_STACK_LWIP_IPV4;
	    }
	} else if (socket->family == SOCKET_DGRAM) {
		struct pbuf_wrapper * pw = (struct pbuf_wrapper *)socket->rxBufChain;
		*ia = *pw->addr;
		*port = pw->port;
	}
	err = recv_copy_free(socket, buf, len);
	return err;
}





const struct socket_api lwipv4_socket_api = {
    .stack = SOCKET_STACK_LWIP_IPV4,
    .init = init,
//    .buf_api = {
//        //.stack_to_buf = ,
//        .get_ptr = lwip_buf_get_ptr,
//        .get_size = lwip_buf_get_size,
//        .alloc = lwip_buf_alloc,
//        .try_free = lwip_buf_try_free,
//        .free = lwip_buf_free,
//        .u2b = lwip_copy_from_user,
//        .b2u = lwip_copy_to_user,
//    },
    .create = lwipv4_socket_create,
    .destroy = lwipv4_socket_destroy,
    .close = lwipv4_socket_close,
//    .abort = lwipv4_socket_abort,
    .periodic_task = lwipv4_socket_periodic_task,
    .periodic_interval = lwipv4_socket_periodic_interval,
    .resolve = lwipv4_socket_resolve,
    .connect = lwipv4_socket_connect,
    .str2addr = str2addr,
    .bind = lwipv4_socket_bind,
//    .start_listen = start_listen,
//    .stop_listen = stop_listen,
//    .start_send = lwipv4_socket_start_send,
//    .start_recv = lwipv4_socket_start_recv,
    .send = lwipv4_socket_send,
    .send_to = lwipv4_socket_send_to,
    .recv = lwipv4_socket_recv,
    .recv_from = lwipv4_socket_recv_from,
    .is_connected = lwipv4_socket_is_connected,
    .is_bound = lwipv4_socket_is_bound,
    .tx_busy = lwipv4_socket_tx_is_busy,
    .rx_busy = lwipv4_socket_rx_is_busy,
    .pbuf_type = SOCKET_BUFFER_LWIP_PBUF,
};