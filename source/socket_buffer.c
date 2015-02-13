
#include "lwip/pbuf.h"
#include "socket_types_impl.h"

#include "socket_buffer.h"
#include "lwip_socket_buffer.h"


static inline pbuf_type lwip_socket_pool_remap(socket_alloc_pool_t p)
{
    pbuf_type lp = PBUF_POOL;
    switch (p) {
    case SOCKET_ALLOC_HEAP:
        lp = PBUF_RAM;
        break;
    case SOCKET_ALLOC_POOL_BEST:
        lp = PBUF_POOL;
        break;
    }
    return lp;
}

void * lwip_buf_get_ptr(const struct socket_buffer *b)
{
    return ((struct pbuf *)b->impl)->payload;
}
size_t lwip_buf_get_size(const struct socket_buffer *b)
{
    return ((struct pbuf *)b->impl)->len;
}
void lwip_buf_alloc(const size_t len, const socket_alloc_pool_t p, struct socket_buffer *b)
{
    void *pb = (void *) pbuf_alloc(PBUF_TRANSPORT, len, lwip_socket_pool_remap(p));
    b->impl = pb;
}
socket_error_t lwip_buf_try_free(struct socket_buffer *b)
{
    if (b == NULL)
        return SOCKET_ERROR_NULL_PTR;
    if (((struct pbuf *)b->impl)->ref > 1) {
        return SOCKET_ERROR_BUSY;
    }
    lwip_buf_free(b);
    return SOCKET_ERROR_NULL_PTR;
}

void lwip_buf_free(struct socket_buffer *b)
{
    pbuf_free((b->impl));
}
socket_error_t lwip_copy_from_user(struct socket_buffer *b, const void *u, const size_t len)
{
    err_t err = pbuf_take((b->impl), u, len);
    return lwipv4_socket_error_remap(err);
}
uint16_t lwip_copy_to_user(void *u, const struct socket_buffer *b, const size_t len)
{
    uint16_t rc = pbuf_copy_partial((b->impl), u, len, 0);
    return rc;
}
