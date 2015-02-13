/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright 2015 ARM Holdings PLC
 */
#ifndef MBED_LWIP_SOCKET_BUFFER_H_
#define MBED_LWIP_SOCKET_BUFFER_H_
#include "socket_types.h"
void * lwip_buf_get_ptr(const struct socket_buffer *b);
size_t lwip_buf_get_size(const struct socket_buffer *b);
void lwip_buf_alloc(const size_t len, const socket_alloc_pool_t p, struct socket_buffer *b);
socket_error_t lwip_buf_try_free(struct socket_buffer *b);
void lwip_buf_free(struct socket_buffer *b);
socket_error_t lwip_copy_from_user(struct socket_buffer *b, const void *u, const size_t len);
uint16_t lwip_copy_to_user(void *u, const struct socket_buffer *b, const size_t len);

#endif // MBED_LWIP_SOCKET_BUFFER_H_
