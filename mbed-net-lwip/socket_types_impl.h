/*
 * socket_types_impl.h
 *
 *  Created on: 28 Nov 2014
 *      Author: bremor01
 */

#ifndef LIBRARIES_NET_LWIP_SOCKET_SOCKET_TYPES_IMPL_H_
#define LIBRARIES_NET_LWIP_SOCKET_SOCKET_TYPES_IMPL_H_

#include "socket_types.h"
#include "lwip/err.h"
socket_error_t socket_error_remap(err_t lwip_err);



#endif /* LIBRARIES_NET_LWIP_SOCKET_SOCKET_TYPES_IMPL_H_ */
