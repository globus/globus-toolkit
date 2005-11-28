/*
 * myproxy_sasl_server.h
 *
 * Internal MyProxy SASL server interface.
 *
 */
#ifndef __MYPROXY_SASL_SERVER_H
#define __MYPROXY_SASL_SERVER_H

#if defined(HAVE_LIBSASL2)

int
auth_sasl_negotiate_server(myproxy_socket_attrs_t *attrs,
			   myproxy_request_t *client_request);

extern int myproxy_sasl_authenticated; /* set to 1 after success */

#endif

#endif
