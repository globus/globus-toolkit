/*
 * myproxy_sasl_client.h
 *
 * Internal MyProxy SASL client interface.
 *
 */
#ifndef __MYPROXY_SASL_CLIENT_H
#define __MYPROXY_SASL_CLIENT_H

#if defined(HAVE_LIBSASL2)

int
auth_sasl_negotiate_client(myproxy_socket_attrs_t *attrs,
			   myproxy_request_t *client_request);

#endif

#endif
