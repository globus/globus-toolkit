/*
 * myproxy-auth.h
 *
 * Interface for doing GSI authentication with myproxy.
 *
 * Use the gss_assist interface.
 */

#ifndef __MYPROXY_AUTH_H
#define __MYPROXY_AUTH_H

#include <gssapi.h>

#include "myproxy-gss-context.h"

/*
 * MYPROXY_AUTH_accept()
 *
 * Routine that the server calls to authenticate a new client.
 * context should have been allocated with MYPROXY_GSS_CONTEXT_new()
 * and had a valid socket assigned to it with MYPROXY_GSS_CONTEXT_set_socket()
 *
 * Returns 0 on success, -1 on error.
 */
int MYPROXY_AUTH_accept(MYPROXY_GSS_CONTEXT *context);

/*
 * MYPROXY_AUTH_init()
 *
 * Routine that the client calls to authenticate to the server.
 * context should have been allocated with MYPROXY_GSS_CONTEXT_new()
 * and had a valid socket assigned to it with MYPROXY_GSS_CONTEXT_set_socket()
 *
 * Returns 0 on success, -1 on error.
 */
int MYPROXY_AUTH_init(MYPROXY_GSS_CONTEXT *context)

#endif /* !__MYPROXY_AUTH_H */
