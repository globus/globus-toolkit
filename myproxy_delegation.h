/*
 * myproxy_delegation.h
 *
 * functions for get-delegation - delegation from Myproxy server to the client
 */
#ifndef __MYPROXY_DELEGATION_H
#define __MYPROXY_DELEGATION_H

#include "myproxy.h"

int myproxy_get_delegation(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request,
    char                   *certfile, /* for backward compatibility.
					 use client_request->authzcreds
					 instead. */
    myproxy_response_t     *server_response,
    char                   *outputfile,
    int                     use_empty_passwd,
    int                     read_passwd_from_stdin,
    int                     dn_as_username,
    char                   *outfile);

int myproxy_set_delegation_defaults(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request);

#endif
