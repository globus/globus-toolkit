#ifndef __MYPROXY_AUTHORIZATION_H
#define __MYPROXY_AUTHORIZATION_H

#include "myproxy_creds.h"

typedef enum {
  AUTHORIZETYPE_NULL = 0,
  AUTHORIZETYPE_PASSWD,
#if defined(HAVE_LIBSASL2)
  AUTHORIZETYPE_SASL,
#endif
  AUTHORIZETYPE_CERT
} author_method_t;

/* client/server authorization data */
typedef struct
{
  char *server_data;   /* data sent from the server.  It can be arbitrary ASCII
                          string ending with '\0'. */
  char *client_data;   /* data created by the client according to server_data */
  size_t client_data_len; 
  author_method_t  method;
} authorization_data_t;

int authorization_init_server (authorization_data_t ***data);
void authorization_data_free (authorization_data_t **data);

char * authorization_get_name(author_method_t method);
author_method_t authorization_get_method(char *name);

/* 
 * Fill in author_data with client's response and return pointer into 
 * author_data to data choosen by the client. No new space is allocated for 
 * the returned pointer. This function is called by the server.
 * authorization_data_t is supposed to be allocated and (partly) filled in by 
 * the server. 
 */
authorization_data_t * 
authorization_store_response(char *, 
                             size_t, 
                             author_method_t,
                             authorization_data_t **);

/*
 * Search a data for the supplied method in the supplied list. Using the extra 
 * data fill in the response and return a pointer into the list to the data 
 * choosen. No special space is allocated for the return value. 
 * Called by the client.
 */
authorization_data_t *
authorization_create_response(authorization_data_t **, 
                              author_method_t,
                              void *extra_data,
                              size_t extra_data_len);
/*
 * Verifies that data sent by the client matches the expecting value for the 
 * server's challenge.
 */
int authorization_check(authorization_data_t *client_auth_data,
                        struct myproxy_creds *creds,
                        char *client_name);

#endif /* __MYPROXY_AUTHORIZATION_H */
