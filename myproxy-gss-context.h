/*
 * myproxy-gss-context.h
 *
 * An object wrapper around a GSSAPI context.
 */

#ifndef __MYPROXY_GSS_CONTEXT_H
#define __MYPROXY_GSS_CONTEXT_H

/*
 * Definition of the MYPROXY_GSS_CONTEXT object.
 */
struct _myproxy_gss_context;

typedef struct _myproxy_gss_context MYPROXY_GSS_CONTEXT;

/*
 * MYPROXY_GSS_CONTEXT_new()
 *
 * Allocate and return a MYPROXY_GSS_CONTEXT object.
 */
MYPROXY_GSS_CONTEXT *MYPROXY_GSS_CONTEXT_new();

/*
 * MYPROXY_GSS_CONTEXT_destroy()
 *
 * Destroy the given MYPROXY_GSS_CONTEXT object and deallocate
 * all memory associated with it.
 */
void MYPROXY_GSS_CONTEXT_destroy(MYPROXY_GSS_CONTEXT *context);

/*
 * MYPROXY_GSS_CONTEXT_set_socket()
 *
 * Sets the socket descriptor to be used for all communications.
 */
void MYPROXY_GSS_CONTEXT_set_socket(MYPROXY_GSS_CONTEXT *context,
				    int sock);

/*
 * MYPROXY_GSS_CONTEXT_get_error_string()
 *
 * Returns a (potentially multiline) string describing the last
 * error that occurred involving the given MYPROXY_GSS_CONTEXT
 * object. Returns NULL if no error has occurred.
 */
char *MYPROXY_GSS_CONTEXT_get_error_string(MYPROXY_GSS_CONTEXT *context);

/*
 * MYPROXY_GSS_CONTEXT_clear_error()
 *
 * Clear any error state associated with the give MYPROXY_GSS_CONTEXT
 * object.
 */
void MYPROXY_GSS_CONTEXT_clear_error(MYPROXY_GSS_CONTEXT *context);

/*
 * MYPROXY_GSS_CONTEXT_get_client_name()
 *
 * This routine, when called by the myproxy server, returns a
 * string containing the name of the attached client.
 * If called by the client, or before authentication has taken
 * place, returns NULL.
 */
char *MYPROXY_GSS_CONTEXT_get_client_name(MYPROXY_GSS_CONTEXT *context);

#endif /* !__MYPROXY_GSS_CONTEXT_H */
