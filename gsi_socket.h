/*
 * gsi_socket.h
 *
 * Interface for a GSI-protected socket.
 */

#ifndef __GSI_SOCKET_H
#define __GSI_SOCKET_H

struct _gsi_socket;
typedef struct _gsi_socket GSI_SOCKET;

/*
 * Return code for many of the GSI_SOCKET routines:
 */
#define GSI_SOCKET_SUCCESS		0
#define GSI_SOCKET_ERROR		-1

/*
 * GSI_SOCKET_new()
 *
 * Create a new GSI_SOCKET object for a socket descriptor.
 *
 * Returns NULL on memory allocation failure.
 */
GSI_SOCKET *GSI_SOCKET_new(int sock);

/*
 * GSI_SOCKET_destroy()
 *
 * Destroy the GSI_SOCKET object and deallocated all associated
 * memory.
 */
void GSI_SOCKET_destroy(GSI_SOCKET *gsi_socket);

/*
 * GSI_SOCKET_get_error_string()
 *
 * Returns a NUL-terminated string (possibly multi-lined) describing
 * the last error the occurred with this GSI_SOCKET. Returns NULL
 * if no error has occurred.
 */
char *GSI_SOCKET_get_error_string(GSI_SOCKET *gsi_socket);

/*
 * GSI_SOCKET_clear_error()
 *
 * Clears any error state in the given GSI_SOCKET object.
 */
void GSI_SOCKET_clear_error();

/*
 * GSI_SOCKET_authentication_init()
 *
 * Perform the client-side authentication process.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_authentication_init(GSI_SOCKET *gsi_socket);

/*
 * GSI_SOCKET_authentication_accept()
 *
 * Perform the server-side authentication process.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_authentication_accept(GSI_SOCKET *gsi_socket);

/*
 * GSI_SOCKET_write_buffer()
 *
 * Write the given buffer to the peer. If authentication has been done,
 * the buffer will be protected via the GSI.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_write_buffer(GSI_SOCKET *gsi_socket,
			    char *buffer,
			    size_t buffer_len);

/*
 * GSI_SOCKET_read_buffer()
 *
 * Read the given buffer from the peer. If authentication has been done,
 * the buffer will be protected via the GSI.
 *
 * *p_buffer will be set to point at an allocated buffer containing
 * the data. It should be freed by the caller.
 *
 * *p_buffer_len will be set to the length of the read data.
 *
 * Returns number of bytes read on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_write_buffer(GSI_SOCKET *gsi_socket,
			    char **p_buffer,
			    size_t *p_buffer_len);

/*
 * GSI_SOCKET_delegation_init_ext()
 *
 * Delegate credentials to the peer.
 *
 * source_credentials should be a string specifying the location
 * of the credentials to delegate. If NULL, the default
 * credentials for the current context will be used.
 *
 * flags is reserved for future use and should currently always be
 * GSI_SOCKET_DELEGATION_FLAGS_DEFAULT.
 *
 * lifetime should be the lifetime of the delegated credentials
 * in seconds. A value of GSI_SOCKET_DELEGATION_LIFETIME_MAXIMUM
 * indicates that the longest possible lifetime should be delegated.
 *
 * restrictions is reserved for future use and should currently always be
 * GSI_SOCKET_DELEGATION_RESTRICTIONS_DEFAULT.
 *
 * Returns GSI_SOCKET_SUCCESS success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_delegation_init_ext(GSI_SOCKET *gsi_socket,
				   char *source_credentials,
				   int flags,
				   int lifetime,
				   void *restrictions);
/*
 * Values for GSI_SOCKET_DELEGATION_init() flags:
 */
#define GSI_SOCKET_DELEGATION_FLAGS_DEFAULT			0x0000

/*
 * Values for GSI_SOCKET_DELEGATION_init() lifetime:
 */
#define GSI_SOCKET_DELEGATION_LIFETIME_MAXIMUM			0x0000

/*
 * Valyes for GSI_SOCKET_DELEGATION_init() restrictions:
 */
#define GSI_SOCKET_DELEGATION_RESTRICTIONS_DEFAULT		NULL

/*
 * GSI_SOCKET_delegation_accept_ext()
 *
 * Accept delegated credentials from the peer.
 *
 * If p_target_credentials is NULL, it will be set to point to
 * a allocated string (to be freed by caller) indicating the
 * location of the received credentials. If target_credentials
 * is non-NULL it should point to a string indicating the
 * desired location for the credentials to be stored.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_delegation_accept_ext(GSI_SOCKET *gsi_socket,
				     char **p_target_credentials);


#endif /* !__GSI_SOCKET_H */
