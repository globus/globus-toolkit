/*
 * gsi_socket.h
 *
 * Interface for a GSI-protected socket.
 */

#ifndef __GSI_SOCKET_H
#define __GSI_SOCKET_H

#include <sys/types.h>

struct _gsi_socket;
typedef struct _gsi_socket GSI_SOCKET;

/*
 * Return code for many of the GSI_SOCKET routines:
 */
#define GSI_SOCKET_SUCCESS		0
#define GSI_SOCKET_ERROR		-1
#define GSI_SOCKET_TRUNCATED		-2

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
 * Fills in buffer with a NUL-terminated string (possibly multi-lined)
 * describing  * the last error the occurred with this GSI_SOCKET.
 * bufferlen should be the size of buffer. It returns the number of
 * characters actually put into buffer (not including the trailing
 * NUL).
 *
 * If there is no error known of, buffer will be set to a zero-length
 * string, and zero will be returned.
 *
 * If the buffer wasn't big enough and the string was truncated,
 * -1 will be returned.
 */
int GSI_SOCKET_get_error_string(GSI_SOCKET *gsi_socket,
				char *buffer,
				int buffer_len);

/*
 * GSI_SOCKET_clear_error()
 *
 * Clears any error state in the given GSI_SOCKET object.
 */
void GSI_SOCKET_clear_error(GSI_SOCKET *gsi_socket);

/*
 * GSI_SOCKET_set_encryption()
 *
 * If value is non-zero data transmitted will be encrypted.
 * If value is zero data will not be encrypted (this is the default).
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_set_encryption(GSI_SOCKET *gsi_socket,
			     int value);

/*
 * GSI_SOCKET_set_expected_peer_name()
 *
 * This should be called before GSI_SOCKET_authentication_init() to
 * set the expected name of the entity we are connecting do. By default
 * an appropriate service name will be expected. This allows the
 * connector to set it to anything they desire.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_set_expected_peer_name(GSI_SOCKET *gsi_socket,
				      const char *name);

/*
 * GSI_SOCKET_authentication_init()
 *
 * Perform the client-side authentication process.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_authentication_init(GSI_SOCKET *gsi_socket);

/*
 * GSI_SOCKET_use_creds()
 *
 * Use the credentials pointed to by creds for authentication.
 * The exact contents of creds is mechanism-specific, but is
 * generally a filename. If creds == NULL, the defaults credentials
 * should be used.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_use_creds(GSI_SOCKET *gsi_socket,
			 const char *creds);

/*
 * GSI_SOCKET_authentication_accept()
 *
 * Perform the server-side authentication process.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_authentication_accept(GSI_SOCKET *gsi_socket);

/*
 * GSI_SOCKET_get_client_identity()
 *
 * Fill in buffer with a string representation of the authenticated
 * identity of the client on the other side of the socket.
 *
 * If the client is not identified, returns GSI_SOCKET_ERROR.
 *
 * If the buffer is too small and the string is truncated returns
 * GSI_SOCKET_TRUNCATED.
 *
 * Other wise returns the number of characters written into the buffer
 * (not including the trailing NUL).
 *
 */
int GSI_SOCKET_get_client_name(GSI_SOCKET *gsi_socket,
			       char *buffer,
			       int buffer_len);

/*
 * GSI_SOCKET_write_buffer()
 *
 * Write the given buffer to the peer. If authentication has been done,
 * the buffer will be protected via the GSI.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_write_buffer(GSI_SOCKET *gsi_socket,
			    const char *buffer,
			    size_t buffer_len);

/*
 * GSI_SOCKET_read_buffer()
 *
 * Read the given buffer from the peer. If authentication has been done,
 * the buffer will be protected via the GSI.
 *
 * buffer should be pointing at an allocated buffer bufferlen bytes
 * in length.
 *
 * Note that data is read like individual datagrams and not like a 
 * stream. So if three writes are done of 150, 75 and 50 bytes, and
 * then reads are done into a 100 byte buffer, the first read will
 * read 100 bytes and return GSI_SOCKET_TRUNCATED, the second will
 * read 50 bytes, the third 75 bytes and the fourth 50 bytes.
 *
 * Returns number of bytes put into buffer, GSI_SOCKET_ERROR on error,
 * GSI_SOCKET_TRUNCATED if are more bytes to be returned.
 */
int GSI_SOCKET_read_buffer(GSI_SOCKET *gsi_socket,
			   char *buffer,
			   size_t buffer_len);

/*
 * GSI_SOCKET_read_token()
 *
 * Read a token from the peer. If authentication has been done,
 * the buffer will be protected via the GSI.
 *
 * buffer will be set to point to an allocated buffer that should
 * be freed with GSI_SOCKET_free_token(). buffer_len will be
 * set to the length of the buffer.
 *
 * Returns GSI_SOCKET_SUCCESS or GSI_SOCKET_ERROR.
 */
int GSI_SOCKET_read_token(GSI_SOCKET *gsi_socket,
			  unsigned char **buffer,
			  size_t *buffer_len);

/*
 * GSI_SOCKET_free_token()
 *
 * Free a token returned by GSI_SOCKET_read_token().
 */
void GSI_SOCKET_free_token(unsigned char *buffer);

/*
 * GSI_SOCKET_delegation_init_ext()
 *
 * Delegate credentials to the peer.
 *
 * source_credentials should be a string specifying the location
 * of the credentials to delegate. This is mechanism specific,
 * but typically a file path. If NULL, the default credentials for
 * the current context will be used.
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
				   const char *source_credentials,
				   int flags,
				   int lifetime,
				   const void *restrictions);
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
 * delegated_credentials will be filled in with the location of
 * the delegated credentials. This is mechanism-specific but
 * probably a file path.
 *
 * Returns GSI_SOCKET_SUCCESS on success, GSI_SOCKET_ERROR otherwise.
 */
int GSI_SOCKET_delegation_accept_ext(GSI_SOCKET *gsi_socket,
				     char *delegated_credentials,
				     int delegated_credentials_len);

/*
 * GSI_SOCKET_allow_anonymous()
 *
 * If value=1, allow anonymous GSSAPI/SSL authentication.
 * Otherwise, the client must have a valid GSSAPI/SSL credential.
 * Default is to *not* allow anonymous authentication.
 *
 */
int GSI_SOCKET_allow_anonymous(GSI_SOCKET *self, const int value);

#endif /* !__GSI_SOCKET_H */
