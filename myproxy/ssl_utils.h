/*
 * ssl_utils.h
 *
 * Functions for interacting with SSL, X509, etc.
 */
#ifndef _SSL_UTILS_H
#define _SSL_UTILS_H

struct _ssl_credentials;
typedef struct _ssl_credentials SSL_CREDENTIALS;

/*
 * ssl_destroy_credentials()
 *
 * Destroys the given credentials, deallocating all memory
 * associated with them.
 */
void ssl_destroy_credentials(SSL_CREDENTIALS *creds);

/*
 *
 * ssl_generate_proxy_request()
 *
 * Generate a request for a proxy.
 *
 * pcreds will be filled in with the private key and should be
 * passed to ssl_accept_proxy() to be filled in with the
 * returned certificate.
 *
 * buffer will be set to point at an allocated buffer containing
 * data to be passed to the signer to be passed into
 * ssl_sign_proxy_request().
 *
 * buffer_length will be filled in with the length of buffer.
 *
 * user_certificate can contain a certificate which will be
 * used for the name and key length of the proxy. This may
 * be NULL in which case an empty name and default key length
 * will be used.
 *
 * requested_bits will be used as the key length for the
 * new proxy. If 0 then the length of user_certificate key
 * will be used.
 *
 * callback can point to a function that will be called
 * during key generation.
 */
int ssl_generate_proxy_request(SSL_CREDENTIALS	**new_creds,
			       unsigned char	**buffer,
			       int		*buffer_length,
			       int		requested_bits,
			       void		(*callback)(int,int,char *));


/*
 * ssl_load_certificate()
 *
 * Load a certificate from the given file into the given set of
 * credentials. Any existing certificate will be erased.
 *
 * Returns 0 on success, -1 on error setting verror.
 */
int ssl_load_cert(SSL_CREDENTIALS		*creds,
		  const char			*path);

/*
 * ssl_load_private_key()
 *
 * Load a key from the given file, using pass_phrase if needed,
 * and storing it in the given credentials structure. pass_phrase
 * may be null. Any existing key will be erased.
 *
 * Returns 0 on success, -1 on error.
 */
int ssl_load_private_key(SSL_CREDENTIALS	*creds,
			 const char		*path,
			 const char		*pass_phrase);

/*
 * ssl_load_proxy()
 *
 * Load a proxy certificate and key from the given file, using pass_phrase
 * if needed, and storing the credentials in the given SSL_CREDENTIALS
 * structure. pass_phrase may be NULL. Any existing credentials in
 * the SSL_CREDENTIALS structure will be erased.
 *
 * Returns 0 on success, -1 on error.
 */
int ssl_load_proxy(SSL_CREDENTIALS		*creds,
		   const char			*path,
		   const char			*pass_phrase);

/*
 * ssl_new_credentials()
 *
 * Return a empty credentials structure for use.
 *
 * Returns NULL on error.
 */
SSL_CREDENTIALS *ssl_new_credentials();


#endif /* _SSL_UTILS_H */
