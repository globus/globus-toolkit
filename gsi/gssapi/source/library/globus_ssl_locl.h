#ifndef GLOBUS_SSL_LOCL_H
#define GLOBUS_SSL_LOCL_H

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
#define SSL_STRONG_MASK 0x000001fcL
#else
#define SSL_STRONG_MASK 0x000000fcL
#endif

#define SSL_LOW 0x00000020L

typedef struct ssl3_enc_method
	{
	int (*enc)(SSL *, int);
	int (*mac)(SSL *, unsigned char *, int);
	int (*setup_key_block)(SSL *);
	int (*generate_master_secret)(SSL *, unsigned char *, unsigned char *, int);
	int (*change_cipher_state)(SSL *, int);
#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
	int (*final_finish_mac)(SSL *, EVP_MD_CTX *, EVP_MD_CTX *, const char *, int, unsigned char *);
#else
	int (*final_finish_mac)(SSL *, const char *, int, unsigned char *);
#endif
	int finish_mac_length;
#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
	int (*cert_verify_mac)(SSL *, EVP_MD_CTX *, unsigned char *);
#else
	int (*cert_verify_mac)(SSL *, int, unsigned char *);
#endif
	const char *client_finished_label;
	int client_finished_label_len;
	const char *server_finished_label;
	int server_finished_label_len;
	int (*alert_value)(int);
	} SSL3_ENC_METHOD;

int ssl3_setup_buffers(SSL *s);

int ssl_init_wbio_buffer(SSL *s, int push);
void ssl_free_wbio_buffer(SSL *s);

int ssl3_setup_key_block(SSL *s);
void ssl3_cleanup_key_block(SSL *s);

#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
int ssl_cipher_get_evp(const SSL_SESSION *s, const EVP_CIPHER **enc,
		       const EVP_MD **md, int *mac_pkey_type,
		       int *mac_secret_size, SSL_COMP **comp);
#else
int ssl_cipher_get_evp(SSL_SESSION *s, const EVP_CIPHER **enc,
		       const EVP_MD **md, SSL_COMP **comp);
#endif

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
#endif
