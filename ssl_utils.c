/*
 * ssl_utils.c
 *
 * Routines for interacting directly with SSL, X509 certificates, etc.
 */


#include "verror.h"

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

/* Must be included after stdio.h */
#include "ssl_utils.h"

#include <x509.h>
#include <pem.h>
#include <err.h>

#if SSLEAY_VERSION_NUMBER > 0x0903

/* OpenSSL 0.9.4 */
#define PEM_CALLBACK(A,B)  A, B

#else /* ! SSLEAY_VERSION_NUMBER > 0x0903 */

/* SSLeay 0.9.0 */
#define PEM_CALLBACK(A,B)  A

#endif /* ! SSLEAY_VERSION_NUMBER > 0x0903 */

struct _ssl_credentials
{
    X509		*certificate;
    EVP_PKEY		*private_key;
    STACK		*certificate_chain;
};

/**********************************************************************
 *
 * Internal variables.
 *
 */

/*
 * Holder for pass phrase so callback function can find it.
 */
static const char *_ssl_pass_phrase = NULL;

/**********************************************************************
 *
 * Internal functions.
 *
 */

/*
 * ssl_error_to_verror()
 *
 * Transfer an error description out of the ssl error handler to verror.
 */
static void
ssl_error_to_verror()
{
    while (ERR_peek_error() != 0)
    {
	unsigned long error;
	ERR_STATE *error_state;
	const char *error_data;
	int error_number;
	
	/* Find data for last error */
	error_state = ERR_get_state();

	error_number = (error_state->bottom + 1) % ERR_NUM_ERRORS;
	
	error_data = error_state->err_data[error_number];

	/* Pop error off of stack */
	error = ERR_get_error();
	
	/* Now add to verror state */
	verror_put_string(ERR_error_string(error, NULL));

	if (error_data != NULL)
	{
	    verror_put_string(error_data);
	}
    }
    
    ERR_clear_error();
}

/*
 * ssl_free_cert_chain()
 *
 * Free the given certificate chain and all it contents.
 */
static void
ssl_free_cert_chain(STACK			*cert_chain)
{
    if (cert_chain != NULL)
    {
	sk_pop_free(cert_chain, X509_free);
    }
}

/*
 * ssl_free_credentials_contents()
 *
 * Free all the contents of the given credentials without freeing
 * the credentials structure itself.
 */
static void
ssl_free_credentials_contents(SSL_CREDENTIALS	*creds)
{
    if (creds != NULL)
    {
	if (creds->certificate != NULL) 
	{
	    X509_free(creds->certificate);
	}
	
	if (creds->private_key != NULL)
	{
	    EVP_PKEY_free(creds->private_key);
	}
	
	if (creds->certificate_chain != NULL)
	{
	    ssl_free_cert_chain(creds->certificate_chain);
	}
    }
}


/*
 * ssl_get_key_size()
 *
 * Given a certificate return the size of the key for the certificate
 * in bits.
 *
 * Returns -1 on error.
 */
static int
ssl_get_key_size(X509				*certificate)
{
    EVP_PKEY		*key;
    int			key_size = -1;
    
    assert(certificate != NULL);
	
    key = X509_get_pubkey(certificate);
	
    if (key == NULL)
    {
	verror_put_string("Error reading current certificate to make proxy request");
	ssl_error_to_verror();
	goto error;
    }
	
    if (key->type != EVP_PKEY_RSA)
    {
	verror_put_string("Current certificate wrong key type making proxy request");
	goto error;
    }
	
    /* Success. Convert from bytes to bits */
    key_size = EVP_PKEY_size(key) * 8;

  error:
    return key_size;
}

   
    
/*
 * ssl_get_proxy_name()
 *
 * Given a certificate, return the name of the proxy certificate
 * that would be generated from the certificate. If no certificate
 * is supplied, a blank name is used.
 *
 * Returns 0 on success, -1 on error.
 */
static X509_NAME *
ssl_get_proxy_name(X509				*certificate)
{
    X509_NAME			*name = NULL;
    X509_NAME_ENTRY		*name_entry =NULL;

    if (certificate != NULL)
    {
	name = X509_NAME_dup(X509_get_subject_name(certificate));
	
	if (name == NULL)
	{
	    verror_put_string("Error reading name from user certificate generateing new proxy request");
	    ssl_error_to_verror();
	    goto error;
	}
    }
    else
    {
	name = X509_NAME_new();
	
	if (name == NULL)
	{
	    verror_put_string("Error generating name generateing new proxy request");
	    ssl_error_to_verror();
	    goto error;
	}
    }

    name_entry = X509_NAME_ENTRY_create_by_NID(NULL,
					       NID_commonName,
					       V_ASN1_APP_CHOOSE,
					       (unsigned char *)"proxy",
					       -1);
    
    if (name_entry == NULL)
    {
	verror_put_string("Error generating name (proxy extension) generating new proxy_request");
	ssl_error_to_verror();
	
	X509_NAME_free(name);
	name = NULL;
	goto error;
    }
    
    if (X509_NAME_add_entry(name, name_entry,
			    X509_NAME_entry_count(name), 0 /* new set */) == 0)
    {
	verror_put_string("Error generating name (appending suffix) generating new proxy_request");
	ssl_error_to_verror();
	
	X509_NAME_free(name);
	name = NULL;
	goto error;
    }

  error:
    if (name_entry != NULL)
    {
	X509_NAME_ENTRY_free(name_entry);
    }
    
    return name;
}



/*
 * ssl_init()
 *
 * Initialize the SSL libraries. Should be called first. Can be called
 * multiple times.
 */
static void
ssl_init()
{
    static int ssl_inited = 0;
    
    if (ssl_inited == 0)
    {
	ssl_inited = 1;

	SSL_load_error_strings();

	SSLeay_add_ssl_algorithms();
    }
}

	
/*
 * ssl_pass_phrase_callback()
 *
 * Callback from PEM_read_PrivateKey() in ssl_load_user_key()
 * to return the passphrase stored in _ssl_pass_phrase.
 */
static int
ssl_pass_phrase_callback(char			*buffer,
			 int			buffer_len,
			 int			verify /* Ignored */)
{
    int rc;

    /* SSL libs supply these, make sure they are reasonable */
    assert(buffer != NULL);
    assert(buffer_len > 0);
    
    if (_ssl_pass_phrase == NULL)
    {
	strcpy(buffer, "");
    }
    else
    {
	strncpy(buffer, _ssl_pass_phrase, buffer_len);
	buffer[buffer_len - 1] = '\0';
    }

    return strlen(buffer);
}

/*
 * ssl_x509_request_to_buffer()
 *
 * Dump the given X509 request structure to an allocated buffer.
 *
 * Returns 0 on success, -1 on error.
 */
static int
ssl_x509_request_to_buffer(X509_REQ		*request,
			   unsigned char	**buffer,
			   int			*buffer_length)
{
    char *tmp_buffer = NULL;
    int tmp_buffer_size;
    int return_status = -1;
    BIO *bio = NULL;
    
    assert(request != NULL);
    assert(buffer != NULL);
    assert(buffer_length != NULL);

    bio = BIO_new(BIO_s_mem());
    
    if (bio == NULL)
    {
	verror_put_string("Failed dumping X509 request to buffer (BIO_new() failed)");
	ssl_error_to_verror();
	goto error;
    }
    
    if (i2d_X509_REQ_bio(bio, request) == 0)
    {
	verror_put_string("Failed dumping X509 request to buffer");
	ssl_error_to_verror();
	goto error;
    }
    
    tmp_buffer_size = BIO_pending(bio);
    
    tmp_buffer = malloc(tmp_buffer_size);
    
    if (tmp_buffer == NULL)
    {
	verror_put_string("Failed dumping X509 request to buffer (malloc() failed)");
	verror_put_errno(errno);
	goto error;
    }
    
    if (BIO_read(bio, tmp_buffer, tmp_buffer_size) == 0)
    {
	verror_put_string("Failed dump X509 request to buffer (BIO_read() failed)");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Success */
    *buffer = tmp_buffer;
    *buffer_length = tmp_buffer_size;
    return_status = 0;
    
  error:
    if (bio != NULL)
    {
	BIO_free(bio);
    }
    
    if (return_status == -1)
    {
	if (tmp_buffer != NULL)
	{
	    free(tmp_buffer);
	}
    }
    
    return return_status;
}

    
    
    
/**********************************************************************
 *
 * API Functions
 *
 */


void
ssl_destroy_credentials(SSL_CREDENTIALS		*creds)
{
    ssl_init();
    
    if (creds != NULL)
    {
	ssl_free_credentials_contents(creds);
	
	free(creds);
    }
}

int
ssl_generate_proxy_request(SSL_CREDENTIALS	**new_creds,
			   unsigned char	**buffer,
			   int			*buffer_length,
			   int			requested_bits,
			   void			(*callback)(int,int,char *))
{
    SSL_CREDENTIALS		*creds = NULL;
    int				new_key_bits;
    const int			default_key_size = 512;	/* bits */
    RSA				*rsa = NULL;
    X509_REQ			*request = NULL;
    X509_NAME			*name = NULL;
    int				return_status = -1;
    EVP_PKEY			*key = NULL;
    
    ssl_init();
    
    assert(new_creds != NULL);
    assert(buffer != NULL);
    assert(buffer_length != NULL);

    /* Make new credentials structure to hold new certificate */
    creds = ssl_new_credentials();
    
    if (creds == NULL)
    {
	goto error;
    }
    
    /* How many bits do we want the new key to be? */
    if (requested_bits != 0)
    {
	new_key_bits = requested_bits;
    }
    else
    {
	/* Default */
	new_key_bits = default_key_size;
    }
    
    /* Generate key for request */
    rsa = RSA_generate_key(new_key_bits,
			   RSA_F4 /* public exponent */,
			   callback,
			   NULL /* callback argument */);
    
    if (rsa == NULL)
    {
	verror_put_string("Error generating new keys for proxy request");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Build the request */
    request = X509_REQ_new();
    
    if (request == NULL)
    {
	verror_put_string("Error generating new proxy request structure");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Not sure what this does */
    if (X509_REQ_set_version(request, 0L) == 0)
    {
	verror_put_string("Error generating new proxy request (setting version)");
	ssl_error_to_verror();
	goto error;
    }
    
    /*
     * Just use an empty name and let signer fill in the correct name.
     */
    name = X509_NAME_new();
    
    if (name == NULL)
    {
	verror_put_string("Error generating new proxy request (generating name)");
	ssl_error_to_verror();
	goto error;
    }

    if (X509_REQ_set_subject_name(request, name) == 0)
    {
	verror_put_string("Error generating new proxy request (setting name)");
	ssl_error_to_verror();
	goto error;
    }	

    key = EVP_PKEY_new();
    
    if (key == NULL)
    {
	verror_put_string("Error generating new proxy keys");
	ssl_error_to_verror();
	goto error;
    }
    
    if (EVP_PKEY_assign_RSA(key, rsa) == 0)
    {
	verror_put_string("Error generating proxy request (assigning RSA key)");
	ssl_error_to_verror();
	goto error;
    }

    if (X509_REQ_set_pubkey(request, key) == 0)
    {
	verror_put_string("Error generating new proxy request (setting public key)");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Request successfully generated, now dump to buffer */
    if (ssl_x509_request_to_buffer(request,
				   buffer,
				   buffer_length) == -1)
    {
	goto error;
    }
    
    /* Success */
    return_status = 0;

    *new_creds = creds;
    creds = NULL;

  error:
    if (name != NULL)
    {
	X509_NAME_free(name);
    }
    
    if (key != NULL)
    {
	EVP_PKEY_free(key);
    }

    if (request != NULL)
    {
	X509_REQ_free(request);
    }
    
    if (return_status == -1)
    {
	if (rsa != NULL)
	{
	    RSA_free(rsa);
	}
    }
    
    return return_status;
}

	
		     
		     
int
ssl_load_certificate(SSL_CREDENTIALS		*creds,
		     const char			*path)
{
    FILE		*cert_file = NULL;
    X509		*cert = NULL;
    int			return_status = -1;
    
    assert(creds != NULL);
    assert(path != NULL);

    ssl_init();
    
    cert_file = fopen(path, "r");
    
    if (cert_file == NULL) 
    {
	verror_put_string("Error opening certificate file %s", path);
	verror_put_errno(errno);
	goto error;
    }
    
    if (PEM_read_X509(cert_file, &cert, PEM_CALLBACK(NULL,NULL)) == NULL)
    {
	verror_put_string("Error reading certificate %s", path);
	ssl_error_to_verror();
	goto error;
    }

    if (creds->certificate != NULL)
    {
	X509_free(creds->certificate);
    }
    
    creds->certificate = cert;

    /* Success */
    return_status = 0;
    
  error:
    if (cert_file != NULL) 
    {
	fclose(cert_file);
    }
    
    return return_status;
}

int
ssl_load_private_key(SSL_CREDENTIALS		*creds,
		     const char			*path,
		     const char			*pass_phrase)
{
    FILE		*key_file = NULL;
    EVP_PKEY		*key = NULL;
    int			return_status = -1;
    
    assert(creds != NULL);
    assert(path != NULL);
    
    ssl_init();
    
    /* 
     * Put pass phrase where the callback function can find it.
     */
    _ssl_pass_phrase = pass_phrase;
    
    key_file = fopen(path, "r");
    
    if (key_file == NULL)
    {
	verror_put_string("Error opening certificate file %s", path);
	verror_put_errno(errno);
	goto error;
    }

    if (PEM_read_PrivateKey(key_file, &(key),
			    PEM_CALLBACK(ssl_pass_phrase_callback,
					 NULL)) == NULL)
    {
	unsigned long error;
	
	error = ERR_peek_error();

	/* If this is a bad password, return a better error message */
	if (ERR_GET_REASON(error) == EVP_R_BAD_DECRYPT)
	{
	    verror_put_string("Bad password");
	}
	else 
	{
	    verror_put_string("Error reading private key %s", path);
	    ssl_error_to_verror();
	}
	
	goto error;
    }
    
    if (creds->private_key != NULL)
    {
	EVP_PKEY_free(creds->private_key);
    }

    creds->private_key = key;
    
    /* Success */
    return_status = 0;

  error:
    if (key_file != NULL)
    {
	fclose(key_file);
    }
    
    return return_status;
}

int
ssl_load_proxy(SSL_CREDENTIALS			*creds,
	       const char			*path,
	       const char			*pass_phrase)
{
    FILE		*proxy_file = NULL;
    X509		*cert = NULL;
    EVP_PKEY		*key = NULL;
    STACK		*cert_chain = NULL;
    int			certificate_count = 0;
    int			return_status = -1;
    
    assert(creds != NULL);
    assert(path != NULL);
    
    /* 
     * Put pass phrase where the callback function can find it.
     */
    _ssl_pass_phrase = pass_phrase;
    
    proxy_file = fopen(path, "r");
    
    if (proxy_file == NULL)
    {
	verror_put_string("Error opening proxy file %s", path);
	verror_put_errno(errno);
	goto error;
    }
    
    /*
     * Proxy file contains proxy certificate followed by proxy
     * private key, followed by the certificate chain.
     */

    /* Read proxy certificate */
    if (PEM_read_X509(proxy_file, &cert, PEM_CALLBACK(NULL,NULL)) == NULL)
    {
	verror_put_string("Error reading proxy certificate %s", path);
	ssl_error_to_verror();
	goto error;
    }

    /* Read proxy private key */
    if (PEM_read_PrivateKey(proxy_file, &(key),
			    PEM_CALLBACK(ssl_pass_phrase_callback,
					 NULL)) == NULL)
    {
	unsigned long error;
	
	error = ERR_peek_error();

	/* If this is a bad password, return a better error message */
	if (ERR_GET_REASON(error) == EVP_R_BAD_DECRYPT)
	{
	    verror_put_string("Bad password");
	}
	else 
	{
	    verror_put_string("Error reading private key %s", path);
	    ssl_error_to_verror();
	}
	
	goto error;
    }

    /* Ok, now read the certificate chain */

    /* Create empty stack */
    cert_chain = sk_new_null();
    
    while (1)
    {
	X509 *certificate = NULL;
	
	if (PEM_read_X509(proxy_file, &certificate, PEM_CALLBACK(NULL,
								 NULL)) == NULL)
	{
	    /*
	     * If we just can't find a start line then we've reached EOF.
	     */
	    if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE)
	    {
		/* Just EOF, clear error and break out of loop */
		ERR_clear_error();
		break;
	    }

	    /* Actual error */
	    verror_put_string("Error reading certificate chain from proxy %s",
			      path);
	    ssl_error_to_verror();
	    goto error;
	}

	/* Add to chain */
	if (sk_insert(cert_chain, (char *) certificate,
		      sk_num(cert_chain)) == 0)
	{
	    verror_put_string("Error reading certificate chain from proxy %s",
			      path);
	    ssl_error_to_verror();
	    goto error;
	}
    } /* while(1) */

    /*
     * Ok, everything has been successfully read, now store it into
     * creds, removing any existing contents.
     */
    ssl_free_credentials_contents(creds);
    
    creds->private_key = key;
    creds->certificate = cert;
    creds->certificate_chain = cert_chain;
    
    /* Success */
    return_status = 0;
    
  error:
    if (return_status != 0)
    {
	/*
	 * On error, clean up any key, cert or chain. On success
	 * we don't want to do this as they are part of the creds.
	 */

	if (cert != NULL)
	{
	    X509_free(cert);
	}
	
	if (key != NULL)
	{
	    EVP_PKEY_free(key);
	}
	
	if (cert_chain)
	{
	    ssl_free_cert_chain(cert_chain);
	}
    }

    return return_status;
}


SSL_CREDENTIALS *
ssl_new_credentials()
{
    SSL_CREDENTIALS *creds = NULL;
    
    creds = malloc(sizeof(*creds));
    
    if (creds == NULL)
    {
	verror_put_errno(errno);
	goto error;
    }
    
    creds->certificate = NULL;
    creds->private_key = NULL;
    creds->certificate_chain = NULL;
    
  error:
    return creds;
}

    
	
	    
	    


 
