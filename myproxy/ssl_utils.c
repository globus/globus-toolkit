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

#define STACK_OF(A) STACK

#define sk_X509_NAME_ENTRY_num  sk_num
#define sk_X509_NAME_ENTRY_value  sk_value

#define sk_SSL_CIPHER_num  sk_num
#define sk_SSL_CIPHER_value  sk_value
#define sk_SSL_CIPHER_insert  sk_insert
#define sk_SSL_CIPHER_delete  sk_delete

#define sk_X509_EXTENSION_num sk_num
#define sk_X509_EXTENSION_value sk_value
#define sk_X509_EXTENSION_push sk_push
#define sk_X509_EXTENSION_new_null sk_new_null
#define sk_X509_EXTENSION_pop_free sk_pop_free

#define sk_X509_REVOKED_num sk_num
#define sk_X509_REVOKED_value sk_value

#endif /* ! SSLEAY_VERSION_NUMBER > 0x0903 */

/**********************************************************************
 *
 * Constants
 *
 */
#define PROXY_EXTENSION			"proxy"
#define LIMITED_PROXY_EXTENSION		"limited proxy"

#define PROXY_DEFAULT_LIFETIME		24 * 60 * 60 /* seconds */

/* Amount of clock skew to allow for when generating certificates */
#define PROXY_CLOCK_SKEW_ALLOWANCE	60 * 5 /* seconds */

#define PROXY_DEFAULT_VERSION		2L /* == v3 */

/**********************************************************************
 *
 * Internal data structures
 *
 */
struct _ssl_credentials
{
    X509		*certificate;
    EVP_PKEY		*private_key;
    STACK		*certificate_chain;
};

struct _ssl_proxy_restrictions
{
    /* 0 = unrestricted, 1 = limited */
    int			limited_proxy;

    /* Proxy lifetime in seconds, 0 means default, -1 means maximum */
    long		lifetime;
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
 * Given a certificate, and the restrictions associated with the
 * proxy we are generating return the name of the proxy certificate
 * that would be generated from the certificate. If no certificate
 * is supplied, a blank name is used.
 *
 * Returns 0 on success, -1 on error.
 */
static X509_NAME *
ssl_get_proxy_name(X509				*certificate,
		   SSL_PROXY_RESTRICTIONS	*restrictions)
{
    X509_NAME			*name = NULL;
    X509_NAME_ENTRY		*name_entry =NULL;
    unsigned char		*proxy_name_extension = PROXY_EXTENSION;
    
    if (restrictions != NULL)
    {
	/* Handle restrictions */
	if (restrictions->limited_proxy == 1)
	{
	    proxy_name_extension = LIMITED_PROXY_EXTENSION;
	}
    }
    
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
					       proxy_name_extension,
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
 * ssl_proxy_cert_from_buffer()
 *
 * Retrieve the proxy certificate and certificate chain from the
 * given buffer and put into creds which is assumed to already
 * contain the private key for the proxy certificate.
 *
 * Return 0 on success, -1 on error.
 */
static int
ssl_proxy_cert_from_buffer(SSL_CREDENTIALS	*creds,
			   unsigned char	*buffer,
			   int			buffer_length)
{
    BIO			*bio = NULL;
    X509		*proxy_cert = NULL;
    unsigned char	number_of_certs;
    int			cert_index = 0;
    STACK		*cert_chain = NULL;
    int			return_status = -1;
    
    assert(creds != NULL);
    assert(buffer != NULL);

    /* Transfer the buffer to a bio */
    bio = BIO_new(BIO_s_mem());
    
    if (bio == NULL)
    {
	verror_put_string("Failed unpacking proxy certificate from buffer (BIO_new failed)");
	ssl_error_to_verror();
	goto error;
    }
    
    if (BIO_write(bio, buffer, buffer_length) == -1)
    {
	verror_put_string("Failed unpacking proxy certificate from buffer (BIO_write() failed)");
	ssl_error_to_verror();
	goto error;
    }

    /*
     * Buffer contains:
     *		-a bytes containing the number of certificates.
     *          -the proxy certificate
     *          -the certificate chain
     */

    /* Read number of certificates */
    if (BIO_read(bio, &number_of_certs, sizeof(number_of_certs)) == 0)
    {
	verror_put_string("Failed unpacking proxy certificate from buffer (reading number of certificates)");
	ssl_error_to_verror();
	goto error;
    }

    if (number_of_certs == 0) 
    {
	verror_put_string("Failed unpacking proxy certificate from buffer (number of certificates == 0)");
	ssl_error_to_verror();
	goto error;
    }

    /* DEBUG */printf("Number of certs = %d\n", number_of_certs);
    
    /* Now read the proxy certificate */
    proxy_cert = d2i_X509_bio(bio, NULL /* make new cert */);
    
    if (proxy_cert == NULL)
    {
	verror_put_string("Failed unpacking proxy certificate from buffer (reading proxy certificate)");
	ssl_error_to_verror();
	goto error;
    }	

    /*
     * XXX This would be the place to make sure the proxy cert matches
     *     the key in creds.
     */

    cert_index++;
    
    /* Now read the certificate chain */
    cert_chain = sk_new_null();
    
    while (cert_index < number_of_certs)
    {
	X509		*cert;
	
	cert = d2i_X509_bio(bio, NULL /* make new cert */);
    
	if (cert == NULL)
	{
	    verror_put_string("Failed unpacking proxy certificate from buffer (reading cert chain)");
	    ssl_error_to_verror();
	    goto error;
	}

	if (sk_push(cert_chain, (char *) cert) == 0)
	{
	    verror_put_string("Failed unpacking proxy certificate from buffer (building cert chain)");
	    ssl_error_to_verror();
	    X509_free(cert);
	    goto error;
	}

	cert_index++;
    }
    
    /* Success */

    /* XXX Should free any current contents first */
    creds->certificate = proxy_cert;
    creds->certificate_chain = cert_chain;

    return_status = 0;
    
  error:
    if (bio != NULL)
    {
	BIO_free(bio);
    }
    
    if (return_status == -1)
    {
	if (proxy_cert != NULL)
	{
	    X509_free(proxy_cert);
	}
	
	if (cert_chain != NULL)
	{
	    ssl_free_cert_chain(cert_chain);
	}
    }

    return return_status;
}
    
    

/*
 * ssl_proxy_cert_to_buffer()
 *
 * Given a proxy certificate and the credentials used to make the proxy
 * certificate, dump the certificate allong with it's certificate chain
 * to a buffer suitable for shipping over the network.
 *
 * Returns 0 on success, -1 on error.
 */
static int
ssl_proxy_cert_to_buffer(SSL_CREDENTIALS	*creds,
			 X509			*proxy_certificate,
			 unsigned char		**buffer,
			 int			*buffer_length)
{
    BIO			*bio = NULL;
    unsigned char	number_of_certs;
    int			index;
    unsigned char	*tmp_buffer = NULL;
    int			tmp_buffer_size;
    int			return_status = -1;
    
    assert(creds != NULL);
    assert(proxy_certificate != NULL);
    assert(buffer != NULL);
    assert(buffer_length != NULL);
    
    bio = BIO_new(BIO_s_mem());
    
    if (bio == NULL)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (BIO_new() failed)");
	ssl_error_to_verror();
	goto error;
    }

    /*
     * Determine the number of certificates we are going to write to
     * to the buffer. We add two - one for the signer's certificate
     * and one for the proxy certificate.
     */
    number_of_certs = sk_num(creds->certificate_chain) + 2;

    if (BIO_write(bio, &number_of_certs, sizeof(number_of_certs)) == 0)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (BIO_write() failed)");
	ssl_error_to_verror();
	goto error;
    }

    /*
     * Now write out proxy certificate, followed by the signing certificate
     * and then the signing certificate's chain.
     */
    if (i2d_X509_bio(bio, proxy_certificate) == 0)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (write of proxy cert failed)");
	ssl_error_to_verror();
	goto error;
    }

    if (i2d_X509_bio(bio, creds->certificate) == 0)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (write of signing cert failed)");
	ssl_error_to_verror();
	goto error;
    }

    for (index = 0; index < sk_num(creds->certificate_chain); index++)
    {
	X509		*cert;
	
	cert = (X509 *) sk_value(creds->certificate_chain, index);
	
	if (i2d_X509_bio(bio, creds->certificate) == 0)
	{
	    verror_put_string("Failed dumping proxy certificate to buffer (write of cert chain failed)");
	    ssl_error_to_verror();
	    goto error;
	}
    }

    /* Now dump bio's contents to buffer */

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
	verror_put_string("Failed dumping proxy to buffer (BIO_read() failed)");
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
    char			*tmp_buffer = NULL;
    int				tmp_buffer_size;
    int				return_status = -1;
    BIO				*bio = NULL;
    
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

/*
 * ssl_x509_request_from_buffer()
 *
 * Parse a buffer as generated by ssl_x509_request_to_buffer() and
 * return the X509_REQ object.
 *
 * Returns 0 on success, -1 on error.
 */
static int
ssl_x509_request_from_buffer(unsigned char	*buffer,
			     int		buffer_length,
			     X509_REQ		**p_request)
{
    X509_REQ			*request = NULL;
    BIO				*bio = NULL;
    int				return_status = -1;
    
    assert(buffer != NULL);
    assert(p_request != NULL);
    
    bio = BIO_new(BIO_s_mem());

    if (bio == NULL)
    {
	verror_put_string("Failed unpacking X509 request from buffer (BIO_new() failed)");
	ssl_error_to_verror();
	goto error;
    }

    if (BIO_write(bio, buffer, buffer_length) == -1)
    {
	verror_put_string("Failed unpacking X509 request from buffer (BIO_write() failed)");
	ssl_error_to_verror();
	goto error;
    }
    
    request = d2i_X509_REQ_bio(bio, NULL /* make new req */);
    
    if (request == NULL)
    {
	verror_put_string("Failed unpacking X509 request from buffer");
	ssl_error_to_verror();
	goto error;
    }

    /* Success */
    *p_request = request;
    return_status = 0;

  error:
    if (bio)
    {
	BIO_free(bio);
    }
    
    if (return_status == -1)
    {
	if (request)
	{
	    X509_REQ_free(request);
	}
    }
    
    return return_status;
}

/*
 * ssl_x509_request_verify()
 *
 * Check the X509_REQUEST object and make sure it's properly formed
 * and signed. Note that this does not look at the name.
 *
 * Returns 0 on success, -1 on error.
 */
static int
ssl_x509_request_verify(X509_REQ		*request)
{
    int				return_status = -1;
    EVP_PKEY			*request_public_key = NULL;
    int				verify_result;
    
    assert(request != NULL);
    
    /* Make sure all the data appears to be present */
    if ((request->req_info == NULL) ||
	(request->req_info->pubkey == NULL) ||
	(request->req_info->pubkey->public_key == NULL) ||
	(request->req_info->pubkey->public_key->data == NULL))
    {
	verror_put_string("X509 request missing data");
	goto error;
    }

    /* Check signature on request */
    request_public_key = X509_REQ_get_pubkey(request);
    
    if (request_public_key == NULL)
    {
	verror_put_string("Error getting public key from X509 request");
	ssl_error_to_verror();
	goto error;
    }
    
    verify_result = X509_REQ_verify(request, request_public_key);
    
    if (verify_result < 0)
    {
	verror_put_string("Error verifying X509 request");
	ssl_error_to_verror();
	goto error;
    }
    
    if (verify_result == 0)
    {
	verror_put_string("Bad signature on request");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Success */
    return_status = 0;
    
  error:
    return return_status;
}

    
/**********************************************************************
 *
 * These are fairly major internal functions that rely on a lot
 * of the internal function above.
 *
 */


/*
 * ssl_generate_cert_request()
 *
 * Generate a certificate request.
 *
 * p_creds is filled in with a pointer to the start of the new
 * credentials.
 *
 * p_request is filled in with a pointer to the new request.
 *
 * requested_bits is the number of bits to used for the keys
 * of the new certificate. May be zero in which case a default
 * of 512 is used.
 *
 * callback is a function to be called back during the RSA key
 * generation. See SSLeay's doc/rsa.doc RSA_generate_key()
 * function for details.
 *
 * Returns 0 on success, -1 on error.
 */
static int
ssl_generate_cert_request(SSL_CREDENTIALS	**p_creds,
			  X509_REQ		**p_request,
			  X509_NAME		*requested_name,
			  int			requested_bits,
			  void			(*callback)(int,int,char *))
{
    const int			default_key_size = 512;	/* bits */
    SSL_CREDENTIALS		*creds = NULL;
    X509_NAME			*name = NULL;
    int				return_status = -1;
    EVP_PKEY			*key = NULL;
    RSA				*rsa = NULL;
    X509_REQ			*request = NULL;
    
    assert(p_creds != NULL);
    assert(p_request != NULL);
 
    /* Make new credentials structure to hold new certificate */
    creds = ssl_new_credentials();
    
    if (creds == NULL)
    {
	goto error;
    }
    
    /* How many bits do we want the new key to be? */
    if (requested_bits == 0)
    {
	requested_bits = default_key_size;
    }

     /* Generate key for request */
    rsa = RSA_generate_key(requested_bits,
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
    if (requested_name != NULL)
    {
	name = X509_NAME_dup(requested_name);

	if (name == NULL)
	{
	    verror_put_string("Error generating new proxy request (duping name)");
	    ssl_error_to_verror();
	    goto error;
	}
    }
    else
    {
	X509_NAME_ENTRY			*name_entry = NULL;

	/*
	 * We have no name to go on, however we can't just use an empty
	 * name as this causes d2i_X509_REQ_bio() to fail if we ever
	 * take this req and turn it into a buffer and then convert
	 * it back. I'm guessing this means that a req with an empty
	 * is probably illegal.
	 *
	 * So for now we will just create a bogus name to use. The
	 * idea is that whomever signs this certificate will put in
	 * whatever name they want anyways.
	 */
	name = X509_NAME_new();

	if (name == NULL)
	{
	    verror_put_string("Error generating new proxy request (generating name)");
	    ssl_error_to_verror();
	    goto error;
	}

	/* "certreq" is the bogus name I picked arbitratily */
	name_entry = X509_NAME_ENTRY_create_by_NID(NULL /* make new entry */,
						   NID_commonName,
						   V_ASN1_APP_CHOOSE,
						   (unsigned char *) "certreq",
						   -1 /* use strlen() */);
	
	if (name_entry == NULL)
	{
	    verror_put_string("Error generating new proxy request (generating empty name)");
	    ssl_error_to_verror();
	    goto error;
	}

	if (X509_NAME_add_entry(name, name_entry,
				X509_NAME_entry_count(name),
				0 /* create new set */) == 0)
	{
	   X509_NAME_ENTRY_free(name_entry);
	   verror_put_string("Error generating new proxy request (adding name entry)");
	   ssl_error_to_verror();
	   goto error;
	}

	X509_NAME_ENTRY_free(name_entry);
	
    }
    
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

    if (X509_REQ_sign(request, key, EVP_md5()) == 0)
    {
	verror_put_string("Error generating new proxy request (signing request)");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Success */
    *p_creds = creds;
    creds = NULL;
    
    *p_request = request;
    request = NULL;

    return_status = 0;
    

  error:
    if (name != NULL)
    {
	X509_NAME_free(name);
    }

    if (return_status == -1)
    {
    
	if (key != NULL)
	{
	    EVP_PKEY_free(key);
	}
    
	if (request != NULL)
	{
	    X509_REQ_free(request);
	}

	if (rsa != NULL)
	{
	    RSA_free(rsa);
	}

	if (creds != NULL)
	{
	    ssl_destroy_credentials(creds);
	}
    }
    
    return return_status;
}


/*
 * ssl_generate_proxy_certificate()
 *
 * Given the credentials and a certificate request, generate a proxy
 * certificate. ssl_x509_request_verify() is used to check the request.
 *
 * restrictions, if non-NULL, will be applied.
 *
 * Returns 0 on succes, -1 on error.
 */
static int
ssl_generate_proxy_certificate(SSL_CREDENTIALS		*creds,
			       X509_REQ			*request,
			       SSL_PROXY_RESTRICTIONS	*restrictions,
			       X509			**p_proxy_cert)
{
    long			lifetime = PROXY_DEFAULT_LIFETIME;
    X509_NAME			*proxy_name = NULL;
    X509			*proxy_certificate = NULL;
    ASN1_INTEGER		*serial_number = NULL;
    int				return_status = -1;
    
    assert(creds != NULL);
    assert(request != NULL);
    assert(p_proxy_cert != NULL);
    
    if (ssl_x509_request_verify(request) == -1)
    {
	goto error;
    }

    if (restrictions != NULL)
    {
	/* Parse restrictions */
	if (restrictions->lifetime != 0)
	{
	    lifetime = restrictions->lifetime;
	}
    }

    /* Make the certificate we will turn into the proxy */
    proxy_certificate = X509_new();
    
    if (proxy_certificate == NULL)
    {
	verror_put_string("Error generating proxy certificate (X509_new() failed)");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Generate the name the proxy certificate will have */
    proxy_name = ssl_get_proxy_name(creds->certificate, restrictions);
    
    if (proxy_name == NULL)
    {
	goto error;
    }

    if (X509_set_subject_name(proxy_certificate, proxy_name) == 0)
    {
	verror_put_string("Error generating proxy_certificate (error setting name)");
	ssl_error_to_verror();
	goto error;
    }
    
    if (X509_set_issuer_name(proxy_certificate,
			     X509_get_subject_name(creds->certificate)) == 0)
    {
	verror_put_string("Error generating proxy_certificate (error setting issuer name)");
	ssl_error_to_verror();
	goto error;
    }

    /* Assign proxy same serial number as user certificate */
    serial_number = X509_get_serialNumber(creds->certificate);
    
    if (X509_set_serialNumber(proxy_certificate, serial_number) == 0)
    {
	verror_put_string("Error generating proxy_certificate (setting serial number)");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Allow for clock skew */
    X509_gmtime_adj(X509_get_notBefore(proxy_certificate),
		    -(PROXY_CLOCK_SKEW_ALLOWANCE));

    /* Set expiration time */
    if (lifetime == -1L)
    {
	ASN1_UTCTIME		*user_cert_expires;
	
	/*
	 * Maximum lifetime requested, so set to the lifetime of the
	 * signing certificate.
	 */
	user_cert_expires = X509_get_notAfter(creds->certificate);
	
	X509_set_notAfter(proxy_certificate, user_cert_expires);
	}
    else
    {
	/* Set to requested lifetime */
	X509_gmtime_adj(X509_get_notAfter(proxy_certificate), lifetime);
    }

    /* Copy public key from request to certificate */
    if (X509_set_pubkey(proxy_certificate, X509_REQ_get_pubkey(request)) == 0)
    {
	verror_put_string("Error generating proxy_certificate (setting public key)");
	ssl_error_to_verror();
	goto error;
    }	

    /* Set the certificate version */
    if (X509_set_version(proxy_certificate, PROXY_DEFAULT_VERSION) == 0)
    {
	verror_put_string("Error generating proxy_certificate (setting version)");
	ssl_error_to_verror();
	goto error;
    }	
    
    /* Clear any extensions on certificate */
    if (proxy_certificate->cert_info->extensions != NULL)
    {
	sk_X509_EXTENSION_pop_free(proxy_certificate->cert_info->extensions,
				   X509_EXTENSION_free);
    }
 
    /*
     * This is were we would add any extensions
     */

#ifndef NO_DSA
    {
	EVP_PKEY *pktmp = NULL;
	
	/* DEE? not sure what this is doing, I think
	 * it is adding from the key to be used to sign to the 
	 * new certificate any info DSA may need
	 */
	pktmp = X509_get_pubkey(proxy_certificate);

	if (EVP_PKEY_missing_parameters(pktmp) &&
	    !EVP_PKEY_missing_parameters(creds->private_key))
	{
	    EVP_PKEY_copy_parameters(pktmp, creds->private_key);
	}
    }
#endif

    if (X509_sign(proxy_certificate, creds->private_key, EVP_md5()) == 0)
    {
	verror_put_string("Error generating proxy_certificate (signing certificate)");
	ssl_error_to_verror();
	goto error;
    }	
    
    /* Success */
    *p_proxy_cert = proxy_certificate;

    return_status = 0;
    
  error:
    if (proxy_name != NULL)
    {
	X509_NAME_free(proxy_name);
    }

    /* XXX Need to free serial_number? */

    if (return_status == -1)
    {
	if (proxy_certificate != NULL)
	{
	    X509_free(proxy_certificate);
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


int
ssl_proxy_request_init(SSL_CREDENTIALS		**new_creds,
		       unsigned char		**buffer,
		       int			*buffer_length,
		       int			requested_bits,
		       void			(*callback)(int,int,char *))
{
    SSL_CREDENTIALS		*creds = NULL;
    X509_REQ			*request = NULL;
    int				return_status = -1;

    
    ssl_init();
    
    assert(new_creds != NULL);
    assert(buffer != NULL);
    assert(buffer_length != NULL);

    /* Generate the request */
    if (ssl_generate_cert_request(&creds,
				  &request,
				  NULL /* no name */,
				  requested_bits,
				  callback) == -1)
    {
	goto error;
    }
    
    /* Request successfully generated, now dump to buffer */
    if (ssl_x509_request_to_buffer(request,
				   buffer,
				   buffer_length) == -1)
    {
	goto error;
    }

    /* START DEBUG */
    {
	X509_REQ	*tmp_request;
	
	if (ssl_x509_request_from_buffer(*buffer, *buffer_length,
					 &tmp_request) == -1)
	{
	    goto error;
	}
    }
    /* END DEBUG */

    /* Success */
    return_status = 0;

    *new_creds = creds;
    creds = NULL;

  error:
    if (request != NULL)
    {
	X509_REQ_free(request);
    }
    
    if (return_status == -1)
    {
	if (creds != NULL)
	{
	    ssl_destroy_credentials(creds);
	}
    }
    
    return return_status;
}


int
ssl_proxy_request_finalize(SSL_CREDENTIALS	*creds,
			   unsigned char	*buffer,
			   int			buffer_length)
{
    int return_status = -1;
    
    assert(creds != NULL);
    assert(buffer != NULL);
    
    if (ssl_proxy_cert_from_buffer(creds,
				   buffer,
				   buffer_length) == -1)
    {
	goto error;
    }
    
    /* Success */
    return_status = 0;
    
  error:
    return return_status;
}

int
ssl_proxy_request_sign(SSL_CREDENTIALS		*creds,
		       SSL_PROXY_RESTRICTIONS	*restrictions,
		       unsigned char		*request_buffer,
		       int			request_buffer_length,
		       unsigned char		**proxy_buffer,
		       int			*proxy_buffer_length)
{
    X509_REQ			*request = NULL;
    X509			*proxy_certificate = NULL;
    int				return_status = -1;
    
    assert(creds != NULL);
    assert(creds->certificate);
    assert(creds->private_key);
    assert(request_buffer != NULL);
    assert(proxy_buffer != NULL);
    assert(proxy_buffer_length != NULL);
    
    /* Get the request for the buffer */
    if (ssl_x509_request_from_buffer(request_buffer,
				     request_buffer_length,
				     &request) == -1)
    {
	goto error;
    }
    
    /* Verify request and make certificate */
    if (ssl_generate_proxy_certificate(creds,
				       request,
				       restrictions,
				       &proxy_certificate) == -1)
    {
	goto error;
    }

    /* Now dump certificate and cert chain to buffer */
    if (ssl_proxy_cert_to_buffer(creds,
				 proxy_certificate,
				 proxy_buffer,
				 proxy_buffer_length) == -1)
    {
	goto error;
    }
    
    /* Success */
    return_status = 0;

  error:
    if (request != NULL)
    {
	X509_REQ_free(request);
    }
    
    if (proxy_certificate != NULL)
    {
	X509_free(proxy_certificate);
    }
    
    return return_status;
}

    
      
	
	    
	    


 
