/*
 * ssl_utils.c
 *
 * Routines for interacting directly with SSL, X509 certificates, etc.
 */


#include "myproxy_common.h"	/* all needed headers included here */

#define PEM_CALLBACK(func)	func, NULL
#define PEM_NO_CALLBACK		NULL, NULL

/**********************************************************************
 *
 * Constants
 *
 */
#define PROXY_EXTENSION			"proxy"
#define LIMITED_PROXY_EXTENSION		"limited proxy"

#define PROXY_DEFAULT_LIFETIME		-1L /* magic # for lifetime */
                                            /*   of signing cert    */

/* Amount of clock skew to allow for when generating certificates */
#define PROXY_CLOCK_SKEW_ALLOWANCE	60 * 5 /* seconds */

#define PROXY_DEFAULT_VERSION		2L /* == v3 */

/* Return values for ssl_check_keys_match() */
#define SSL_KEYS_MATCH			1
#define SSL_KEYS_MISMATCH		-1

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
 * buffer_from_file()
 *
 * Read the entire contents of a file into a buffer.
 *
 * Returns SSL_SUCCESS or SSL_ERROR, setting verror.
 */
static int
buffer_from_file(const char			*path,
		 unsigned char			**pbuffer,
		 int				*pbuffer_len)
{
    int				fd = -1;
    int				open_flags;
    int				return_status = SSL_ERROR;
    struct stat			statbuf;
    unsigned char		*buffer = NULL;
    int				buffer_len;
    
    assert(path != NULL);
    assert(pbuffer != NULL);
    assert(pbuffer_len != NULL);
    
    open_flags = O_RDONLY;
    
    fd = open(path, open_flags);
    
    if (fd == -1)
    {
	verror_put_string("Failure opening file \"%s\"", path);
	verror_put_errno(errno);
	goto error;
    }
    
    if (fstat(fd, &statbuf) == -1)
    {
	verror_put_string("Failure stating file \"%s\"", path);
	verror_put_errno(errno);
	goto error;
    }

    buffer_len = statbuf.st_size;
    
    buffer = malloc(buffer_len);
    
    if (buffer == NULL)
    {
	verror_put_string("malloc() failed");
	verror_put_errno(errno);
	goto error;
    }
    
    if (read(fd, buffer, buffer_len) == -1)
    {
	verror_put_string("Error reading file \"%s\"", path);
	verror_put_errno(errno);
	goto error;
    }

    /* Succcess */
    *pbuffer = buffer;
    *pbuffer_len = buffer_len;
    return_status = SSL_SUCCESS;

  error:
    if (fd != -1)
    {
	close(fd);
    }
    
    if (return_status == SSL_ERROR)
    {
	if (buffer != NULL)
	{
	    free(buffer);
	}
    }
    
    return return_status;
}


/*
 * ssl_error_to_verror()
 *
 * Transfer an error description out of the ssl error handler to verror.
 */
void
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
 * bio_from_buffer()
 *
 * Given a buffer of length buffer_len, return a memory bio with the
 * contents of the buffer.
 *
 * Returns pointer to bio on success, NULL on error.
 */
static BIO *
bio_from_buffer(const unsigned char		*buffer,
		int				buffer_len)
{
    BIO			*bio = NULL;

    assert(buffer != NULL);
    
    bio = BIO_new(BIO_s_mem());

    if (bio == NULL)
    {
	verror_put_string("Failed creating memory BIO");
	ssl_error_to_verror();
	goto error;
    }

    if (BIO_write(bio, (unsigned char *) buffer, buffer_len) == SSL_ERROR)
    {
	verror_put_string("Failed writing buffer to BIO");
	ssl_error_to_verror();
	BIO_free(bio);
	bio = NULL;
	goto error;
    }

  error:
    return bio;
}


/*
 * bio_to_buffer()
 *
 * Given a bio return the contents of the bio in a buffer.
 * pbuffer is set to point to the allocated buffer, and pbuffer_len
 * is filled in with the buffer length. Caller should free *pbuffer.
 *
 * Returns SSL_SUCCESS or SSL_ERROR.
 */
static int
bio_to_buffer(BIO				*bio,
	      unsigned char			**pbuffer,
	      int				*pbuffer_len)
{
    char 		*buffer = NULL;
    int			buffer_len;
    int			return_status = SSL_ERROR;
    
    assert(bio != NULL);
    
    buffer_len = BIO_pending(bio);
    
    buffer = malloc(buffer_len);
    
    if (buffer == NULL)
    {
	verror_put_string("Failed dumping BIO to buffer (malloc() failed)");
	verror_put_errno(errno);
	goto error;
    }
    
    if (BIO_read(bio, buffer, buffer_len) == SSL_ERROR)
    {
	verror_put_string("Failed dumping BIO to buffer (BIO_read() failed)");
	ssl_error_to_verror();
	goto error;
    }

    /* Success */
    *pbuffer = buffer;
    *pbuffer_len = buffer_len;
    return_status = SSL_SUCCESS;
    
  error:
    if (return_status == SSL_ERROR)
    {
	if (buffer != NULL)
	{
	    free(buffer);
	}
    }
    
    return return_status;
}

 
/*
 * ssl_cert_chain_free()
 *
 * Free the given certificate chain and all it contents.
 */
static void
ssl_cert_chain_free(STACK			*cert_chain)
{
    if (cert_chain != NULL)
    {
	sk_pop_free(cert_chain, (void (*)(void *))X509_free);
    }
}

/*
 * ssl_credentials_free_contents()
 *
 * Free all the contents of the given credentials without freeing
 * the credentials structure itself.
 */
static void
ssl_credentials_free_contents(SSL_CREDENTIALS	*creds)
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
	    ssl_cert_chain_free(creds->certificate_chain);
	}
    }
}

static int
creds_from_bio(BIO *bio, SSL_CREDENTIALS **creds)
{
   STACK               *cert_chain = NULL;
   X509                *cert = NULL;
   unsigned char       number_of_certs;
   int                 cert_index;
   int                 return_status = SSL_ERROR;
 
   if (BIO_read(bio, &number_of_certs, sizeof(number_of_certs)) == SSL_ERROR) {
      verror_put_string("Failed unpacking chain from buffer"
                        "(reading number of certificates)");
      ssl_error_to_verror();
      return SSL_ERROR;
   }

   if (number_of_certs == 0) {
      verror_put_string("Failed unpacking chain from buffer"
                        "(number of certificates is zero)");
      ssl_error_to_verror();
      return SSL_ERROR;
   }

   cert = d2i_X509_bio(bio, NULL /* make new cert */);

   if (cert == NULL) {
      verror_put_string("Failed unpacking chain from buffer"
                        "(reading user's certificate)");
      ssl_error_to_verror();
      goto end;
   }

   /* Now read the certificate chain */
   cert_chain = sk_new_null();
   for (cert_index = 1; cert_index < number_of_certs; cert_index++) {
      X509  *x509;

      x509 = d2i_X509_bio(bio, NULL /* make new cert */);
      if (x509 == NULL) {
         verror_put_string("Failed unpacking chain from buffer"
                           "(reading certificate)");
         ssl_error_to_verror();
         goto end;
      }

      if (sk_push(cert_chain, (char *) x509) == SSL_ERROR) {
         verror_put_string("Failed unpacking chain from buffer"
                           "(building a new chain)");
         ssl_error_to_verror();
         X509_free(x509);
         goto end;
      }
   }

   *creds = ssl_credentials_new();
   if (*creds == NULL) {
       verror_put_string("Failed unpacking chain from buffer"
                         "(building a new chain)");
       goto end;
   }
   (*creds)->certificate_chain = cert_chain;
   cert_chain = NULL;
   (*creds)->certificate = cert;
   cert = NULL;

   return_status = SSL_SUCCESS;

end:
   if (cert)
      X509_free(cert);
   if (cert_chain)
      ssl_cert_chain_free(cert_chain);

   return return_status;
}

static int
creds_to_bio(SSL_CREDENTIALS *chain, BIO **bio)
{
    unsigned char number_of_certs;
    BIO  *output_bio = NULL;
    int index;
    int return_status = SSL_ERROR;

    output_bio = BIO_new(BIO_s_mem());
    if (output_bio == NULL) {
       verror_put_string("BIO_new() failed");
       ssl_error_to_verror();
       return SSL_ERROR;
    }

    number_of_certs = sk_num(chain->certificate_chain) + 1;

    if (BIO_write(output_bio, &number_of_certs,sizeof(number_of_certs)) == SSL_ERROR) {
       verror_put_string("Failed dumping chain to buffer"
                         "(BIO_write() failed)");
       ssl_error_to_verror();
       goto end;
    }

    if (i2d_X509_bio(output_bio, chain->certificate) == SSL_ERROR) {
       verror_put_string("Failed dumping chain to buffer "
                         "(write of user's certificate failed)");
       ssl_error_to_verror();
       goto end;
    }

    for (index = 0; index < sk_num(chain->certificate_chain); index++) {
       X509  *cert;

       cert = (X509 *) sk_value(chain->certificate_chain, index);
       if (i2d_X509_bio(output_bio, cert) == SSL_ERROR) {
          verror_put_string("Failed dumping chain to buffer "
                            "(write of cert chain failed)");
          ssl_error_to_verror();
          goto end;
       }
    }
    *bio = output_bio;
    output_bio = NULL;
    return_status = SSL_SUCCESS;
    
end:
    if (output_bio)
       BIO_free(output_bio);

    return return_status;
}

/*
 * ssl_proxy_generate_name()
 *
 * Given a certificate, and the restrictions associated with the
 * proxy we are generating return the name of the proxy certificate
 * that would be generated from the certificate. If no certificate
 * is supplied, a blank name is used.
 *
 * Returns name or NULL on error.
 */
static X509_NAME *
ssl_proxy_generate_name(X509				*certificate,
			SSL_PROXY_RESTRICTIONS		*restrictions)
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
			    X509_NAME_entry_count(name),
			    0 /* new set */) == SSL_ERROR)
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
 * my_init()
 *
 * Do any needed initialization for these routines.
 * Should be called first. Can be called multiple times.
 */
static void
my_init()
{
    static int my_inited = 0;
    
    if (my_inited == 0)
    {
	my_inited = 1;

	/* Initialize the ssleay libraries */

	SSL_load_error_strings();

	SSLeay_add_ssl_algorithms();
    }
}

	
/*
 * my_pass_phrase_callback()
 *
 * Callback from PEM_read_PrivateKey() in ssl_load_user_key()
 * to return the passphrase stored in _ssl_pass_phrase.
 */
static int
my_pass_phrase_callback(char			*buffer,
			 int			buffer_len,
			 int			verify /* Ignored */,
			void                    *u)
{
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
 * ssl_keys_check_match()
 *
 * Check to make sure a private and public key go together.
 * Currently only checks RSA keys.
 *
 * Returns SSL_KEYS_MATCH, SSL_KEYS_MISMATCH or SSL_ERROR.
 */
static int
ssl_keys_check_match(X509			*certificate,
		     EVP_PKEY			*private_key)
{
    int					return_status = SSL_ERROR;
    EVP_PKEY				*public_key;
    
    assert(certificate != NULL);
    assert(private_key != NULL);
    
    public_key = X509_PUBKEY_get(X509_get_X509_PUBKEY(certificate));
    
    if (public_key == NULL)
    {
	verror_put_string("Could not certificate key");
	goto error;
    }

    if (EVP_MD_type(public_key) != EVP_MD_type(private_key))
    {
	verror_put_string("Keys types do not match");
	return_status = SSL_KEYS_MISMATCH;
	goto error;
    }
    
    switch (EVP_MD_type(public_key))
    {
      case EVP_PKEY_RSA:
	{
	    RSA			*private_rsa;
	    RSA			*public_rsa;

	    private_rsa = private_key->pkey.rsa;
	    public_rsa = public_key->pkey.rsa;
	    
	    if ((public_rsa == NULL) ||
		(public_rsa->n == NULL))
	    {
		verror_put_string("Public key malformed");
		goto error;
	    }
	
	    if ((private_rsa == NULL) ||
		(private_rsa->n == NULL))
	    {
		verror_put_string("Private key malformed");
		goto error;
	    }
	
	    if (BN_cmp(public_rsa->n, private_rsa->n) == 1)
	    {
		return_status = SSL_KEYS_MISMATCH;
	    }
	    else
	    {
		return_status = SSL_KEYS_MATCH;
	    }
	}
	
	break;
	
      default:
	verror_put_string("Unrecognized key type");
	goto error;
    }

  error:
    return return_status;
}

    


/*
 * ssl_x509_request_to_buffer()
 *
 * Dump the given X509 request structure to an allocated buffer.
 *
 * Returns SSL_SUCCESS or SSL_ERROR
 */
static int
ssl_x509_request_to_buffer(X509_REQ		*request,
			   unsigned char	**buffer,
			   int			*buffer_length)
{
    int				return_status = SSL_ERROR;
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

    
    if (i2d_X509_REQ_bio(bio, request) == SSL_ERROR)
    {
	verror_put_string("Failed dumping X509 request to buffer");
	ssl_error_to_verror();
	goto error;
    }
    
    if (bio_to_buffer(bio, buffer, buffer_length) == SSL_ERROR)
    {
	goto error;
    }
        
    /* Success */
    return_status = SSL_SUCCESS;
    
  error:
    if (bio != NULL)
    {
	BIO_free(bio);
    }
    
    return return_status;
}


/*
 * ssl_x509_request_from_buffer()
 *
 * Parse a buffer as generated by ssl_x509_request_to_buffer() and
 * return the X509_REQ object.
 *
 * Returns SSL_SUCCESS or SSL_ERROR.
 */
static int
ssl_x509_request_from_buffer(unsigned char	*buffer,
			     int		buffer_length,
			     X509_REQ		**p_request)
{
    X509_REQ			*request = NULL;
    BIO				*bio = NULL;
    int				return_status = SSL_ERROR;
    
    assert(buffer != NULL);
    assert(p_request != NULL);
    
    bio = bio_from_buffer(buffer, buffer_length);
    
    if (bio == NULL)
    {
	verror_put_string("Failed unpacking X509 request from buffer");
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
    return_status = SSL_SUCCESS;

  error:
    if (bio)
    {
	BIO_free(bio);
    }
    
    if (return_status == SSL_ERROR)
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
 * Returns SSL_SUCCESS or SSL_ERROR.
 */
static int
ssl_x509_request_verify(X509_REQ		*request)
{
    int				return_status = SSL_ERROR;
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
    return_status = SSL_SUCCESS;
    
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
 * ssl_x509_request_generate()
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
 * Returns SSL_ERROR or SSL_SUCCESS
 */
static int
ssl_x509_request_generate(SSL_CREDENTIALS	**p_creds,
			  X509_REQ		**p_request,
			  X509_NAME		*requested_name,
			  int			requested_bits,
			  void			 (*callback)(int,int,void *))
{
    const int			default_key_size = 512;	/* bits */
    SSL_CREDENTIALS		*creds = NULL;
    X509_NAME			*name = NULL;
    int				return_status = SSL_ERROR;
    EVP_PKEY			*key = NULL;
    RSA				*rsa = NULL;
    X509_REQ			*request = NULL;
    
    assert(p_creds != NULL);
    assert(p_request != NULL);
 
    /* Make new credentials structure to hold new certificate */
    creds = ssl_credentials_new();
    
    if (creds == NULL)
    {
	goto error;
    }
    
    /* How many bits do we want the new key to be? */
    if (requested_bits == 0)
    {
	requested_bits = default_key_size;
    }

    /* XXX DK: feed RAND_seed() with enough data */
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
    if (X509_REQ_set_version(request, 0L) == SSL_ERROR)
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
				0 /* create new set */) == SSL_ERROR)
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

    if (X509_REQ_set_subject_name(request, name) == SSL_ERROR)
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
    
    if (EVP_PKEY_assign_RSA(key, rsa) == SSL_ERROR)
    {
	verror_put_string("Error generating proxy request (assigning RSA key)");
	ssl_error_to_verror();
	goto error;
    }

    if (X509_REQ_set_pubkey(request, key) == SSL_ERROR)
    {
	verror_put_string("Error generating new proxy request (setting public key)");
	ssl_error_to_verror();
	goto error;
    }

    if (X509_REQ_sign(request, key, EVP_md5()) == SSL_ERROR)
    {
	verror_put_string("Error generating new proxy request (signing request)");
	ssl_error_to_verror();
	goto error;
    }
    
    /* Success */
    creds->private_key = key;

    *p_creds = creds;
    creds = NULL;
    
    *p_request = request;
    request = NULL;

    return_status = SSL_SUCCESS;
    

  error:
    if (name != NULL)
    {
	X509_NAME_free(name);
    }

    if (return_status == SSL_ERROR)
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
	    ssl_credentials_destroy(creds);
	}
    }
    
    return return_status;
}


/*
 * ssl_proxy_request_sign()
 *
 * Given the credentials and a certificate request, generate a proxy
 * certificate. ssl_x509_request_verify() is used to check the request.
 *
 * restrictions, if non-NULL, will be applied.
 *
 * Returns SSL_SUCCESS or SSL_ERROR
 */
static int
ssl_proxy_request_sign(SSL_CREDENTIALS		*creds,
		       X509_REQ			*request,
		       SSL_PROXY_RESTRICTIONS	*restrictions,
		       X509			**p_proxy_cert)
{
    long			lifetime = PROXY_DEFAULT_LIFETIME;
    X509_NAME			*proxy_name = NULL;
    X509			*proxy_certificate = NULL;
    ASN1_INTEGER		*serial_number = NULL;
    EVP_PKEY                    *request_public_key = NULL;
    int				return_status = SSL_ERROR;
    
    assert(creds != NULL);
    assert(request != NULL);
    assert(p_proxy_cert != NULL);
    
    if (ssl_x509_request_verify(request) == SSL_ERROR)
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
    proxy_name = ssl_proxy_generate_name(creds->certificate, restrictions);
    
    if (proxy_name == NULL)
    {
	goto error;
    }

    if (X509_set_subject_name(proxy_certificate, proxy_name) == SSL_ERROR)
    {
	verror_put_string("Error generating proxy_certificate (error setting name)");
	ssl_error_to_verror();
	goto error;
    }
    
    if (X509_set_issuer_name(proxy_certificate,
			     X509_get_subject_name(creds->certificate)) == SSL_ERROR)
    {
	verror_put_string("Error generating proxy_certificate (error setting issuer name)");
	ssl_error_to_verror();
	goto error;
    }

    /* Assign proxy same serial number as user certificate */
    serial_number = X509_get_serialNumber(creds->certificate);
    
    if (X509_set_serialNumber(proxy_certificate, serial_number) == SSL_ERROR)
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
    request_public_key = X509_REQ_get_pubkey(request);
    if (X509_set_pubkey(proxy_certificate, request_public_key) == SSL_ERROR)
    {
	verror_put_string("Error generating proxy_certificate (setting public key)");
	ssl_error_to_verror();
	goto error;
    }	

    /* Set the certificate version */
    if (X509_set_version(proxy_certificate, PROXY_DEFAULT_VERSION) == SSL_ERROR)
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

    if (X509_sign(proxy_certificate,
		  creds->private_key,
		  EVP_md5()) == SSL_ERROR)
    {
	verror_put_string("Error generating proxy_certificate (signing certificate)");
	ssl_error_to_verror();
	goto error;
    }	
    
    /* Success */
    *p_proxy_cert = proxy_certificate;

    return_status = SSL_SUCCESS;
    
  error:
    if (proxy_name != NULL)
    {
	X509_NAME_free(proxy_name);
    }

    /* XXX Need to free serial_number? */

    if (return_status == SSL_ERROR)
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
ssl_credentials_destroy(SSL_CREDENTIALS		*creds)
{
    my_init();
    
    if (creds != NULL)
    {
	ssl_credentials_free_contents(creds);
	
	free(creds);
    }
}


int
ssl_proxy_file_destroy(const char *proxyfile)
{
    FILE *fp;
    long offset, i;
    char zero = '\0';
    
    assert(proxyfile != NULL);

    fp = fopen(proxyfile, "r+");
    if (!fp) {
	verror_put_string("fopen: %s\n", strerror(errno));
	return SSL_ERROR;
    }
    if (fseek(fp, 0L, SEEK_END) < 0) {
	verror_put_string("fseek: %s\n", strerror(errno));
	fclose(fp);
	return SSL_ERROR;
    }
    offset = ftell(fp);
    if (offset < 0) {
	verror_put_string("ftell: %s\n", strerror(errno));
	fclose(fp);
	return SSL_ERROR;
    }
    if (fseek(fp, 0L, SEEK_SET) < 0) {
	verror_put_string("fseek: %s\n", strerror(errno));
	fclose(fp);
	return SSL_ERROR;
    }
    for (i=0; i < offset; i++) {
	if (fwrite(&zero, 1, 1, fp) != 1) {
	    verror_put_string("fwrite: %s\n", strerror(errno));
	    fclose(fp);
	    return SSL_ERROR;
	}
    }
    fclose(fp);
    if (unlink(proxyfile) < 0) {
	verror_put_string("unlink: %s\n", strerror(errno));
	return SSL_ERROR;
    }

    return SSL_SUCCESS;
}	
		     
		     
int
ssl_certificate_load_from_file(SSL_CREDENTIALS	*creds,
			       const char	*path)
{
    FILE		*cert_file = NULL;
    X509		*cert = NULL;
    int			return_status = SSL_ERROR;
    STACK		*cert_chain = NULL;
    
    assert(creds != NULL);
    assert(path != NULL);

    my_init();
    
    cert_file = fopen(path, "r");
    
    if (cert_file == NULL) 
    {
	verror_put_string("Error opening certificate file %s", path);
	verror_put_errno(errno);
	goto error;
    }
    
    if (PEM_read_X509(cert_file, &cert, PEM_NO_CALLBACK) == NULL)
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

    /* Ok, now read the certificate chain */

    /* Create empty stack */
    cert_chain = sk_new_null();
    
    while (1)
    {
	cert = NULL;
	
	if (PEM_read_X509(cert_file, &cert, PEM_NO_CALLBACK) == NULL)
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
	    verror_put_string("Error parsing certificate chain");
	    ssl_error_to_verror();
	    goto error;
	}

	/* Add to chain */
	if (sk_insert(cert_chain, (char *) cert,
		      sk_num(cert_chain)) == SSL_ERROR)
	{
	    verror_put_string("Error parsing certificate chain");
	    ssl_error_to_verror();
	    goto error;
	}
    } /* while(1) */

    creds->certificate_chain = cert_chain;
    
    /* Success */
    return_status = SSL_SUCCESS;
    
  error:
    if (cert_file != NULL) 
    {
	fclose(cert_file);
    }
    
    return return_status;
}

int
ssl_private_key_load_from_file(SSL_CREDENTIALS	*creds,
			       const char	*path,
			       const char	*pass_phrase,
			       const char	*pass_phrase_prompt)
{
    FILE		*key_file = NULL;
    EVP_PKEY		*key = NULL;
    int			return_status = SSL_ERROR;
    
    assert(creds != NULL);
    assert(path != NULL);
    
    my_init();
    
    /* 
     * Put pass phrase where the callback function can find it.
     */
    _ssl_pass_phrase = pass_phrase;

    if (pass_phrase_prompt) EVP_set_pw_prompt((char *)pass_phrase_prompt);

    key_file = fopen(path, "r");
    
    if (key_file == NULL)
    {
	verror_put_string("Error opening certificate file %s", path);
	verror_put_errno(errno);
	goto error;
    }

    if (PEM_read_PrivateKey(key_file, &(key), (pass_phrase_prompt) ? 
			    my_pass_phrase_callback : NULL, NULL) == NULL)
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
    return_status = SSL_SUCCESS;

  error:
    if (key_file != NULL)
    {
	fclose(key_file);
    }
    
    return return_status;
}

int
ssl_proxy_from_pem(SSL_CREDENTIALS		*creds,
		   const unsigned char		*buffer,
		   int				buffer_len,
		   const char			*pass_phrase)
{
    BIO			*bio = NULL;
    X509		*cert = NULL;
    EVP_PKEY		*key = NULL;
    STACK		*cert_chain = NULL;
    int			return_status = SSL_ERROR;

    assert(creds != NULL);
    assert(buffer != NULL);

    my_init();
    
    /* 
     * Put pass phrase where the callback function can find it.
     */
    _ssl_pass_phrase = pass_phrase;

    bio = bio_from_buffer(buffer, buffer_len);

    if (bio == NULL)
    {
	goto error;
    }

    /*
     * Proxy file contains proxy certificate followed by proxy
     * private key, followed by the certificate chain.
     */

    /* Read proxy certificate */
    if (PEM_read_bio_X509(bio, &cert, PEM_NO_CALLBACK) == NULL)
    {
	verror_put_string("Error parsing proxy certificate");
	ssl_error_to_verror();
	goto error;
    }

    /* Read proxy private key */
    if (PEM_read_bio_PrivateKey(bio, &(key),
				PEM_CALLBACK(my_pass_phrase_callback)) == NULL)
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
	    verror_put_string("Error parsing private key");
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
	
	if (PEM_read_bio_X509(bio, &certificate,
			      PEM_NO_CALLBACK) == NULL)
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
	    verror_put_string("Error parsing certificate chain from proxy");
	    ssl_error_to_verror();
	    goto error;
	}

	/* Add to chain */
	if (sk_insert(cert_chain, (char *) certificate,
		      sk_num(cert_chain)) == SSL_ERROR)
	{
	    verror_put_string("Error parsing certificate chain from proxy");
	    ssl_error_to_verror();
	    goto error;
	}
    } /* while(1) */

    /*
     * Ok, everything has been successfully read, now store it into
     * creds, removing any existing contents.
     */
    ssl_credentials_free_contents(creds);
    
    creds->private_key = key;
    creds->certificate = cert;
    creds->certificate_chain = cert_chain;
    
    /* Success */
    return_status = SSL_SUCCESS;
    
  error:
    if (return_status == SSL_ERROR)
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
	    ssl_cert_chain_free(cert_chain);
	}
    }

    if (bio != NULL)
    {
	BIO_free(bio);
    }
    
    return return_status;
}

    
int
ssl_proxy_load_from_file(SSL_CREDENTIALS	*creds,
			 const char		*path,
			 const char		*pass_phrase)
{
    unsigned char	*buffer = NULL;
    int			buffer_len;
    int			return_status = SSL_ERROR;
    
    assert(creds != NULL);
    assert(path != NULL);

    my_init();

    /* Read the whole contents of the given file */
    if (buffer_from_file(path, &buffer, &buffer_len) == SSL_ERROR)
    {
	goto error;
    }
    
    if (ssl_proxy_from_pem(creds, buffer, buffer_len, pass_phrase) == SSL_ERROR)
    {
	verror_prepend_string("Error reading proxy from %s", path);
	goto error;
    }
    
    /* Success */
    return_status = SSL_SUCCESS;
    
  error:
    if (buffer != NULL)
    {
	free(buffer);
    }

    return return_status;
}


int
ssl_proxy_to_pem(SSL_CREDENTIALS		*creds,
		 unsigned char			**pbuffer,
		 int				*pbuffer_len,
		 const char			*pass_phrase)
{
    BIO				*bio = NULL;
    EVP_CIPHER			*cipher;
    int				pass_phrase_len;
    int				cert_chain_index;
    int				return_status = SSL_ERROR;
    
    assert(creds != NULL);
    assert(pbuffer != NULL);
    assert(pbuffer_len != NULL);

    my_init();

    bio = BIO_new(BIO_s_mem());

    if (bio == NULL)
    {
	verror_put_string("Failed creating memory BIO");
	ssl_error_to_verror();
	goto error;
    }

    /*
     * Write out proxy certificate, followed by proxy private key and
     * then followed by the cert chain.
     */
    if (creds->certificate == NULL)
    {
	verror_put_string("Malformed proxy credentials (No certificate)");
	goto error;
    }
    
    if (PEM_write_bio_X509(bio, creds->certificate) == SSL_ERROR)
    {
	verror_put_string("Error packing proxy certificate");
	ssl_error_to_verror();
	goto error;
    }

    if (creds->private_key == NULL)
    {
	verror_put_string("Malformed proxy credentials (No private key)");
	goto error;
    }
    
    if (pass_phrase == NULL)
    {
	/* No encryption */
	cipher = NULL;
	pass_phrase_len = 0;
    }
    else
    {
	/* Encrypt with pass phrase */
	/* XXX This is my best guess at a cipher */
	cipher = EVP_des_ede3_cbc();
	pass_phrase_len = strlen(pass_phrase);
    }

    if (PEM_write_bio_PrivateKey(bio, creds->private_key, cipher,
				 (char *) pass_phrase, pass_phrase_len,
				 PEM_NO_CALLBACK) == SSL_ERROR)
    {
	verror_put_string("Error packing private key");
	ssl_error_to_verror();
	goto error;
    }
    
    if (creds->certificate_chain != NULL)
    {
	
	for (cert_chain_index = 0;
	     cert_chain_index < sk_num(creds->certificate_chain);
	     cert_chain_index++)
	{
	    X509				*cert;
	
	    cert = (X509 *) sk_value(creds->certificate_chain,
				     cert_chain_index);
	
	    if (PEM_write_bio_X509(bio, cert) == SSL_ERROR)
	    {
		verror_put_string("Error packing certificate chain");
		ssl_error_to_verror();
		goto error;
	    }
	}
    }
    
    /* OK, bio is filled, now dump to buffer */
    if (bio_to_buffer(bio, pbuffer, pbuffer_len) == SSL_ERROR)
    {
	goto error;
    }
    
    /* Success */
    return_status = SSL_SUCCESS;
    
  error:
    if (bio != NULL)
    {
	BIO_free(bio);
    }

    return return_status;
}
    
    
    
int
ssl_proxy_store_to_file(SSL_CREDENTIALS		*proxy_creds,
			const char		*path,
			const char		*pass_phrase)
{
    int				fd = -1;
    int				open_flags;
    int				return_status = SSL_ERROR;
    unsigned char		*buffer = NULL;
    int				buffer_len;
    mode_t			file_mode = 0;
    
    assert(proxy_creds != NULL);
    assert(path != NULL);
    
    my_init();
    
    /*
     * Use open to open the file so we can make sure it doesn't already
     * exist.
     */
    open_flags = O_CREAT | O_EXCL | O_WRONLY;
    
    fd = open(path, open_flags);
    
    if (fd == -1)
    {
	verror_put_string("Error creating %s", path);
	verror_put_errno(errno);
	goto error;
    }

    /* Set file permissions */
    file_mode = S_IRUSR | S_IWUSR;	/* 600 */

    if (fchmod(fd, file_mode) == -1)
    {
	verror_put_string("Error setting permissions on %s", path);
	verror_put_errno(errno);
	goto error;
    }
    
    /*
     * Dump proxy to buffer
     */
    if (ssl_proxy_to_pem(proxy_creds, &buffer,
			 &buffer_len, pass_phrase) == SSL_ERROR)
    {
	goto error;
    }
    
    if (write(fd, buffer, buffer_len) == -1)
    {
	verror_put_errno(errno);
	verror_put_string("Error writing proxy to %s", path);
	goto error;
    }
    
    /* Success */
    return_status = SSL_SUCCESS;

  error:
    if (buffer != NULL)
    {
	free(buffer);
    }

    if (fd != -1)
    {
	close(fd);

	if (return_status == SSL_ERROR)
	{
	    /* Remove any file we created */
	    ssl_proxy_file_destroy(path);
	}
    }

    return return_status;
}

    
SSL_CREDENTIALS *
ssl_credentials_new()
{
    SSL_CREDENTIALS *creds = NULL;

    my_init();
    
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
ssl_proxy_delegation_init(SSL_CREDENTIALS	**new_creds,
			  unsigned char		**buffer,
			  int			*buffer_length,
			  int			requested_bits,
			  void			(*callback)(int,int,void *))
{
    SSL_CREDENTIALS		*creds = NULL;
    X509_REQ			*request = NULL;
    int				return_status = SSL_ERROR;

    
    my_init();
    
    assert(new_creds != NULL);
    assert(buffer != NULL);
    assert(buffer_length != NULL);

    /* Generate the request */
    if (ssl_x509_request_generate(&creds,
				  &request,
				  NULL /* no name */,
				  requested_bits,
				  callback) == SSL_ERROR)
    {
	goto error;
    }
    
    /* Request successfully generated, now dump to buffer */
    if (ssl_x509_request_to_buffer(request,
				   buffer,
				   buffer_length) == SSL_ERROR)
    {
	goto error;
    }

    /* Success */
    return_status = SSL_SUCCESS;

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
	    ssl_credentials_destroy(creds);
	}
    }
    
    return return_status;
}


int
ssl_proxy_delegation_finalize(SSL_CREDENTIALS	*creds,
			      unsigned char	*buffer,
			      int		buffer_length)
{
    BIO				*bio = NULL;
    int				return_status = SSL_ERROR;
    unsigned char		number_of_certs;
    X509			*proxy_cert = NULL;
    int				cert_index = 0;
    STACK			*cert_chain = NULL;

    assert(creds != NULL);
    assert(buffer != NULL);
    
    /* Transfer the buffer to a bio */
    bio = bio_from_buffer(buffer, buffer_length);

    if (bio == NULL)
    {
	verror_put_string("Failed unpacking proxy certificate from buffer");
	goto error;
    }

    /*
     * Buffer contains:
     *		-a bytes containing the number of certificates.
     *          -the proxy certificate
     *          -the certificate chain
     */

    /* Read number of certificates */
    if (BIO_read(bio, &number_of_certs, sizeof(number_of_certs)) == SSL_ERROR)
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

    /* Now read the proxy certificate */
    proxy_cert = d2i_X509_bio(bio, NULL /* make new cert */);
    
    if (proxy_cert == NULL)
    {
	verror_put_string("Failed unpacking proxy certificate from buffer (reading proxy certificate)");
	ssl_error_to_verror();
	goto error;
    }	

    /*
     * Check to make sure new proxy certificate matches private key we
     * generated earlier.
     */
    switch(ssl_keys_check_match(proxy_cert, creds->private_key))
    {
      case SSL_KEYS_MATCH:
	break;
	
      case SSL_KEYS_MISMATCH:
	verror_put_string("Proxy certificate does not match private key");
	goto error;
	
      default:
	goto error;
    }
    
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

	if (sk_push(cert_chain, (char *) cert) == SSL_ERROR)
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

    return_status = SSL_SUCCESS;
    
  error:
    if (bio != NULL)
    {
	BIO_free(bio);
    }
    
    if (return_status == SSL_ERROR)
    {
	if (proxy_cert != NULL)
	{
	    X509_free(proxy_cert);
	}
	
	if (cert_chain != NULL)
	{
	    ssl_cert_chain_free(cert_chain);
	}
    }

    return return_status;
}

int
ssl_proxy_delegation_sign(SSL_CREDENTIALS		*creds,
			  SSL_PROXY_RESTRICTIONS	*restrictions,
			  unsigned char			*input_buffer,
			  int				input_buffer_length,
			  unsigned char			**output_buffer,
			  int				*output_buffer_length)
{
    X509_REQ			*request = NULL;
    X509			*proxy_certificate = NULL;
    int				return_status = SSL_ERROR;
    BIO				*bio = NULL;
    unsigned char		number_of_certs;
    int				index;
    
    assert(creds != NULL);
    assert(creds->certificate);
    assert(creds->private_key);
    assert(input_buffer != NULL);
    assert(output_buffer != NULL);
    assert(output_buffer_length != NULL);

    my_init();
    
    /* Get the request for the buffer */
    if (ssl_x509_request_from_buffer(input_buffer,
				     input_buffer_length,
				     &request) == SSL_ERROR)
    {
	goto error;
    }
    
    /* Verify request and make certificate */
    if (ssl_proxy_request_sign(creds,
			       request,
			       restrictions,
			       &proxy_certificate) == SSL_ERROR)
    {
	goto error;
    }

    /* Now dump certificate and cert chain to buffer */
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

    if (BIO_write(bio, &number_of_certs, sizeof(number_of_certs)) == SSL_ERROR)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (BIO_write() failed)");
	ssl_error_to_verror();
	goto error;
    }

    /*
     * Now write out proxy certificate, followed by the signing certificate
     * and then the signing certificate's chain.
     */
    if (i2d_X509_bio(bio, proxy_certificate) == SSL_ERROR)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (write of proxy cert failed)");
	ssl_error_to_verror();
	goto error;
    }

    if (i2d_X509_bio(bio, creds->certificate) == SSL_ERROR)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (write of signing cert failed)");
	ssl_error_to_verror();
	goto error;
    }

    for (index = 0; index < sk_num(creds->certificate_chain); index++)
    {
	X509		*cert;
	
	cert = (X509 *) sk_value(creds->certificate_chain, index);
	
	if (i2d_X509_bio(bio, cert) == SSL_ERROR)
	{
	    verror_put_string("Failed dumping proxy certificate to buffer (write of cert chain failed)");
	    ssl_error_to_verror();
	    goto error;
	}
    }

    /* Now dump bio's contents to buffer */
    if (bio_to_buffer(bio, output_buffer, output_buffer_length) == SSL_ERROR)
    {
	goto error;
    }
         
    /* Success */
    return_status = SSL_SUCCESS;

  error:
    if (bio != NULL)
    {
	BIO_free(bio);
    }
    
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


void
ssl_free_buffer(unsigned char *buffer)
{
    if (buffer != NULL)
    {
	free(buffer);
    }
}


SSL_PROXY_RESTRICTIONS *
ssl_proxy_restrictions_new()
{
    SSL_PROXY_RESTRICTIONS		*restrictions = NULL;
    
    restrictions = malloc(sizeof(SSL_PROXY_RESTRICTIONS));

    if (restrictions == NULL)
    {
	verror_put_string("malloc() failed");
	verror_put_errno(errno);
	return NULL;
    }
    
    /* Set defaults */
    restrictions->limited_proxy = 0;	/* Not limited */
    restrictions->lifetime = 0;		/* 0 == default */
    
    return restrictions;
}

void
ssl_proxy_restrictions_destroy(SSL_PROXY_RESTRICTIONS *restrictions)
{
    if (restrictions != NULL)
    {
	free(restrictions);
    }
}

int
ssl_proxy_restrictions_set_lifetime(SSL_PROXY_RESTRICTIONS	*restrictions,
				    const long			lifetime)
{
    int				return_value = SSL_ERROR;
    
    /* Check arguments */
    if (restrictions == NULL)
    {
	verror_put_errno(EINVAL);
	goto error;
    }
    
    if (lifetime < 0L)
    {
	verror_put_errno(EINVAL);
	goto error;
    }
    
    /* OK */
    restrictions->lifetime = lifetime;
    return_value = SSL_SUCCESS;
    
  error:
    return return_value;
}

int
ssl_get_base_subject_file(const char *proxyfile, char **subject)
{
   SSL_CREDENTIALS	*creds = NULL;
   int			return_value = SSL_ERROR;
   char			path[MAXPATHLEN];

   if (proxyfile == NULL) {
      char *user_cert = NULL;
      
      GLOBUS_GSI_SYSCONFIG_GET_USER_CERT_FILENAME(&user_cert,
						  GLOBUS_PROXY_FILE_INPUT);
      strncpy(path, user_cert, sizeof(path));
      free(user_cert);
   } else {
      strncpy(path, proxyfile, sizeof(path));
   }

   creds = ssl_credentials_new();

   if (ssl_certificate_load_from_file(creds, path) != SSL_SUCCESS)
       goto error;

   if (ssl_get_base_subject(creds, subject) != SSL_SUCCESS)
       goto error;

   return_value = SSL_SUCCESS;

   error:
   if (creds) ssl_credentials_destroy(creds);
   return return_value;
}

int
ssl_get_base_subject(SSL_CREDENTIALS *creds, char **subject)
{
   char       client[1024];
   X509_NAME  *client_subject = NULL;
    
   client_subject = X509_NAME_dup(X509_get_subject_name(creds->certificate));
   if (client_subject == NULL) {
      return SSL_ERROR;
   }

#if defined(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY) /* gotta love API changes */
   globus_gsi_cert_utils_get_base_name(client_subject,
				       creds->certificate_chain);
#else   
   globus_gsi_cert_utils_get_base_name(client_subject);
#endif

   X509_NAME_oneline(client_subject, client, sizeof(client));
   *subject = strdup(client);
   X509_NAME_free(client_subject);

   return SSL_SUCCESS;
}

int
ssl_creds_to_buffer(SSL_CREDENTIALS *creds, unsigned char **buffer,
                    int *buffer_length)
{
   BIO  *bio = NULL;

   if (creds_to_bio(creds, &bio) == SSL_ERROR)
       return SSL_ERROR;

   if (bio_to_buffer(bio, buffer, buffer_length) == SSL_ERROR) {
       BIO_free(bio);
       return SSL_ERROR;
   }

   BIO_free(bio);

   return SSL_SUCCESS;
}

int
ssl_creds_from_buffer(unsigned char *buffer, int buffer_length,
                      SSL_CREDENTIALS **creds)
{
   BIO  *bio = NULL;

   bio = bio_from_buffer(buffer, buffer_length);
   if (bio == NULL)
      return SSL_ERROR;

   if (creds_from_bio(bio, creds) == SSL_ERROR) {
      BIO_free(bio);
      return SSL_ERROR;
   }

   BIO_free(bio);
   return SSL_SUCCESS;
}

int
ssl_sign(unsigned char *data, int length,
         SSL_CREDENTIALS *creds,
	 unsigned char **signature, int *signature_len)
{
   EVP_MD_CTX ctx;

   *signature = malloc(EVP_PKEY_size(creds->private_key));
   if (*signature == NULL) {
      verror_put_string("malloc()");
      verror_put_errno(errno);
      return SSL_ERROR;
   }

   EVP_SignInit(&ctx, EVP_sha1());
   EVP_SignUpdate(&ctx, (void *)data, length);
   if (EVP_SignFinal(&ctx, *signature, signature_len, creds->private_key) != 1) {
      verror_put_string("Creating signature (EVP_SignFinal())");
      ssl_error_to_verror();
      free(*signature);
      return SSL_ERROR;
   }

   return SSL_SUCCESS;
}

int
ssl_verify(unsigned char *data, int length,
           SSL_CREDENTIALS *creds,
	   unsigned char *signature, int signature_len)
{
   EVP_MD_CTX ctx;

   EVP_VerifyInit(&ctx, EVP_sha1());
   EVP_VerifyUpdate(&ctx, (void*) data, length);
   if (EVP_VerifyFinal(&ctx, signature, signature_len,
	              X509_get_pubkey(creds->certificate)) != 1 ) {
      verror_put_string("Verifying signature (EVP_VerifyFinal())");
      ssl_error_to_verror();
      return SSL_ERROR;
   }

   return SSL_SUCCESS;
}

/* Chain verifying is inspired by proxy_verify_chain() from GSI. */
int
ssl_verify_gsi_chain(SSL_CREDENTIALS *chain)
{
   int                   return_status = SSL_ERROR;
   int                   i,j;
   char                  *certdir = NULL;
   X509                  *xcert = NULL;
   X509_LOOKUP           *lookup = NULL;
   X509_STORE            *cert_store = NULL;
   X509_STORE_CTX        csc;
   SSL                   *ssl;
   SSL_CTX               *sslContext = NULL;

   memset(&csc, 0, sizeof(csc));
   cert_store=X509_STORE_new();
   if (chain->certificate_chain != NULL) {
      for (i = 0; i < sk_X509_num(chain->certificate_chain); i++) {
	 xcert = sk_X509_value(chain->certificate_chain, i);
	 j = X509_STORE_add_cert(cert_store, xcert);
	 if (!j) {
	    if ((ERR_GET_REASON(ERR_peek_error()) == 
		                       X509_R_CERT_ALREADY_IN_HASH_TABLE)) {
	       ERR_clear_error();
	       break;
	    }
	    else {
	       verror_put_string("X509_STORE_add_cert()");
	       ssl_error_to_verror();
	       goto end;
	    }
	 }
      }
   }
   lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_hash_dir());
   if (lookup == NULL) {
      verror_put_string("X509_STORE_add_lookup()");
      ssl_error_to_verror();
      goto end;
   }

   GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&certdir);
   if (certdir == NULL) {
      verror_put_string("failed to find GSI CA cert directory");
      ssl_error_to_verror();
      goto end;
   }
   X509_LOOKUP_add_dir(lookup, certdir, X509_FILETYPE_PEM);
   X509_STORE_CTX_init(&csc, cert_store, chain->certificate, NULL);
   
   sslContext = SSL_CTX_new(SSLv3_server_method());
   if (sslContext == NULL) {
      verror_put_string("Initializing SSL_CTX");
      ssl_error_to_verror();
      goto end;
   }

   SSL_CTX_set_purpose(sslContext, X509_PURPOSE_ANY);

   ssl = SSL_new(sslContext);
   if (ssl == NULL) {
      verror_put_string("Initializing SSL");
      ssl_error_to_verror();
      goto end;
   }

   /* override the check_issued with our version */
   csc.check_issued = globus_gsi_callback_check_issued;

   X509_STORE_CTX_set_app_data(&csc, (void*)ssl);

   if(!X509_verify_cert(&csc)) {
      verror_put_string("X509_verify_cert() failed");
      ssl_error_to_verror();
      goto end;
   }

   return_status = SSL_SUCCESS;

end:
   X509_STORE_CTX_cleanup(&csc);
   if (ssl)
      SSL_free(ssl);
   if (sslContext)
      SSL_CTX_free(sslContext);
   if (certdir)
      free(certdir);
   if (cert_store)
      X509_STORE_free(cert_store);

   return return_status;
}



int
ssl_get_times(const char *path, time_t *not_before, time_t *not_after)
{
   FILE         *cert_file = NULL;
   X509         *cert = NULL;

   assert(path != NULL);

   cert_file = fopen(path, "r");
   if (cert_file == NULL) {
      verror_put_string("Failure opening file \"%s\"", cert_file);
      verror_put_errno(errno);
      return -1;
   }

   if (not_before)
       *not_before = 0;
   if (not_after)
       *not_after = 0;

   while (PEM_read_X509(cert_file, &cert, PEM_NO_CALLBACK) != NULL) {
       if (not_before) {
	   time_t new_not_before;
	   globus_gsi_cert_utils_make_time(X509_get_notBefore(cert),
					   &new_not_before);
	   if (*not_before == 0 || *not_before < new_not_before) {
	       *not_before = new_not_before;
	   }
       }
       if (not_after) {
	   time_t new_not_after;
	   globus_gsi_cert_utils_make_time(X509_get_notAfter(cert),
					   &new_not_after);
	   if (*not_after == 0 || *not_after > new_not_after) {
	       *not_after = new_not_after;
	   }
       }
       
       X509_free(cert);
       cert = NULL;
   }

   fclose(cert_file);

   return 0;
}
