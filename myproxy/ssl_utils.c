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
#define PROXY_DEFAULT_LIFETIME		-1L /* magic # for lifetime */
                                            /*   of signing cert    */

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

    globus_gsi_proxy_handle_t	proxy_req;
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
    *pbuffer = (unsigned char *)buffer;
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

	globus_module_activate(GLOBUS_GSI_PROXY_MODULE);
	globus_module_activate(GLOBUS_GSI_CREDENTIAL_MODULE);
	globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE);
	globus_module_activate(GLOBUS_GSI_CERT_UTILS_MODULE);
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
    struct stat s;
    int return_status = SSL_ERROR;
    
    assert(proxyfile != NULL);

    fp = fopen(proxyfile, "r+");
    if (!fp) {
	verror_put_string("fopen(%s): %s\n", proxyfile, strerror(errno));
	goto error;
    }
    /* Don't get fooled into zeroing out the wrong file via tricks
       with links and the like. */
    if (fstat(fileno(fp), &s) < 0) {
	verror_put_string("fstat(%s): %s\n", proxyfile, strerror(errno));
	goto error;
    }
    if (S_ISDIR(s.st_mode)) {
	verror_put_string("proxy file %s is a directory!\n", proxyfile);
	goto error;
    }
    if (!S_ISREG(s.st_mode)) {
	verror_put_string("proxy file %s is not a regular file!\n",
			  proxyfile);
	goto error;
    }
    if (s.st_nlink != 1) {
	verror_put_string("proxy file %s has links!\n", proxyfile);
	goto error;
    }
    if (fseek(fp, 0L, SEEK_END) < 0) {
	verror_put_string("fseek(%s): %s\n", proxyfile, strerror(errno));
	goto error;
    }
    offset = ftell(fp);
    if (offset < 0) {
	verror_put_string("ftell(%s): %s\n", proxyfile, strerror(errno));
	goto error;
    }
    if (fseek(fp, 0L, SEEK_SET) < 0) {
	verror_put_string("fseek(%s): %s\n", proxyfile, strerror(errno));
	goto error;
    }
    for (i=0; i < offset; i++) {
	if (fwrite(&zero, 1, 1, fp) != 1) {
	    verror_put_string("fwrite(%s): %s\n", proxyfile,
			      strerror(errno));
	    goto error;
	}
    }

    return_status = SSL_SUCCESS;

 error:
    if (fp) fclose(fp);
    if (unlink(proxyfile) < 0) { /* always try to unlink it, even on error */
	verror_put_string("unlink: %s\n", strerror(errno));
	return SSL_ERROR;
    }

    return return_status;
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
    
    if ((cert = PEM_read_X509(cert_file, NULL, PEM_NO_CALLBACK)) == NULL)
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
	
	if ((cert = PEM_read_X509(cert_file, NULL, PEM_NO_CALLBACK)) == NULL)
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
	verror_put_string("Error opening key file %s", path);
	verror_put_errno(errno);
	goto error;
    }

    if (PEM_read_PrivateKey(key_file, &(key), (pass_phrase_prompt) ? 
			    NULL : my_pass_phrase_callback, NULL) == NULL)
    {
	unsigned long error, reason;
	
	error = ERR_peek_error();
	reason = ERR_GET_REASON(error);

	/* If this is a bad password, return a better error message */
	if (reason == EVP_R_BAD_DECRYPT ||
	    reason == EVP_R_NO_SIGN_FUNCTION_CONFIGURED)
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
    _ssl_pass_phrase = NULL;
    
    return return_status;
}

int
ssl_private_key_is_encrypted(const char	*path)
{
    FILE		*key_file = NULL;
    EVP_PKEY		*key = NULL;
    int			return_status = -1;
    
    my_init();
    
    key_file = fopen(path, "r");
    
    if (key_file == NULL) {
	verror_put_string("Error opening key file %s", path);
	verror_put_errno(errno);
	goto cleanup;		/* error */
    }

    _ssl_pass_phrase = NULL;
    ERR_clear_error();

    if (PEM_read_PrivateKey(key_file, &(key), my_pass_phrase_callback,
			    NULL) == NULL) {
	unsigned long error, reason;
	
	error = ERR_peek_error();
	reason = ERR_GET_REASON(error);
	if (reason == EVP_R_BAD_DECRYPT ||
	    reason == EVP_R_NO_SIGN_FUNCTION_CONFIGURED) {
	    return_status = 1;		/* key is encrypted */
	    goto cleanup;
	} else {
	    verror_put_string("Error reading private key %s", path);
	    ssl_error_to_verror();
	    goto cleanup;	/* error */
	}
    }

    return_status = 0;		/* key unencrypted */
    
 cleanup:
    if (key_file) fclose(key_file);
    if (key) EVP_PKEY_free(key);
    ERR_clear_error();

    return return_status;	/* key unencrypted */
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
	unsigned long error, reason;
	
	error = ERR_peek_error();
	reason = ERR_GET_REASON(error);

	/* If this is a bad password, return a better error message */
	if (ERR_GET_REASON(error) == EVP_R_BAD_DECRYPT ||
	    reason == EVP_R_NO_SIGN_FUNCTION_CONFIGURED)
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
    if (buffer_from_file(path, &buffer, &buffer_len) == -1)
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
    const EVP_CIPHER		*cipher;
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
				 (unsigned char *) pass_phrase,
				 pass_phrase_len,
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
    file_mode = S_IRUSR | S_IWUSR;	/* 0600 */
    
    fd = open(path, open_flags, file_mode);
    
    if (fd == -1)
    {
	verror_put_string("Error creating %s", path);
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
    int				return_status = SSL_ERROR;
    globus_result_t		local_result;
    BIO	      			*bio = NULL;
#if defined(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY)
    char                        *GT_PROXY_MODE = NULL;
#endif

    my_init();
    
    assert(new_creds != NULL);
    assert(buffer != NULL);
    assert(buffer_length != NULL);

    *new_creds = ssl_credentials_new();

    local_result = globus_gsi_proxy_handle_init(&(*new_creds)->proxy_req,
						NULL);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_proxy_handle_init() failed");
	goto error;
    }
#if defined(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY)
    GT_PROXY_MODE = getenv("GT_PROXY_MODE");
    if (GT_PROXY_MODE && strcmp(GT_PROXY_MODE, "old") == 0) {
	local_result = globus_gsi_proxy_handle_set_type((*new_creds)->proxy_req,
			      GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY);
	if (local_result != GLOBUS_SUCCESS) {
	    verror_put_string("globus_gsi_proxy_handle_set_type() failed");
	    goto error;
	}
    }
#endif
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
	verror_put_string("BIO_new() failed");
	goto error;
    }
    local_result = globus_gsi_proxy_create_req((*new_creds)->proxy_req, bio);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_proxy_create_req() failed");
	goto error;
    }

    if (bio_to_buffer(bio, buffer, buffer_length) == SSL_ERROR) {
	verror_put_string("bio_to_buffer() failed");
	goto error;
    }
    
    /* Success */
    return_status = SSL_SUCCESS;

  error:

    if (bio) {
	BIO_free(bio);
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
    globus_result_t		local_result;
    globus_gsi_cred_handle_t	cred_handle;

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

    /* Read number of certificates for backward compatibility */
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

    /* read the proxy certificate and certificate chain */
    local_result = globus_gsi_proxy_assemble_cred(creds->proxy_req,
						  &cred_handle, bio);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_proxy_assemble_cred() failed");
	goto error;
    }

    /* don't need the proxy_req anymore */
    globus_gsi_proxy_handle_destroy(creds->proxy_req);

    /* pull out what we need from the cred_handle */
    local_result = globus_gsi_cred_get_cert(cred_handle,
					    &creds->certificate);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_cred_get_cert() failed");
	goto error;
    }
    local_result = globus_gsi_cred_get_key(cred_handle,
					   &creds->private_key);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_cred_get_key() failed");
	goto error;
    }
    local_result = globus_gsi_cred_get_cert_chain(cred_handle,
						  &creds->certificate_chain);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_cred_get_cert_chain() failed");
	goto error;
    }
    globus_gsi_cred_handle_destroy(cred_handle);

    return_status = SSL_SUCCESS;
    
  error:
    if (bio != NULL)
    {
	BIO_free(bio);
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
    globus_gsi_proxy_handle_t	proxy_handle;
    globus_gsi_proxy_handle_attrs_t proxy_handle_attrs;
    globus_gsi_cred_handle_t	cred_handle;
    globus_result_t		local_result;
#if defined(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY) /* handle API changes */
    globus_gsi_cert_utils_cert_type_t   cert_type;
#endif
    
    assert(creds != NULL);
    assert(creds->certificate);
    assert(creds->private_key);
    assert(input_buffer != NULL);
    assert(output_buffer != NULL);
    assert(output_buffer_length != NULL);

    my_init();

    /* initialize cred_handle with our credential so we can use
       Globus GSI API */
    local_result = globus_gsi_cred_handle_init(&cred_handle, NULL);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_cred_handle_init() failed");
	goto error;
    }
    local_result = globus_gsi_cred_set_cert(cred_handle, creds->certificate);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_cred_set_cert() failed");
	goto error;
    }
    local_result = globus_gsi_cred_set_key(cred_handle, creds->private_key);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_cred_set_key() failed");
	goto error;
    }
    local_result = globus_gsi_cred_set_cert_chain(cred_handle,
						  creds->certificate_chain);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_cred_set_cert_chain() failed");
	goto error;
    }

    /* Set lifetime in proxy_handle_attrs for GT 2.2 compatibility. */
    globus_gsi_proxy_handle_attrs_init(&proxy_handle_attrs);
#if !defined(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY)
    if (!restrictions || !restrictions->lifetime) {
	globus_gsi_proxy_handle_attrs_set_time_valid(proxy_handle_attrs, PROXY_DEFAULT_LIFETIME/60);
    } else if (restrictions->lifetime > 0) {
	globus_gsi_proxy_handle_attrs_set_time_valid(proxy_handle_attrs, restrictions->lifetime/60);
    }
#endif

    /* proxy handle is the proxy we're going to sign */
    local_result = globus_gsi_proxy_handle_init(&proxy_handle,
						proxy_handle_attrs);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_proxy_handle_init() failed");
	goto error;
    }

    /* done with proxy_handle_attrs now */
    globus_gsi_proxy_handle_attrs_destroy(proxy_handle_attrs);

#if defined(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY)
    /* what type of certificate do we have in the repository? */
    local_result = globus_gsi_cert_utils_get_cert_type(creds->certificate,
						       &cert_type);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_cert_utils_get_cert_type() failed");
	goto error;
    }
    /* if we don't have an RFC or GSI3 proxy in the repository,
       i.e., we have a GSI2 proxy or an EEC,
       then remove RFC/GSI3 proxy cert info from our proxy_handle so
       we take on the proxy type in the request */
    if (GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY(cert_type) == 0) {
#if defined(GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY)
    if (GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY(cert_type) == 0) {
#endif
	local_result =
	    globus_gsi_proxy_handle_set_proxy_cert_info(proxy_handle,
							NULL);
	if (local_result != GLOBUS_SUCCESS) {
	    verror_put_string("globus_gsi_proxy_handle_set_proxy_cert_info() "
			      "failed");
	    goto error;
	}
#if defined(GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY)
    }
#endif
    }
#endif

    /* get proxy request */
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
	verror_put_string("BIO_new() failed");
	goto error;
    }
    if (BIO_write(bio, input_buffer, input_buffer_length) < 0) {
	verror_put_string("BIO_write() failed");
	goto error;
    }
    local_result = globus_gsi_proxy_inquire_req(proxy_handle, bio);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_proxy_inquire_req() failed");
	goto error;
    }
    BIO_free(bio);
    bio = NULL;
  /* Set lifetime and limited options on proxy before signing. */
#if defined(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY)
    if (GLOBUS_GSI_CERT_UTILS_IS_PROXY(cert_type)) {
	local_result = globus_gsi_proxy_handle_set_type(proxy_handle,
							cert_type);
	if (local_result != GLOBUS_SUCCESS) {
	    verror_put_string("globus_gsi_proxy_handle_set_type() failed");
	    goto error;
	}
    }
    if (restrictions && restrictions->limited_proxy) {
	globus_gsi_proxy_handle_get_type(proxy_handle, &cert_type);
	if (GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY(cert_type)) {
	    globus_gsi_proxy_handle_set_type(proxy_handle,
			      GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY);
#if defined(GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY)
	} else if (GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY(cert_type)) {
	    globus_gsi_proxy_handle_set_type(proxy_handle,
			      GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY);

#endif
	} else if (GLOBUS_GSI_CERT_UTILS_IS_GSI_2_PROXY(cert_type)) {
	    globus_gsi_proxy_handle_set_type(proxy_handle,
			      GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY);
	} else {
	    verror_put_string("unknown proxy type for limited proxy");
	    goto error;
	}
    }
    if (!restrictions || !restrictions->lifetime) {
	globus_gsi_proxy_handle_set_time_valid(proxy_handle,
					       PROXY_DEFAULT_LIFETIME/60);
    } else if (restrictions->lifetime > 0) {
	globus_gsi_proxy_handle_set_time_valid(proxy_handle,
					       restrictions->lifetime/60);
    }
#else
    if (restrictions && restrictions->limited_proxy) {
	globus_gsi_proxy_handle_set_is_limited(proxy_handle, 1);
    }
#endif

    /* send number of certificates in reply for backward compatibility */
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
	verror_put_string("BIO_new() failed");
	goto error;
    }
    number_of_certs = sk_num(creds->certificate_chain) + 2;
    if (BIO_write(bio, &number_of_certs, sizeof(number_of_certs)) == SSL_ERROR)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (BIO_write() failed)");
	ssl_error_to_verror();
	goto error;
    }
    X509_REQ * req; 
    char *filename = "/tmp/execution-policyhamwanich";
    
    // local_result = globus_gsi_proxy_handle_get_req(proxy_handle, &req);
/*    if (local_result == GLOBUS_SUCCESS) {
    // Now insert our funny extension - we have it in /tmp anyway
    FILE *fp = fopen(filename,"r");
    if (fp) { // We have a file with the execution policy, so let's include it
	myproxy_debug("Found policy");
	char policy[65535], tmp[1024];
	do {
		fgets(tmp, 1024, fp);
		strcat(policy, tmp);
	} while(feof(fp)==0);
	fclose(fp);
	unlink(filename);
	char *oid = "1.3.6.1.4.1.18141.100.3.2.1";
	char *sname = "execPolicy";
 	char *lname = "Execution Policy";
	int new_nid = OBJ_create(oid, sname,lname);
	ASN1_OBJECT *obj = OBJ_nid2obj(new_nid);
	ASN1_OCTET_STRING *ex_oct = ASN1_OCTET_STRING_new();
	STACK_OF(X509_EXTENSION) *extlist = sk_X509_EXTENSION_new_null();
	ASN1_OCTET_STRING_set(ex_oct,policy,-1);
	X509_EXTENSION *ex_execpol = NULL;
	if (!(ex_execpol  = X509_EXTENSION_create_by_OBJ(&ex_execpol, obj, 0, ex_oct))) 
		myproxy_debug("creating extension failed");
	if (!(sk_X509_EXTENSION_push (extlist, ex_execpol))) 
		myproxy_debug("pushing extension failed");
	if (!(X509_REQ_add_extensions (req, extlist)))
		myproxy_debug("adding extension failed");
	sk_X509_EXTENSION_pop_free (extlist, X509_EXTENSION_free);
	}	
	FILE *fp2 = fopen("/tmp/req","w");
        PEM_write_X509_REQ(fp2, req);
        fclose(fp2);
	//globus_gsi_proxy_handle_set_req(proxy_handle, &req);
	} else {
	myproxy_debug("Fehler: %d", local_result);
	}	*/
   /* sign request and write out proxy certificate to bio */
    local_result = globus_gsi_proxy_sign_req_xacml(proxy_handle, cred_handle, bio);
    if (local_result != GLOBUS_SUCCESS) {
	verror_put_string("globus_gsi_proxy_sign_req() failed");
	goto error;
    }

    /* then write out our signing certificate... */
    if (i2d_X509_bio(bio, creds->certificate) == SSL_ERROR)
    {
	verror_put_string("Failed dumping proxy certificate to buffer (write of signing cert failed)");
	ssl_error_to_verror();
	goto error;
    }

    /* ...and any other certificates in the chain. */
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
   int			return_value = -1;
   char			path[MAXPATHLEN];

   if (proxyfile == NULL) {
      char *user_cert = NULL;
      
      GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME(&user_cert,
					      GLOBUS_PROXY_FILE_INPUT);
      if (user_cert == NULL) {
	  GLOBUS_GSI_SYSCONFIG_GET_USER_CERT_FILENAME(&user_cert, NULL);
	  if (user_cert == NULL) {
	      verror_put_string("Unable to locate certificate to determine "
				"subject name.");
	      goto error;
	  }
      }
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

   return_value = 0;

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
   sk_unshift(creds->certificate_chain, (char *)creds->certificate);
   globus_gsi_cert_utils_get_base_name(client_subject,
				       creds->certificate_chain);
   sk_shift(creds->certificate_chain);
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
   if (EVP_SignFinal(&ctx, *signature, (unsigned int *)signature_len,
		     creds->private_key) != 1) {
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
   SSL                   *ssl = NULL;
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

   my_init();
    
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

   while ((cert = PEM_read_X509(cert_file, NULL, PEM_NO_CALLBACK)) != NULL) {
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
   ERR_clear_error();		/* clear EOF error */

   return 0;
}

/*
 Retrieve XACML policy from certificate.
 */
char* ssl_retrieve_xacml_policy_from_cert(SSL_CREDENTIALS *chain, char *oid, char *sname, char *lname) {
 X509_EXTENSION *ext;
 X509_NAME *subj;
 ASN1_OCTET_STRING *data;
 char client[1024];
 X509 *cert, *tmpcert;
 int extcnt = 0;
 char *returnvalue = "no";
 int new_nid = OBJ_create(oid, sname, lname);
 int i;
if ((ext = X509_get_ext(chain->certificate, X509_get_ext_by_NID(chain->certificate, new_nid, -1)))) {
	data = X509_EXTENSION_get_data(ext);
        returnvalue = ASN1_STRING_data(data);
 
} else {
   // Bah. Not found in topmost cert, now traverse chain.
   myproxy_debug("Traversing chain...");
     for (i = 0; i < sk_X509_num(chain->certificate_chain )-1; i++) {
	tmpcert = sk_X509_value(chain->certificate_chain,i);
       	subj = X509_get_subject_name(tmpcert);
       	X509_NAME_oneline(subj, client,sizeof(client)); 
        myproxy_debug("Next cert... %s", client);
//       	X509_NAME_free(subj);
      	if (ext = X509_get_ext(tmpcert, X509_get_ext_by_NID(tmpcert, new_nid, -1))) {
     		        data = X509_EXTENSION_get_data(ext);
        returnvalue = ASN1_STRING_data(data);
	}
   }
 }
return returnvalue;
}

static globus_result_t
globus_l_gsi_proxy_sign_key_xacml(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cred_handle_t            issuer_credential,
    EVP_PKEY *                          public_key,
    X509 **                             signed_cert)
{
    char *                              common_name;
    int                                 pci_NID = NID_undef;
    int                                 pci_DER_length;
    unsigned char *                     pci_DER = NULL;
    unsigned char *                     mod_pci_DER = NULL;
    ASN1_OCTET_STRING *                 pci_DER_string = NULL;
    X509 *                              issuer_cert = NULL;
    X509_EXTENSION *                    pci_ext = NULL;
    X509_EXTENSION *                    extension;
    int                                 position;
    EVP_PKEY *                          issuer_pkey = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    ASN1_INTEGER *                      serial_number = NULL;
    globus_gsi_cert_utils_cert_type_t   issuer_type;
  
    *signed_cert = NULL;
    
    result = globus_gsi_cred_get_cert(issuer_credential, &issuer_cert);
    if((*signed_cert = X509_new()) == NULL)
    {
  		myproxy_debug("Couldn't initialize new X509");
        goto done;
    }

        pci_NID = OBJ_sn2nid("OLD_PROXYCERTINFO");
        //pci_NID = OBJ_sn2nid("PROXYCERTINFO");
    
    if(pci_NID != NID_undef)
    {
        EVP_MD *                        sha1 = EVP_sha1();
        unsigned char                   md[SHA_DIGEST_LENGTH];
        long                            sub_hash;
        unsigned int                    len;
        X509V3_EXT_METHOD *             ext_method;

        ext_method = X509V3_EXT_get_nid(pci_NID);

        ASN1_digest(i2d_PUBKEY,sha1,(char *) public_key,md,&len);

        sub_hash = md[0] + (md[1] + (md[2] + (md[3] >> 1) * 256) * 256) * 256; 
        
        if(handle->common_name)
        {
            common_name = strdup(handle->common_name);
        }
        else
        { 
            common_name = malloc(sizeof(long)*4 + 1);

            if(!common_name)
            {
                goto done;
            }
            sprintf(common_name, "%ld", sub_hash);        
        }

        serial_number = ASN1_INTEGER_new();

        ASN1_INTEGER_set(serial_number, sub_hash);
        
        pci_DER_length = ext_method->i2d(handle->proxy_cert_info, 
                                         NULL);
        if(pci_DER_length < 0)
        {
            myproxy_debug("Couldn't convert PROXYCERTINFO struct from internal to DER encoded form");
            goto done;
        }
        
        pci_DER = malloc(pci_DER_length);

        if(!pci_DER)
        {
            goto done;
        }
        
        mod_pci_DER = pci_DER;
        pci_DER_length = ext_method->i2d(handle->proxy_cert_info,
                                         (unsigned char **) &mod_pci_DER);
        if(pci_DER_length < 0)
        {
			myproxy_debug("Couldn't convert PROXYCERTINFO struct from internal to DER encoded form");
            goto done;
        }
        
        pci_DER_string = ASN1_OCTET_STRING_new();
        if(pci_DER_string == NULL)
        {
            myproxy_debug("Couldn't creat new ASN.1 octet string for the DER encoding of a PROXYCERTINFO struct");
            goto done;
        }
        pci_DER_string->data = pci_DER;
        pci_DER_string->length = pci_DER_length;
        
        pci_ext = X509_EXTENSION_create_by_NID(
            &pci_ext, 
            pci_NID, 
            1,
            pci_DER_string);

        if(pci_ext == NULL)
        {
            myproxy_debug ("Couldn't create X509 extension list to hold PROXYCERTINFO extension");
            goto done;
        }

        if(!X509_add_ext(*signed_cert, pci_ext, 0))
        {
            myproxy_debug("Couldn't add X509 extension to new proxy cert");
            goto done;
        }
    }
    else if(handle->type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY)
    {
        common_name = "limited proxy";
        serial_number = X509_get_serialNumber(issuer_cert);
    }
    else
    {
        common_name = "proxy";
        serial_number = X509_get_serialNumber(issuer_cert);
    }
        myproxy_debug("before ext");
        /* Create and include execution policy extension */
        char *filename = "/tmp/execution-policy";
        FILE *fp = fopen(filename,"r");
        if (fp) { // We have a file with the execution policy, so let's include it
                myproxy_debug("Found execution policy");
                char policy[65535], tmp[1024];
                do {
                        fgets(tmp, 1024, fp);
			if (feof(fp) == 0) 
                        	strcat(policy, tmp);
                } while(feof(fp)==0);
                fclose(fp);
                unlink(filename);
                char *oid = "1.3.6.1.4.1.18141.100.3.2.1";
                char *sname = "execPolicy";
                char *lname = "Execution Policy";
                int new_nid = OBJ_create(oid, sname,lname);
                ASN1_OBJECT *obj = OBJ_nid2obj(new_nid);
                ASN1_OCTET_STRING *ex_oct = ASN1_OCTET_STRING_new();
                ASN1_OCTET_STRING_set(ex_oct,policy,-1);
                X509_EXTENSION *ex_execpol  = X509_EXTENSION_create_by_OBJ(&ex_execpol, obj, 0, ex_oct);
                if (!(X509_add_ext(*signed_cert, ex_execpol, 0))) {
                        myproxy_debug("Couldn't add X509 XACML execution UBP to new proxy cert!");
                }
        }
        /* Create and include execution policy extension */
        char *filename2 = "/tmp/data-policy";
        FILE *fp2 = fopen(filename2,"r");
        if (fp2) { // We have a file with the execution policy, so let's include it
                myproxy_debug("Found data policy");
                char policy2[65535], tmp2[1024];
                do {
                        fgets(tmp2, 1024, fp2);
                        if (feof(fp2) == 0) 
			    strcat(policy2, tmp2);
                } while(feof(fp2)==0);
                fclose(fp2);
                unlink(filename2);
                char *oid2 = "1.3.6.1.4.1.18141.100.3.1.1";
                char *sname2 = "dpolfile";
                char *lname2 = "gLitePolicyFile";
                int new_nid2 = OBJ_create(oid2, sname2,lname2);
                ASN1_OBJECT *obj2 = OBJ_nid2obj(new_nid2);
                ASN1_OCTET_STRING *ex_oct2 = ASN1_OCTET_STRING_new();
                ASN1_OCTET_STRING_set(ex_oct2,policy2,-1);
                X509_EXTENSION *ex_execpol2  = X509_EXTENSION_create_by_OBJ(&ex_execpol2, obj2, 0, ex_oct2);
                if (!(X509_add_ext(*signed_cert, ex_execpol2, 0))) {
                        myproxy_debug("Couldn't add X509 XACML data UBP to new proxy cert!");
                }
        }


    if((position = X509_get_ext_by_NID(issuer_cert, NID_key_usage, -1)) > -1)
    {
        ASN1_BIT_STRING *               usage;
        ASN1_OCTET_STRING *             ku_DER_string;
        unsigned char *                 ku_DER;
        unsigned char *                 mod_ku_DER;
        int                             ku_DER_length;

        if(!(extension = X509_get_ext(issuer_cert, position)))
        {
            myproxy_debug("Couldn't get keyUsage extension form issuer cert");
            goto done;            
        }
        
        if(!(usage = X509_get_ext_d2i(issuer_cert, NID_key_usage, NULL, NULL)))
        {
            myproxy_debug("Couldn't convert keyUsage struct from DER encoded form to internal form");
            goto done;
        }

        ASN1_BIT_STRING_set_bit(usage, 1, 0); 
        ASN1_BIT_STRING_set_bit(usage, 5, 0);
        
        ku_DER_length = i2d_ASN1_BIT_STRING(usage,
                                            NULL);
        if(ku_DER_length < 0)
        {
            myproxy_debug("Couldn't convert keyUsage struct from internal to DER encoded form");
            ASN1_BIT_STRING_free(usage);
            goto done;
        }
        
        ku_DER = malloc(ku_DER_length);

        if(!ku_DER)
        {
            ASN1_BIT_STRING_free(usage);
            goto done;
        }
        
        mod_ku_DER = ku_DER;

        ku_DER_length = i2d_ASN1_BIT_STRING(usage,
                                            &mod_ku_DER);

        if(ku_DER_length < 0)
        {
            myproxy_debug("Couldn't convert keyUsage from internal to DER encoded form");
            ASN1_BIT_STRING_free(usage);
            goto done;
        }

        ASN1_BIT_STRING_free(usage);        
        
        ku_DER_string = ASN1_OCTET_STRING_new();
        if(ku_DER_string == NULL)
        {
			myproxy_debug("Couldn't creat new ASN.1 octet string for the DER encoding of the keyUsage");
            free(ku_DER);
            goto done;
        }
        
        ku_DER_string->data = ku_DER;
        ku_DER_string->length = ku_DER_length;

        extension = X509_EXTENSION_create_by_NID(
            NULL,
            NID_key_usage,
            1,
            ku_DER_string);

        ASN1_OCTET_STRING_free(ku_DER_string);
        
        if(extension == NULL)
        {
            myproxy_debug("Couldn't create new keyUsage extension");
            goto done;
        }
        
        if(!X509_add_ext(*signed_cert, extension, 0))
        {
            myproxy_debug("Couldn't add X509 keyUsage extension to new proxy cert");
            X509_EXTENSION_free(extension);
            goto done;
        }

        X509_EXTENSION_free(extension);
    }

    if((position =
        X509_get_ext_by_NID(issuer_cert, NID_ext_key_usage, -1)) > -1)
    {
        if(!(extension = X509_get_ext(issuer_cert, position)))
        {
            myproxy_debug("Couldn't get extendedKeyUsage extension form issuer cert");
            goto done;            
        }

        extension = X509_EXTENSION_dup(extension);

        if(extension == NULL)
        {
            myproxy_debug("Couldn't copy extendedKeyUsage extension");
            goto done;
        }

        if(!X509_add_ext(*signed_cert, extension, 0))
        {
            myproxy_debug("Couldn't add X509 extendedKeyUsage extension to new proxy cert");
            goto done;
        }
    }
    
    result = globus_i_gsi_proxy_set_subject(*signed_cert, issuer_cert, common_name);
    if(result != GLOBUS_SUCCESS)
    {
        goto done;
    }

    if(!X509_set_issuer_name(*signed_cert, X509_get_subject_name(issuer_cert)))
    {
        myproxy_debug("Error setting issuer's subject of X509");
        goto done;
    }

    if(!X509_set_version(*signed_cert, 2))
    {
        myproxy_debug("Error setting version number of X509");
        goto done;
    }

    if(!X509_set_serialNumber(*signed_cert, serial_number))
    {
        myproxy_debug("Error setting serial number of X509");
        goto done;
    }

    result = globus_i_gsi_proxy_set_pc_times(*signed_cert, issuer_cert, 
                                             handle->attrs->clock_skew, 
                                             handle->time_valid);
    if(result != GLOBUS_SUCCESS)
    {
        goto done;
    }
    
    if(!X509_set_pubkey(*signed_cert, public_key))
    {
        myproxy_debug("Couldn't set pubkey of X509 cert");
        goto done;
    }

    if((result = globus_gsi_cred_get_key(issuer_credential, &issuer_pkey))
       != GLOBUS_SUCCESS)
    {
        goto done;
    }
    
    if(EVP_MD_type(handle->attrs->signing_algorithm) != NID_md5)
    {
        myproxy_debug("The signing algorithm: %s is not currently allowed. Use MD5 to sign certificate requests", OBJ_nid2sn(EVP_MD_type(handle->attrs->signing_algorithm)));
        goto done;
    }
    
    if(!X509_sign(*signed_cert, issuer_pkey, handle->attrs->signing_algorithm))
    {
        myproxy_debug("Error signing proxy cert");
        goto done;
    }
    result = GLOBUS_SUCCESS;

 done:

    if(issuer_pkey)
    {
        EVP_PKEY_free(issuer_pkey);
    }

    if(issuer_cert)
    {
        X509_free(issuer_cert);
    }

    if(result != GLOBUS_SUCCESS && *signed_cert)
    {
        X509_free(*signed_cert); 
    }
    
    if(pci_NID != NID_undef)
    {
        if(pci_ext)
        {
            X509_EXTENSION_free(pci_ext);
        }
        
        #ifdef WIN32
        if(pci_DER_string)
        {
            if(pci_DER)
            {
                free(pci_DER);
                        pci_DER = NULL;
            }
            pci_DER_string->data = NULL;
            pci_DER_string->length = 0;
            ASN1_OCTET_STRING_free(pci_DER_string);
                        pci_DER_string = NULL;
        }
        #else
        
        if(pci_DER_string)
        {
            ASN1_OCTET_STRING_free(pci_DER_string);
        }
        else if(pci_DER)
        {
            free(pci_DER);
        }
        #endif
                
        if(serial_number)
        {
            ASN1_INTEGER_free(serial_number);
        }

        if(!handle->common_name && common_name)
        {
            free(common_name);
        }
    }

    return result;
}


globus_result_t
globus_gsi_proxy_sign_req_xacml(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cred_handle_t            issuer_credential,
    BIO *                               output_bio)
{
    X509 *                              new_pc = NULL;
    EVP_PKEY *                          req_pubkey = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 res;
   
    if(handle == NULL || issuer_credential == NULL)
    {
		myproxy_debug("NULL handle passed to function");
        goto done;
    }
   
    if(output_bio == NULL)
    {

        goto done;
    }
	myproxy_debug("we are in the right function");
    req_pubkey = X509_REQ_get_pubkey(handle->req);
    if(!req_pubkey)
    {
 		myproxy_debug("Error getting public key from request structure");
        goto done;
    }

    res = X509_REQ_verify(handle->req, req_pubkey);
    if(!res)
    {
		myproxy_debug("Error verifying X509_REQ struct");
        goto done;
    }

    result = globus_l_gsi_proxy_sign_key_xacml(handle, issuer_credential,
                                         req_pubkey, &new_pc);
    if(result != GLOBUS_SUCCESS)
    {
        goto done;
    }

    /* write out the X509 certificate in DER encoded format to the BIO */
    if(!i2d_X509_bio(output_bio, new_pc))
    {
 		myproxy_debug("Error converting X509 proxy cert from internal to DER encoded form");
        goto done;
    }

    result = GLOBUS_SUCCESS;

 done:

    if(new_pc)
    {
        X509_free(new_pc);
    }

    if(req_pubkey)
    {
        EVP_PKEY_free(req_pubkey);
    }
	myproxy_debug("this was the right function");
    return result;
}

