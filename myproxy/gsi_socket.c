/*
 * gsi_socket.c
 *
 * See gsi_socket.h for documentation.
 */

#include "gsi_socket.h"
#include "ssl_utils.h"
#include "verror.h"
#include "string_funcs.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>

#ifndef SUPPORT_SSL_ANONYMOUS_AUTH
#include <gssapi.h>
#include <globus_gss_assist.h>
#endif

struct _gsi_socket 
{
    int				sock;
    int				encryption;	/* Boolean */
    int				allow_anonymous; /* Boolean */
    /* All these variables together indicate the last error we saw */
    char			*error_string;
    int				error_number;
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    SSL_CTX			*ssl_context;
    SSL				*ssl;
    proxy_cred_desc		*cred_handle;
#else
    gss_ctx_id_t		gss_context;
    OM_uint32			major_status;
    OM_uint32			minor_status;
#endif
    char			*expected_peer_name;
    char			*peer_name;
    /* Buffer to hold unread, unwrapped data */
    char			*input_buffer;
    char			*input_buffer_index;
    int				input_buffer_length;
};

#define DEFAULT_SERVICE_NAME		"host"

/*********************************************************************
 *
 * Internal functions
 *
 */


#if !defined(SUPPORT_SSL_ANONYMOUS_AUTH)
/*
 * append_gss_status()
 *
 * Given a gssapi status and and indicator (gssapi error or mechanism-
 * specific error), append the errors strings to the given string.
 *
 * Returns number of bytes written to buffer, -1 if error was truncated
 * because the buffer was too small.
 */
static int
append_gss_status(char *buffer,
		  int bufferlen,
		  const OM_uint32 gss_code,
		  const int type)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_buffer_desc error_string;
    OM_uint32 context = 0;
    int total_chars = 0;
    int chars;
        
    assert(buffer != NULL);
    
    do 
    {
	maj_stat = gss_display_status(&min_stat, gss_code, type,
				      GSS_C_NULL_OID,
				      &context, &error_string);

	if ((error_string.value != NULL) &&
	    (error_string.length > 0))
	{
	    chars = my_strncpy(buffer, error_string.value, bufferlen);
	    
	    if (chars == -1)
	    {
		return -1;
	    }
	    
	    total_chars += chars;
	    buffer = &buffer[chars];
	    bufferlen -= chars;
	}

	(void) gss_release_buffer(&min_stat, &error_string);

    } while(context);
    
    return total_chars;
}
#endif

/*
 * read_all()
 *
 * Read all the requested bytes into the requested buffer.
 */
static int
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
read_all(SSL *ssl,
#else
read_all(const int sock,
#endif
	 char *buffer,
	 const int nbytes)
{
    int total_bytes_read = 0;
    int bytes_read;
    
    assert(buffer != NULL);
    
    while (total_bytes_read < nbytes)
    {
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
	bytes_read = SSL_read(ssl, &buffer[total_bytes_read], 
#else
	bytes_read = read(sock, &buffer[total_bytes_read], 
#endif
			  nbytes - total_bytes_read);
	
	if (bytes_read == -1)
	{
	    return -1;
	}

	if (bytes_read == 0)
	{
	    /* EOF */
	    errno = EPIPE;
	    return -1;
	}
	
	total_bytes_read += bytes_read;
    }
    
    return total_bytes_read;
}

/*
 * write_all()
 *
 * Write all the requested bytes to the given socket.
 */
static int
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
write_all(SSL *ssl,
#else
write_all(const int sock,
#endif
	  const char *buffer,
	  const int nbytes)
{
    int total_bytes_written = 0;
    int bytes_written;
    
    assert(buffer != NULL);
    
    while (total_bytes_written < nbytes)
    {
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
	bytes_written = SSL_write(ssl, (char *)&buffer[total_bytes_written], 
#else
	bytes_written = write(sock, &buffer[total_bytes_written], 
#endif
			      nbytes - total_bytes_written);
	
	if (bytes_written == -1)
	{
	    return -1;
	}

	if (bytes_written == 0)
	{
	    /* EOF */
	    errno = EPIPE;
	    return -1;
	}

	total_bytes_written += bytes_written;
    }
    
    return total_bytes_written;
}


/*
 * read_token()
 *
 * Read and allocate a token from the given socket.
 */
static int
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
read_token(SSL *ssl,
#else
read_token(const int sock,
#endif
	   char **p_buffer,
	   size_t *p_buffer_size)
{
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    char *bufferp, c;
#else
    enum header_fields 
    {
	flag                            = 0,
	major_version                   = 1,
	minor_version                   = 2,
	length_high_byte                = 3,
	length_low_byte                 = 4
    };

    char *bufferp;
#endif
    unsigned char header[5];
    int data_len;
    int buffer_len;
    

    assert(p_buffer != NULL);
    assert(p_buffer_size != NULL);
    
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    /* 
     * Get the packet length from SSL so we know how big a buffer to alloc.
     * First, call SSL_peek() to force SSL to read in the message and then
     * get the length with SSL_pending.  If we don't call SSL_peek() first,
     * SSL_pending() will return 0. 
    */
    if (SSL_peek(ssl, &c, 1) < 0 || (data_len = SSL_pending(ssl)) < 0) 
    {
	return -1;
    }

    buffer_len = data_len;
#else
    if (read_all(sock, header, sizeof(header)) < 0) 
    {
	return -1;
    }

    /*
     * Check and make sure token looks right
     */
    if (((header[flag] < 20) || (header[flag] > 26)) ||
	(header[major_version] != 3) ||
	((header[minor_version] != 0) && (header[minor_version] != 1)))
    {
	errno = EBADMSG;
	return -1;
    }
    
    data_len = (header[length_high_byte] << 8) + header[length_low_byte];

    buffer_len = data_len + sizeof(header);
#endif

    *p_buffer = malloc(buffer_len);

    if (*p_buffer == NULL)
    {
	return -1;
    }

    bufferp = *p_buffer;
    
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    if (read_all(ssl, bufferp, data_len) < 0)
#else
    memcpy(bufferp, header, sizeof(header));

    bufferp += sizeof(header);
    
    if (read_all(sock, bufferp, data_len) < 0)
#endif
    {
	free(*p_buffer);
	*p_buffer = NULL;
	return -1;
    }
    
    *p_buffer_size = buffer_len;

    return buffer_len;
}

#if !defined(SUPPORT_SSL_ANONYMOUS_AUTH)
/*
 * assist_read_token()
 *
 * Wrapper around read_token() for gss_assist routines.
 *
 * Returns 0 on success, -1 on error.
 */
static int
assist_read_token(void *p_sock,
		  void **p_buffer,
		  size_t *p_buffer_size)
{
    int return_value;
    
    assert(p_sock != NULL);
    assert(p_buffer != NULL);
    assert(p_buffer_size != NULL);
    
    return_value = read_token(*((int *) p_sock),
			      (char **) p_buffer,
			      p_buffer_size);

    return (return_value == -1 ? -1 : 0);
}
#endif

/*
 * write_token()
 *
 * Write a token to the the given socket.
 *
 * Returns 0 on success, -1 on error.
 */
static int
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
write_token(SSL *ssl,
#else
write_token(const int sock,
#endif
	    const char *buffer,
	    const size_t buffer_size)
{
    int return_value;

    assert(buffer != NULL);

#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    return_value = write_all(ssl, buffer, buffer_size);
#else
    return_value = write_all(sock, buffer, buffer_size);
#endif

    return (return_value == -1 ? -1 : 0);
}


#if !defined(SUPPORT_SSL_ANONYMOUS_AUTH)
static int
assist_write_token(void *sock,
		   void *buffer,
		   size_t buffer_size)
{
    assert(sock != NULL);
    assert(buffer != NULL);
    
    return write_token(*((int *) sock), (char *) buffer, buffer_size);
}
#endif

/*
 * Wrapper around setenv() function
 */
static int
mysetenv(const char *var,
	 const char *value,
	 int override)
{
#ifdef HAVE_SETENV

    return setenv(var, value, override);

#else /* !HAVE_SETENV */

    char *envstr = NULL;
    int status;


    assert(var != NULL);
    assert(value != NULL);
    
    /* If we're not overriding and it's already set, then return */
    if (!override && getenv(var))
	return 0;

    envstr = malloc(strlen(var) + strlen(value) + 2 /* '=' and NUL */);

    if (envstr == NULL)
    {
	return -1;
    }
    
    sprintf(envstr, "%s=%s", var, value);

    status = putenv(envstr);

    /* Don't free envstr as it may still be in use */
  
    return status;
#endif /* !HAVE_SETENV */
}

/*
 * GSI_SOCKET_set_error_from_verror()
 *
 * Set the given GSI_SOCKET's error state from verror.
 */
static void
GSI_SOCKET_set_error_from_verror(GSI_SOCKET *self)
{
    char		*string;
    
    if (verror_is_error() == 0)
    {
	return;
    }
    
    string = verror_get_string();
    
    if (string != NULL)
    {
	self->error_string = strdup(string);
    }
    
    self->error_number = verror_get_errno();
}

	    
/*********************************************************************
 *
 * API Functions
 *
 */

GSI_SOCKET *
GSI_SOCKET_new(int sock)
{
    GSI_SOCKET *self = NULL;
    
    self = malloc(sizeof(GSI_SOCKET));
    
    if (self == NULL)
    {
	return NULL;
    }

    memset(self, 0, sizeof(GSI_SOCKET));
    
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    ERR_load_prxyerr_strings(0);
    SSLeay_add_ssl_algorithms();
    self->ssl_context = NULL;
    self->ssl = NULL;
    self->cred_handle = NULL;
#else
    self->gss_context = GSS_C_NO_CONTEXT;
#endif
    self->sock = sock;

    return self;
}


void
GSI_SOCKET_destroy(GSI_SOCKET *self)
{
    if (self == NULL)
    {
	return;
    }
    
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    if (self->cred_handle)
    {
	proxy_cred_desc_free((proxy_cred_desc *)self->cred_handle);
    }

    if (self->ssl)
    {
	SSL_free(self->ssl);
    }
#else
    if (self->gss_context != GSS_C_NO_CONTEXT)
    {
	gss_buffer_desc output_token_desc  = GSS_C_EMPTY_BUFFER;

	gss_delete_sec_context(&self->minor_status,
			       &self->gss_context,
			       &output_token_desc);
	
	/* XXX Should deal with output_token_desc here */
	gss_release_buffer(&self->minor_status, &output_token_desc);
    }
#endif

    if (self->input_buffer != NULL)
    {
	free(self->input_buffer);
    }

    if (self->expected_peer_name != NULL)
    {
	free(self->expected_peer_name);
    }
    
    if (self->peer_name != NULL)
    {
	free(self->peer_name);
    }
    
    if (self->error_string)
    {
	free(self->error_string);
    }

    free(self);
}


int
GSI_SOCKET_get_error_string(GSI_SOCKET *self,
			    char *buffer,
			    int bufferlen)
{
    int total_chars = 0;
    int chars;
    
    
    if ((buffer == NULL) || (bufferlen == 0))
    {
	/* Punt */
	return -1;
    }
    
    if (self == NULL)
    {
	return my_strncpy(buffer, "GSI_SOCKET is NULL", bufferlen);
    }

    if (self->error_string != NULL)
    {
	chars = my_strncpy(buffer, self->error_string, bufferlen);
	
	if (chars == -1)
	{
	    goto truncated;
	}
	
	total_chars += chars;
	buffer = &buffer[chars];
	bufferlen -= chars;
    }
    
    if (self->error_number != 0)
    {
	chars = my_strncpy(buffer, strerror(self->error_number), bufferlen);

	if (chars == -1)
	{
	    goto truncated;
	}
		
	total_chars += chars;
	buffer = &buffer[chars];
	bufferlen -= chars;
    }

#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    {
	unsigned long sslerror;

	while ((sslerror = ERR_get_error()) != 0 && bufferlen > 120) {
	    ERR_error_string(sslerror, buffer);
	    chars = strlen(buffer);
	    total_chars += chars;
	    buffer = &buffer[chars];
	    bufferlen -= chars;
	}
    }
    
#else
    if (self->major_status)
    {
	chars = append_gss_status(buffer, bufferlen, 
				  self->major_status,
				  GSS_C_GSS_CODE);

	if (chars == -1)
	{
	    goto truncated;
	}
		
	total_chars += chars;
	buffer = &buffer[chars];
	bufferlen -= chars;

	chars = append_gss_status(buffer, bufferlen,
				  self->minor_status,
				  GSS_C_MECH_CODE);

	if (chars == -1)
	{
	    goto truncated;
	}
		
	total_chars += chars;
	buffer = &buffer[chars];
	bufferlen -= chars;

	/* Parse errors from gss-assist routines */
	chars = 0;
	
	switch(self->major_status) 
	{
	  case GSS_S_DEFECTIVE_TOKEN | GSS_S_CALL_INACCESSIBLE_READ:
	    chars = my_strncpy(buffer, "Error reading token", bufferlen);
	    break;
	    
	  case GSS_S_DEFECTIVE_TOKEN | GSS_S_CALL_INACCESSIBLE_WRITE:
	    chars = my_strncpy(buffer, "Error writing token", bufferlen);
	    break;
	}

	total_chars += chars;
	buffer = &buffer[chars];
	bufferlen -= chars;
    }
#endif

    if (total_chars == 0)
    {
	/* No error */
	buffer[0] = '\0';
    }
    
    return total_chars;

  truncated:
    return -1;
}

void
GSI_SOCKET_clear_error(GSI_SOCKET *self)
{
    if (self == NULL)
    {
	return;
    }
    
    if (self->error_string != NULL)
    {
	free(self->error_string);
	self->error_string = NULL;
    }
    self->error_number = 0;
#if !defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    self->major_status = 0;
    self->minor_status = 0;
#endif
}


int
GSI_SOCKET_set_encryption(GSI_SOCKET *self,
			  const int value)
{
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    self->encryption = value;

    return GSI_SOCKET_SUCCESS;
}


int
GSI_SOCKET_allow_anonymous(GSI_SOCKET *self, const int value)
{
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    self->allow_anonymous = value;

    return GSI_SOCKET_SUCCESS;
}

int
GSI_SOCKET_set_expected_peer_name(GSI_SOCKET *self,
				  const char *name)
{
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    if (self->peer_name != NULL)
    {
	self->error_string = strdup("Already connected to peeer");
	return GSI_SOCKET_ERROR;
    }
    
    if (name == NULL)
    {
	self->error_string = strdup("Bad name");
	return GSI_SOCKET_ERROR;
    }
    
    self->expected_peer_name = strdup(name);

    if (self->expected_peer_name == NULL)
    {
	self->error_number = errno;
	return GSI_SOCKET_ERROR;
    }

    return GSI_SOCKET_SUCCESS;
}  

/* XXX This routine really needs a complete overhaul */
int
GSI_SOCKET_use_creds(GSI_SOCKET *self,
		     const char *creds)
{
    int return_code = GSI_SOCKET_ERROR;
    
    if (creds == NULL)
    {
	/* XXX Do nothing for now */
	return_code = GSI_SOCKET_SUCCESS;
    }
    else
    {
        return_code = (mysetenv("X509_USER_PROXY", creds, 1) == -1) ? GSI_SOCKET_ERROR : GSI_SOCKET_SUCCESS;
    }

    return return_code;
}

#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
static SSL_CTX *
create_minimal_context(char *certdir)
{
   SSL_CTX *ctx;

   ctx = SSL_CTX_new(SSLv3_method()); /* same as gssapi_ssleay */
   if (ctx != NULL) {
      SSL_CTX_set_options(ctx, 0); /* no options */
      SSL_CTX_sess_set_cache_size(ctx, 5); /* set small session-id cache */
      SSL_CTX_load_verify_locations(ctx, NULL, certdir);
   }
   return ctx;
}

static void *
my_ssl_init(int verify, int peer_has_proxy, int allow_anonymous)
{
    char			*certfile = NULL, *keyfile = NULL;
    char			*certdir = NULL, *userproxy = NULL;
    int 			(*pw_cb)() = NULL;
    int				load_err = 0;
    proxy_cred_desc		*cred_handle;

    myproxy_get_filenames(NULL,1,NULL,&certdir,&userproxy,&certfile,&keyfile);
    cred_handle = proxy_cred_desc_new();

    /* load credentials if they're available */
     pw_cb = proxy_password_callback_no_prompt;
#ifdef GSI_NEW
    if (certfile!=NULL)
	load_err = proxy_load_user_cert(cred_handle,certfile,NULL,
					NULL);
    if (keyfile!=NULL && !load_err)
	load_err = proxy_load_user_key(cred_handle,keyfile,pw_cb,
				       NULL);
    if (!load_err) {
	if (!strcmp(certfile, keyfile)) {
	    if (cred_handle->cert_chain == NULL) {
		cred_handle->cert_chain = sk_new_null();
	    }
	    proxy_load_user_proxy(cred_handle->cert_chain,certfile,
					     NULL);
	}
	proxy_init_cred(cred_handle,pw_cb,NULL);
    }
	
#else
    if ((certfile!=NULL) && (keyfile!=NULL)) {
	load_err = proxy_load_user_cert(cred_handle,certfile,NULL);
	if (!load_err)
	    load_err = proxy_load_user_key(cred_handle,keyfile,pw_cb);
    }
    else
	if (userproxy==NULL) {
	    if (certfile!=NULL)
		load_err = proxy_load_user_cert(cred_handle,certfile,
						NULL);
	    if (keyfile!=NULL && !load_err)
		load_err = proxy_load_user_key(cred_handle,keyfile,
					       pw_cb);
	}
    if (!load_err)
	proxy_init_cred(cred_handle);
#endif


    /* if we failed to load a credential above */
    if ((cred_handle->gs_ctx == NULL || 
	 !SSL_CTX_check_private_key(cred_handle->gs_ctx) ||
	 load_err)) {
	if (cred_handle->ucert != NULL) {
	    X509_free(cred_handle->ucert);
	    cred_handle->ucert = NULL;
	}
	if (cred_handle->upkey != NULL) {
	    EVP_PKEY_free(cred_handle->upkey);
	    cred_handle->upkey = NULL;
	}
	if (cred_handle->gs_ctx != NULL) {
	    SSL_CTX_free(cred_handle->gs_ctx);
	    cred_handle->gs_ctx = NULL;
	}

	if (allow_anonymous) {
	    cred_handle->gs_ctx = create_minimal_context(certdir);
	} else {
	    verror_put_string("Failed to load credential.");
	    if (peer_has_proxy) {
		verror_put_string("A valid service credential is required.");
	    } else {
		verror_put_string("Run grid-proxy-init or myproxy-get-delegation first.");
	    }
	}
    }

    if (cred_handle->gs_ctx != NULL) {
	SSL_CTX_set_verify(cred_handle->gs_ctx,verify,
			   (peer_has_proxy==0)?NULL:proxy_verify_callback);
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
	SSL_CTX_set_purpose(cred_handle->gs_ctx,X509_PURPOSE_ANY);
	SSL_CTX_set_session_id_context(cred_handle->gs_ctx,
				       "MYPROXY",
				       strlen("MYPROXY"));
#endif
    }

    if (certfile) free(certfile);
    if (keyfile) free(keyfile);
    if (certdir) free(certdir);
    if (userproxy) free(userproxy);
    return cred_handle;
}

static int
my_memccmp(unsigned char *s1, unsigned char *s2, unsigned int n)
{
    int i;

    for (i=0; i < n; i++, s1++, s2++) {
	if (toupper(*s1) != toupper(*s2)) {
	    return 1;
	}
    }
    return 0;
}
#endif

int
GSI_SOCKET_authentication_init(GSI_SOCKET *self)
{
    char			*server_name = NULL;
    int				token_status;
    struct sockaddr_in		server_addr;
    int				server_addr_len = sizeof(server_addr);
    struct hostent		*server_info;
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    X509			*peer = NULL;
#else
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    OM_uint32			req_flags = 0, ret_flags = 0;
#endif
    int				return_value = GSI_SOCKET_ERROR;
    
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    self->cred_handle = my_ssl_init(SSL_VERIFY_PEER, 0, self->allow_anonymous);

    if (self->cred_handle == NULL || self->cred_handle->gs_ctx == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    self->ssl_context = ((proxy_cred_desc *)self->cred_handle)->gs_ctx;
    self->ssl = SSL_new(self->ssl_context);
    if (self->ssl == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    /* Set method same as gssapi_ssleay. */
    SSL_set_ssl_method(self->ssl,SSLv3_method());

    SSL_set_fd(self->ssl, self->sock);
    if (SSL_connect(self->ssl) <= 0)
    {
	return GSI_SOCKET_ERROR;
    }

#if 0
    /* TODO: Display this message when running in debug mode. */
    {
	char *cipher;
	cipher = SSL_get_cipher(self->ssl);
	if (cipher) {
	    fprintf(stderr, "SSL encrypting with cipher %s.\n", cipher);
	} else {
	    fprintf(stderr, "Warning: SSL_get_cipher() failed!\n");
	}
    }
#endif

    /*
     * For compatibility with Globus GSSAPI: send "0" indicating we don't
     * want to perform delegation.
     */
    if (SSL_write(self->ssl, "0", 1) != 1) {
	return GSI_SOCKET_ERROR;
    }
#else
    if (self->gss_context != GSS_C_NO_CONTEXT)
    {
	self->error_string = strdup("GSI_SOCKET already authenticated");
	goto error;
    }

    self->major_status = globus_gss_assist_acquire_cred(&self->minor_status,
							GSS_C_INITIATE,
							&creds);

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }
#endif

    if (self->expected_peer_name == NULL)
    {
	/*
	 * No expected peer name supplied, use "host/<fqdn>"
	 */

	if (getpeername(self->sock, (struct sockaddr *) &server_addr,
			&server_addr_len) < 0)
	{
	    self->error_number = errno;
	    self->error_string = strdup("Could not get server address");
	    goto error;
	}

	server_info = gethostbyaddr((char *) &server_addr.sin_addr,
				    sizeof(server_addr.sin_addr),
				    server_addr.sin_family);
    
	if ((server_info == NULL) || (server_info->h_name == NULL))
	{
	    self->error_number = errno;
	    self->error_string = strdup("Could not get server hostname");
	    goto error;
	}

	server_name = (char *) malloc(strlen(DEFAULT_SERVICE_NAME) +
				      strlen(server_info->h_name) + 
				      2 /* 1 for '@', 1 for NUL */);

	if (server_name == NULL)
	{
	    self->error_string = strdup("malloc() failed");
	    goto error;
	}

#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
	sprintf(server_name, "%s/%s", DEFAULT_SERVICE_NAME,
#else
	sprintf(server_name, "%s@%s", DEFAULT_SERVICE_NAME,
#endif
		server_info->h_name);
    }
    else 
    {
	/*
	 * Use supplied expected peer name
	 */
	server_name = strdup(self->expected_peer_name);
	
	if (server_name == NULL)
	{
	    self->error_number = errno;
	    goto error;
	}
    }
	
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
	/* Written with reference to compare_name.c in Globus GSSAPI
	   library. */
    peer = SSL_get_peer_certificate(self->ssl);
    if (peer != NULL) {
	X509_NAME * subject = NULL;
	char cn[1024], *ce1, *ce2;
	int le1, le2, name_equal = 0;;

	subject = X509_get_subject_name(peer);
	if (X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn))<= 0) {
	   self->error_string = strdup("Cannot find CN field in server's certificate");
	   return GSI_SOCKET_ERROR;
	}

	ce1 = cn;
	le1 = strlen(ce1);
	if (le1 > 5 && !my_memccmp(ce1, (unsigned char *)"host/", 5)) {
	    ce1 += 5;
	    le1 -= 5;
	}
	ce2 = server_name;
	le2 = strlen(ce2);
	if (le2 > 5 && !my_memccmp(ce2, (unsigned char *)"host/", 5)) {
	    ce2 += 5;
	    le2 -= 5;
	}
	if (le1 == le2 && !my_memccmp(ce1,ce2,le1)) {
	    name_equal = 1;
	} else {
	    while (le1 > 0 && le2 > 0 && 
		   toupper(*ce1) == toupper(*ce2)) {
		le1--;
		le2--;
		ce1++;
		ce2++;
	    }
	    if (le1 >0 && le2 > 0) {
		if ( *ce1 == '.' && *ce2 == '-' ) {
		    while( le2 > 0  && *ce2 != '.') {
			le2--;
			ce2++;
		    }
		    if (le1 == le2 && !my_memccmp(ce1,ce2,le1)) {
			name_equal = 1;
		    }
		} else 
		    if (*ce2 == '.' && *ce1 == '-') {
			while(le1 > 0 && *ce1 != '.') { 
			    le1--;
			    ce1++; 
			}
			if (le1 == le2 && !my_memccmp(ce1,ce2,le1)) {
			    name_equal = 1;
			}
		    }
	    }
	}
	
	if (!name_equal) {
	    self->error_string =
		my_snprintf("Server authentication failed.\n"
			    "Expected target subject name=\"%s\"\n"
			    "Target returned subject name=\"%s\"\n"
			    "If target name is acceptable, set MYPROXY_SERVER_DN environment variable\n"
			    "to \"%s\" and try again.",
			    server_name, cn, cn);
	    return GSI_SOCKET_ERROR;
	}

    } else {
	self->error_string = strdup("Server authentication failed");
	return GSI_SOCKET_ERROR;
    }
#else
    req_flags |= GSS_C_REPLAY_FLAG;
    req_flags |= GSS_C_MUTUAL_FLAG;
    if (self->encryption) {
      req_flags |= GSS_C_CONF_FLAG;
    }

    self->major_status =
	globus_gss_assist_init_sec_context(&self->minor_status,
					   creds,
					   &self->gss_context,
					   server_name,
					   req_flags,
					   &ret_flags,
					   &token_status,
					   assist_read_token,
					   &self->sock,
					   assist_write_token,
					   &self->sock);

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }

    /* Verify that all service requests were honored. */
    if ((req_flags & ret_flags) != req_flags) {
      self->error_string =
	strdup("GSI_SOCKET requested service not supported");
      goto error;
    }
#endif

    /* Success */
    self->peer_name = server_name;
    server_name = NULL;		/* To prevent free() below */

    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    if (server_name != NULL)
    {
	free(server_name);
    }
    
#if !defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    if (creds != GSS_C_NO_CREDENTIAL)
    {
	OM_uint32 minor_status;
	
	gss_release_cred(&minor_status, &creds);
    }
#endif
    
    return return_value;
}


#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
int
GSI_SOCKET_authentication_accept(GSI_SOCKET *self)
{
    int				return_value = GSI_SOCKET_ERROR, tmp;
    char			*certdir = NULL, deleg_flag;
#ifdef GSI_NEW
    proxy_verify_ctx_desc	verify_ctx_area;
#endif
    proxy_verify_desc		verify_area;
    X509			*peer = NULL;


    if (self == NULL)
    {	
	return GSI_SOCKET_ERROR;
    }

    self->cred_handle = my_ssl_init(SSL_VERIFY_PEER, 1, 0);

    if (self->cred_handle == NULL || self->cred_handle->gs_ctx == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    self->ssl_context = ((proxy_cred_desc *)self->cred_handle)->gs_ctx;
    self->ssl = SSL_new(self->ssl_context);
    if (self->ssl == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    /* Set method & options same as gssapi_ssleay */
    SSL_set_ssl_method(self->ssl,SSLv23_method());
    SSL_set_options(self->ssl,SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1);
    
    myproxy_get_filenames(NULL,1,NULL,&certdir,NULL,NULL,NULL);
#ifdef GSI_NEW
    proxy_verify_ctx_init(&verify_ctx_area);
    proxy_verify_init(&verify_area,&verify_ctx_area);
    SSL_set_ex_data(self->ssl, PVD_SSL_EX_DATA_IDX, (char *)&verify_area);
    if (certdir!=NULL) verify_ctx_area.certdir=strdup(certdir);
#else
    proxy_init_verify(&verify_area);
    SSL_set_app_data(self->ssl,(char *)&verify_area);
    if (certdir!=NULL) verify_area.certdir=strdup(certdir);
#endif

    SSL_set_accept_state(self->ssl);
    SSL_set_fd(self->ssl, self->sock);
    tmp = SSL_accept(self->ssl);
    if (tmp < 0) {
	int err;
	unsigned long errcode;
	err = SSL_get_error(self->ssl, tmp);
	switch (err) {
	case SSL_ERROR_NONE:
	    self->error_string = strdup("SSL_accept() failed: no error");
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    self->error_string =
		strdup("SSL_accept() failed: connection closed");
	    break;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
/*	case SSL_ERROR_WANT_ACCEPT: */
	    self->error_string =
		strdup("SSL_accept() failed: data not ready");
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    self->error_string =
		strdup("SSL_accept() failed: x509 lookup error");
	    break;
	case SSL_ERROR_SYSCALL:
	    self->error_string =
		strdup("SSL_accept() failed: x509 lookup error");
	    break;
	case SSL_ERROR_SSL:
	    self->error_string =
		strdup("SSL_accept() failed: protocol error");
	    break;
	default:
	    self->error_string = strdup("SSL_accept() failed");
	    break;
	}
	return GSI_SOCKET_ERROR;
    }

    /*
     * For compatibility with Globus GSSAPI: receive the delegation flag
     * message.  From myproxy clients, the flag should be "0", indicating
     * no delegation.
     */
    if (SSL_read(self->ssl, &deleg_flag, 1) != 1) {
	self->error_string = strdup("SSL_read() failed.  Client disconnected during SSL negotiation?");
	return GSI_SOCKET_ERROR;
    }

    peer = SSL_get_peer_certificate(self->ssl);
    if (peer != NULL) {
	char buf[1024];
	X509_NAME *subject;
	subject = X509_NAME_dup(X509_get_subject_name(peer));
	proxy_get_base_name(subject); /* drop /CN-proxy entries */
	X509_NAME_oneline(subject, buf, sizeof(buf));
	X509_NAME_free(subject);
	self->peer_name = strdup(buf);
    } else {
	self->peer_name = strdup("anonymous");
    }

#if GSI_NEW
    proxy_verify_release(&verify_area);
    proxy_verify_ctx_release(&verify_ctx_area);
#else
    proxy_release_verify(&verify_area);
#endif

    if (certdir) free(certdir);
    return GSI_SOCKET_SUCCESS;
}
#else
int
GSI_SOCKET_authentication_accept(GSI_SOCKET *self)
{
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    int				token_status;
    int				return_value = GSI_SOCKET_ERROR;


    if (self == NULL)
    {	
	return GSI_SOCKET_ERROR;
    }

    if (self->gss_context != GSS_C_NO_CONTEXT)
    {
	self->error_string = strdup("GSI_SOCKET already authenticated");
	goto error;
    }
	
    self->major_status = globus_gss_assist_acquire_cred(&self->minor_status,
							GSS_C_ACCEPT,
							&creds);

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }
    
    self->major_status =
	globus_gss_assist_accept_sec_context(&self->minor_status,
					     &self->gss_context,
					     creds,
					     &self->peer_name,
					     NULL, /* ret_flags */
					     NULL, /* u2u flag */
					     &token_status,
					     NULL, /* Delegated creds
						    * added in Globus 1.1.3
						    */
					     assist_read_token,
					     &self->sock,
					     assist_write_token,
					     &self->sock);

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }
    
    /* Success */
    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    if (creds != GSS_C_NO_CREDENTIAL)
    {
	OM_uint32 minor_status;

	gss_release_cred(&minor_status, &creds);
    }
    
    return return_value;
 }
#endif

int
GSI_SOCKET_get_client_name(GSI_SOCKET *self,
			   char *buffer,
			   const int buffer_len)
{
    int return_value = GSI_SOCKET_ERROR;
    
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }
    
    if (buffer == NULL)
    {
	self->error_number = EINVAL;
	return GSI_SOCKET_ERROR;
    }
    
    if (self->peer_name == NULL)
    {
	self->error_string = strdup("Client not authenticated");
	goto error;
    }
    
    return_value = my_strncpy(buffer, self->peer_name, buffer_len);

    if (return_value == -1)
    {
	return_value = GSI_SOCKET_TRUNCATED;
	goto error;
    }

    /* SUCCESS */
    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    return return_value;
}


int
GSI_SOCKET_write_buffer(GSI_SOCKET *self,
			const char *buffer,
			const size_t buffer_len)
{
    int return_value = GSI_SOCKET_ERROR;
    
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }
    
    if ((buffer == NULL) || (buffer_len == 0))
    {
	return 0;
    }
    
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    if (self->ssl == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    return write_token(self->ssl, buffer, buffer_len);
#else
    if (self->gss_context == GSS_C_NO_CONTEXT)
    {
	/* No context established, just send in the clear */
	return_value = write_token(self->sock, buffer, buffer_len);
	
	if (return_value == -1)
	{
	    self->error_number = errno;
	    goto error;
	}
    }
    else
    {
	/* Encrypt buffer before sending */
	gss_buffer_desc unwrapped_buffer;
	gss_buffer_desc wrapped_buffer;
	int conf_state;
	
	unwrapped_buffer.value = (char *) buffer;
	unwrapped_buffer.length = buffer_len;
	
	self->major_status = gss_wrap(&self->minor_status,
				      self->gss_context,
				      self->encryption,
				      GSS_C_QOP_DEFAULT,
				      &unwrapped_buffer,
				      &conf_state,
				      &wrapped_buffer);
	
	if (self->major_status != GSS_S_COMPLETE)
	{
	    goto error;
	}
	
	if (self->encryption && !conf_state) {
	  self->error_string = strdup("GSI_SOCKET failed to encrypt");
	  goto error;
	}
	
	return_value = write_token(self->sock, wrapped_buffer.value,
				   wrapped_buffer.length);
	
	if (return_value == -1)
	{
	    self->error_number = errno;
	    gss_release_buffer(&self->minor_status, &wrapped_buffer);
	    goto error;
	}
	
	gss_release_buffer(&self->minor_status, &wrapped_buffer);
    }
#endif
  error:
    return return_value;
}

int
GSI_SOCKET_read_buffer(GSI_SOCKET *self,
		       char *buffer,
		       size_t buffer_len)
{
    int return_value = GSI_SOCKET_ERROR;
    
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }
    
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    if (self->ssl == NULL)
    {
	return GSI_SOCKET_ERROR;
    }
#endif

    if (buffer == NULL)
    {
	self->error_number = EINVAL;
	return GSI_SOCKET_ERROR;
    }

    if (self->input_buffer == NULL) 
    {
	/* No data in input buffer, so read it */

#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
	return_value = read_token(self->ssl,
#else
	return_value = read_token(self->sock,
#endif
				  &(self->input_buffer),
				  (size_t *)&(self->input_buffer_length));
	
	if (return_value == -1)
	{
	    self->error_number = errno;
	    goto error;
	}

#if !defined(SUPPORT_SSL_ANONYMOUS_AUTH)
	if (self->gss_context != GSS_C_NO_CONTEXT)
	{
	    /* Need to unwrap read data */
	    gss_buffer_desc unwrapped_buffer;
	    gss_buffer_desc wrapped_buffer;
	    int conf_state;
	    gss_qop_t qop_state;

	    wrapped_buffer.value = self->input_buffer;
	    wrapped_buffer.length = self->input_buffer_length;

	    self->major_status = gss_unwrap(&self->minor_status,
					    self->gss_context,
					    &wrapped_buffer,
					    &unwrapped_buffer,
					    &conf_state,
					    &qop_state);

	    free(self->input_buffer);
	    self->input_buffer = NULL;
	    self->input_buffer_length = 0;

	    if (self->major_status != GSS_S_COMPLETE)
	    {
		goto error;
	    }
	
	    self->input_buffer = unwrapped_buffer.value;
	    self->input_buffer_length = unwrapped_buffer.length;
	}
#endif

	self->input_buffer_index = self->input_buffer;
    }
    
    /*
     * Now copy data from input_buffer to user buffer
     */
    if (self->input_buffer_length > buffer_len) 
    {
	/* User buffer is too small */
	memcpy(buffer, self->input_buffer_index, buffer_len);
	self->input_buffer_index = &self->input_buffer_index[buffer_len];
	self->input_buffer_length -= buffer_len;
	
	return_value = GSI_SOCKET_TRUNCATED;
	
    }
    else
    {
	/* User buffer is large enough to hold all data */
	memcpy(buffer, self->input_buffer_index, self->input_buffer_length);
	return_value = self->input_buffer_length;
	    
	/* Input buffer all read, so deallocate */
	free(self->input_buffer);
	self->input_buffer = NULL;
	self->input_buffer_index = NULL;
	self->input_buffer_length = 0;
    }

  error:        
    return return_value;
}

int GSI_SOCKET_read_token(GSI_SOCKET *self,
			  unsigned char **pbuffer,
			  size_t *pbuffer_len)
{
    int			bytes_read;
    unsigned char	*buffer;
    int			buffer_len;
    int			return_status = GSI_SOCKET_ERROR;
    
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    bytes_read = read_token(self->ssl,
#else
    bytes_read = read_token(self->sock,
#endif
			    (char **) &buffer,
			    &buffer_len);
    
    if (bytes_read == -1)
    {
	self->error_number = errno;
	goto error;
    }
    
#if !defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    if (self->gss_context != GSS_C_NO_CONTEXT)
    {
	/* Need to unwrap read data */
	gss_buffer_desc unwrapped_buffer;
	gss_buffer_desc wrapped_buffer;
	int conf_state;
	gss_qop_t qop_state;

	wrapped_buffer.value = buffer;
	wrapped_buffer.length = buffer_len;

	self->major_status = gss_unwrap(&self->minor_status,
					self->gss_context,
					&wrapped_buffer,
					&unwrapped_buffer,
					&conf_state,
					&qop_state);

	free(buffer);

	if (self->major_status != GSS_S_COMPLETE)
	{
	    goto error;
	}
	
	buffer = unwrapped_buffer.value;
	buffer_len = unwrapped_buffer.length;
    }
#endif

    /* Success */
    *pbuffer = buffer;
    *pbuffer_len = buffer_len;
    return_status = GSI_SOCKET_SUCCESS;
    
  error:
    return return_status;}

void GSI_SOCKET_free_token(unsigned char *buffer)
{
    if (buffer != NULL)
    {
	free(buffer);
    }
}

int GSI_SOCKET_delegation_init_ext(GSI_SOCKET *self,
				   const char *source_credentials,
				   int flags,
				   int lifetime,
				   const void *restrictions)
{
    int				return_value = GSI_SOCKET_ERROR;
    SSL_CREDENTIALS		*creds = NULL;
    SSL_PROXY_RESTRICTIONS	*proxy_restrictions = NULL;
    unsigned char		*input_buffer = NULL;
    int				input_buffer_length;
    unsigned char		*output_buffer = NULL;
    int				output_buffer_length;
    

    if (self == NULL)
    {
	goto error;
    }

#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    if (self->ssl_context == NULL)
#else
    if (self->gss_context == GSS_C_NO_CONTEXT)
#endif
    {
	self->error_string = strdup("GSI_SOCKET not authenticated");
	goto error;
    }

    /*
     * None of these are currently supported.
     */
    if ((flags != 0) ||
	(restrictions != NULL))
    {
	self->error_number = EINVAL;
	goto error;
    }

    /*
     * Load proxy we are going to use to sign delegation
     */
    creds = ssl_credentials_new();
    
    if (creds == NULL)
    {
	GSI_SOCKET_set_error_from_verror(self);
	goto error;
    }
    
    if (ssl_proxy_load_from_file(creds, source_credentials,
				 NULL /* No pass phrase */) == SSL_ERROR)
    {
	GSI_SOCKET_set_error_from_verror(self);
	goto error;
    }

    /*
     * Read the certificate request from the client
     */
    if (GSI_SOCKET_read_token(self, &input_buffer,
			      &input_buffer_length) == GSI_SOCKET_ERROR)
    {
	goto error;
    }

    /*
     * Set up the restrictions on the proxy
     */
    proxy_restrictions = ssl_proxy_restrictions_new();
    
    if (proxy_restrictions == NULL)
    {
	goto error;
    }
    
    if (ssl_proxy_restrictions_set_lifetime(proxy_restrictions,
					    (long) lifetime) == SSL_ERROR)
    {
	goto error;
    }
    
    /*
     * Sign the request
     */
    if (ssl_proxy_delegation_sign(creds,
				  proxy_restrictions,
				  input_buffer,
				  input_buffer_length,
				  &output_buffer,
				  &output_buffer_length) == SSL_ERROR)
    {
	GSI_SOCKET_set_error_from_verror(self);
	goto error;
    }
    
    /*
     * Write the proxy certificate back to user
     */
    if (GSI_SOCKET_write_buffer(self,
				output_buffer,
				output_buffer_length) == GSI_SOCKET_ERROR)
    {
	goto error;
    }

    /* Success */
    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    if (input_buffer != NULL)
    {
	GSI_SOCKET_free_token(input_buffer);
    }
    
    if (output_buffer != NULL)
    {
	ssl_free_buffer(output_buffer);
    }
    
    if (creds != NULL)
    {
	ssl_credentials_destroy(creds);
    }

    if (proxy_restrictions != NULL)
    {
	ssl_proxy_restrictions_destroy(proxy_restrictions);
    }
    
    return return_value;
}


int
GSI_SOCKET_delegation_accept_ext(GSI_SOCKET *self,
				 char *delegated_credentials,
				 int delegated_credentials_len)
{
    int			return_value = GSI_SOCKET_ERROR;
    SSL_CREDENTIALS	*creds = NULL;
    unsigned char	*output_buffer = NULL;
    int			output_buffer_len;
    unsigned char	*input_buffer = NULL;
    int			input_buffer_len;
    char		filename[L_tmpnam];
    
    if (self == NULL)
    {	
	return GSI_SOCKET_ERROR;
    }

    if ((delegated_credentials == NULL) ||
	(delegated_credentials_len == 0))
    {
	self->error_number = EINVAL;
	goto error;
    }
    
#if defined(SUPPORT_SSL_ANONYMOUS_AUTH)
    if (self->ssl_context == NULL)
#else
    if (self->gss_context == GSS_C_NO_CONTEXT)
#endif
    {
	self->error_string = strdup("GSI_SOCKET not authenticated");
	return GSI_SOCKET_ERROR;
    }

    /* Generate proxy certificate request and send */
    if (ssl_proxy_delegation_init(&creds, &output_buffer, &output_buffer_len,
				  0 /* default number of bits */,
				  NULL /* No callback */) == SSL_ERROR)
    {
	GSI_SOCKET_set_error_from_verror(self);
	goto error;
    }
    
    if (GSI_SOCKET_write_buffer(self, output_buffer,
				output_buffer_len) == GSI_SOCKET_ERROR)
    {
	goto error;
    }
    
    /* Now read the signed certificate */
    if (GSI_SOCKET_read_token(self, &input_buffer,
			      &input_buffer_len) == GSI_SOCKET_ERROR)
    {
	goto error;
    }
    
    if (ssl_proxy_delegation_finalize(creds, input_buffer,
				      input_buffer_len) == SSL_ERROR)
    {
	GSI_SOCKET_set_error_from_verror(self);
	goto error;
    }
    
    /* Now store the credentials */
    if (tmpnam(filename) == NULL)
    {
	self->error_number = errno;
	self->error_string = strdup("tmpnam() failed");
	goto error;
    }
    
    if (ssl_proxy_store_to_file(creds, filename,
				NULL /* No pass phrase */) == SSL_ERROR)
    {
	GSI_SOCKET_set_error_from_verror(self);
	goto error;
    }
    
    if (delegated_credentials != NULL)
    {
	strncpy(delegated_credentials, filename, delegated_credentials_len);
    }
    
    /* Success */
    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    if (creds != NULL)
    {
	ssl_credentials_destroy(creds);
    }
    
    if (input_buffer != NULL)
    {
	GSI_SOCKET_free_token(input_buffer);
    }
    
    if (output_buffer != NULL)
    {
	ssl_free_buffer(output_buffer);
    }

    return return_value;
}
