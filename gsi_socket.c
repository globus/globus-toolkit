/*
 * gsi_socket.c
 *
 * See gsi_socket.h for documentation.
 */

#include "gsi_socket.h"

#include <globus_gss_assist.h>

#include <gssapi.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>

struct _gsi_socket 
{
    gss_ctx_id_t		gss_context;
    int				sock;
    int				encryption;	/* Boolean */
    /* All these variables together indicate the last error we saw */
    char			*error_string;
    int				error_number;
    OM_uint32			major_status;
    OM_uint32			minor_status;
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
	    chars = snprintf(buffer, bufferlen, error_string.value);
	    
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

/*
 * read_all()
 *
 * Read all the requested bytes into the requested buffer.
 */
static int
read_all(const int sock,
	 char *buffer,
	 const int nbytes)
{
    int total_bytes_read = 0;
    int bytes_read;
    
    assert(buffer != NULL);
    
    while (total_bytes_read < nbytes)
    {
	bytes_read = read(sock, &buffer[total_bytes_read], 
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
write_all(const int sock,
	  const char *buffer,
	  const int nbytes)
{
    int total_bytes_written = 0;
    int bytes_written;
    
    assert(buffer != NULL);
    
    while (total_bytes_written < nbytes)
    {
	bytes_written = write(sock, &buffer[total_bytes_written], 
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
 * read_length()
 *
 * Read and return a four byte MSB length from socket and return it.
 */
static int
read_length(const int sock)
{
    unsigned char length_array[4];
    int length = 0;
    
    if (read_all(sock, length_array, sizeof(length_array)) < 0)
    {
	return -1;
    }
    
    length |= length_array[0] << 24;
    length |= length_array[1] << 16;
    length |= length_array[2] << 8;
    length |= length_array[3];
    
    return length;
}

/*
 * write_length()
 *
 * Write a four byte MSB length to the given socket.
 */
static int
write_length(const int sock,
	     const int length)
{
    unsigned char length_array[4];
    
    length_array[0] = (length >> 24) & 0xFF;
    length_array[1] = (length >> 16) & 0xFF;
    length_array[2] = (length >> 8) & 0xFF;
    length_array[3] = length & 0xFF;
    
    return write_all(sock, length_array, sizeof(length_array));
}


/*
 * read_token()
 *
 * Read and allocate a token from the given socket.
 */
static int
read_token(const int sock,
	   char **p_buffer,
	   size_t *p_buffer_size)
{
    int buffer_len;
    
    assert(p_buffer != NULL);
    assert(p_buffer_size != NULL);
    
    buffer_len = read_length(sock);
    
    if (buffer_len == -1)
    {
	return -1;
    }
    
    *p_buffer = malloc(buffer_len);
    
    if (*p_buffer == NULL)
    {
	return -1;
    }
    
    if (read_all(sock, *p_buffer, buffer_len) < 0)
    {
	free(*p_buffer);
	*p_buffer = NULL;
	return -1;
    }
    
    *p_buffer_size = (size_t) buffer_len;
    
    return buffer_len;
}

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

/*
 * write_token()
 *
 * Write a token to the the given socket.
 *
 * Returns 0 on success, -1 on error.
 */
static int
write_token(const int sock,
	    const char *buffer,
	    const size_t buffer_size)
{
    int return_value;

    assert(buffer != NULL);
    
    if (write_length(sock, buffer_size) < 0)
    {
	return -1;
    }
    
    return_value = write_all(sock, buffer, buffer_size);

    return (return_value == -1 ? -1 : 0);
}


static int
assist_write_token(void *sock,
		   void *buffer,
		   size_t buffer_size)
{
    assert(sock != NULL);
    assert(buffer != NULL);
    
    return write_token(*((int *) sock), (char *) buffer, buffer_size);
}

/*
 * Wrapper around setenv() function
 */
static int
mysetenv(const char *var,
	 const char *value,
	 int override)
{
#ifdef HAVE_SETENV

    return setenv(name, value, overwrite);

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


static void
myunsetenv(const char *var)

{
#ifdef HAVE_UNSETENV
    unsetenv(var);

    return;
    
#else /* !HAVE_UNSETENV */
    extern char **environ;
    char **p1 = environ;	/* New array list */
    char **p2 = environ;	/* Current array list */
    int len = strlen(var);

    assert(var != NULL);
    
    /*
     * Walk through current environ array (p2) copying each pointer
     * to new environ array (p1) unless the pointer is to the item
     * we want to delete. Copy happens in place.
     */
    while (*p2) {
	if ((strncmp(*p2, var, len) == 0) &&
	    ((*p2)[len] == '=')) {
	    /*
	     * *p2 points at item to be deleted, just skip over it
	     */
	    p2++;
	} else {
	    /*
	     * *p2 points at item we want to save, so copy it
	     */
	    *p1 = *p2;
	    p1++;
	    p2++;
	}
    }

    /* And make sure new array is NULL terminated */
    *p1 = NULL;
#endif /* HAVE_UNSETENV */
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
    
    self->gss_context = GSS_C_NO_CONTEXT;
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
    
    if (self->gss_context != GSS_C_NO_CONTEXT)
    {
	gss_buffer_desc output_token_desc  = GSS_C_EMPTY_BUFFER;

	gss_delete_sec_context(&self->minor_status,
			       &self->gss_context,
			       &output_token_desc);
	
	/* XXX Should deal with output_token_desc here */
    }

    if (self->input_buffer != NULL)
    {
	free(self->input_buffer);
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
	return snprintf(buffer, bufferlen, "GSI_SOCKET is NULL");
    }

    if (self->error_string != NULL)
    {
	chars = snprintf(buffer, bufferlen, self->error_string);
	
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
	chars = snprintf(buffer, bufferlen, strerror(self->error_number));

	if (chars == -1)
	{
	    goto truncated;
	}
		
	total_chars += chars;
	buffer = &buffer[chars];
	bufferlen -= chars;
    }

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
    }

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
    self->major_status = 0;
    self->minor_status = 0;
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
GSI_SOCKET_use_creds(GSI_SOCKET *self,
		     const char *creds)
{
    int return_code = GSI_SOCKET_ERROR;
    
#ifdef GSI_SOCKET_SSLEAY
    if (creds == NULL)
    {
	/* Unset environment variables so libs use default */
	myunsetenv("X509_USER_PROXY");
	myunsetenv("X509_USER_KEY");
	myunsetenv("X509_USER_CERT");
	return_code = GSI_SOCKET_SUCCESS;
    }
    else
    {
	return_code = (mysetenv("X509_USER_PROXY", creds, 1) == -1) ?
	    GSI_SOCKET_ERROR : GSI_SOCKET_SUCCESS;
    }
#endif /* GSI_SOCKET_SSLEAY */

    return return_code;
}

int
GSI_SOCKET_authentication_init(GSI_SOCKET *self)
{
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    char			*server_name = NULL;
    int				token_status;
    struct sockaddr_in		server_addr;
    int				server_addr_len = sizeof(server_addr);
    struct hostent		*server_info;
    OM_uint32			req_flags = 0;
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
							GSS_C_INITIATE,
							&creds);

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }

    /*
     * Get the FQDN of server from the socket
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

    sprintf(server_name, "%s@%s", DEFAULT_SERVICE_NAME, server_info->h_name);
    
    req_flags |= GSS_C_REPLAY_FLAG;
    req_flags |= GSS_C_MUTUAL_FLAG;

    self->major_status =
	globus_gss_assist_init_sec_context(&self->minor_status,
					   creds,
					   &self->gss_context,
					   server_name,
					   req_flags,
					   NULL, /* ret_flags */
					   &token_status,
					   assist_read_token,
					   &self->sock,
					   assist_write_token,
					   &self->sock);

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }

    /* Success */
    self->peer_name = server_name;
    server_name = NULL;		/* To prevent free() below */

    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    if (server_name != NULL)
    {
	free(server_name);
    }
    
    if (creds != GSS_C_NO_CREDENTIAL)
    {
	OM_uint32 minor_status;
	
	gss_release_cred(&minor_status, &creds);
    }
    
    return return_value;
}


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
    
    return_value = snprintf(buffer, buffer_len, self->peer_name);

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
    
    if (buffer == NULL)
    {
	self->error_number = EINVAL;
	return GSI_SOCKET_ERROR;
    }

    if (self->input_buffer == NULL) 
    {
	/* No data in input buffer, so read it */

	return_value = read_token(self->sock,
				  &(self->input_buffer),
				  &(self->input_buffer_length));
	
	if (return_value == -1)
	{
	    self->error_number = errno;
	    goto error;
	}

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
		OM_uint32 minor_status;
	    
		gss_release_buffer(&minor_status, &wrapped_buffer);
		goto error;
	    }
	
	    self->input_buffer = unwrapped_buffer.value;
	    self->input_buffer_length = unwrapped_buffer.length;
	}

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

int GSI_SOCKET_delegation_init_ext(GSI_SOCKET *self,
				   const char *source_credentials,
				   int flags,
				   int lifetime,
				   const void *restrictions)
{
    gss_ctx_id_t		tmp_gss_context = GSS_C_NO_CONTEXT;
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    int				token_status;
    OM_uint32			req_flags = 0;
    int				return_value = GSI_SOCKET_ERROR;
    gss_buffer_desc		output_token;
    gss_buffer_desc		input_token;
    gss_buffer_desc		*input_token_ptr = GSS_C_NO_BUFFER;

#ifdef GSI_SOCKET_SSLEAY
    char			*x509_user_proxy_save = NULL;
#endif /* GSI_SOCKET_SSLEAY */

    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    if (self->gss_context == GSS_C_NO_CONTEXT)
    {
	self->error_string = strdup("GSI_SOCKET not authenticated");
	return GSI_SOCKET_ERROR;
    }

    /*
     * None of these are currently supported.
     */
    if ((flags != 0) ||
	(lifetime != 0) ||
	(restrictions != NULL))
    {
	self->error_number = EINVAL;
	return GSI_SOCKET_ERROR;
    }

    /*
     * This this is all currently a hack. What we do is reauthenticate
     * and delegate as this is currently the only way to do this through
     * the gssapi.
     */

#ifdef GSI_SOCKET_SSLEAY
    if (source_credentials != NULL)
    {
	/*
	 * Set X509_USER_PROXY so that we are using the requested
	 * credentials.
	 */
	x509_user_proxy_save = getenv("X509_USER_PROXY");
	mysetenv("X509_USER_PROXY", source_credentials, 1);
    }
#endif /* GSI_SOCKET_SSLEAY */    
	
    self->major_status = globus_gss_assist_acquire_cred(&self->minor_status,
							GSS_C_INITIATE,
							&creds);

#ifdef GSI_SOCKET_SSLEAY
    if (source_credentials != NULL)
    {
	/* Restore the previous setting of X509_USER_PROXY */
	if (x509_user_proxy_save == NULL)
	{
	    myunsetenv("X509_USER_PROXY");
	}
	else
	{
	    mysetenv("X509_USER_PROXY", x509_user_proxy_save, 1);
	}
    }
#endif /* GSI_SOCKET_SSLEAY */

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }

    req_flags |= GSS_C_DELEG_FLAG;

    do {
	OM_uint32 min_stat;
	
	self->major_status =
	    gss_init_sec_context(&self->minor_status,
				 creds,
				 &tmp_gss_context,
				 NULL,	/* No need to do mutual auth */
				 NULL,	/* No mech type specified */
				 req_flags,
				 lifetime,
				 NULL,	/* no channel bindings */
				 input_token_ptr,
				 NULL,	/* ignore mech type */
				 &output_token,
				 NULL,	/* ret_flags */
				 NULL);	/* ignore time_rec */

	if (input_token_ptr != GSS_C_NO_BUFFER)
	{
	    (void) gss_release_buffer(&min_stat, input_token_ptr);
	}

	if ((self->major_status != GSS_S_COMPLETE) &&
	    (self->major_status != GSS_S_CONTINUE_NEEDED))
	{
	    goto error;
	}

	if (output_token.length != 0)
	{
	    if (write_token(self->sock,
			    output_token.value,
			    output_token.length) == -1)
	    {
		goto error;
	    }
	    
	    (void) gss_release_buffer(&min_stat, &output_token);
	}
	  
	if (self->major_status == GSS_S_CONTINUE_NEEDED)
	{
	    if (read_token(self->sock,
			   (char **) &input_token.value,
			   &input_token.length) == -1)
	    {
		goto error;
	    }

	    input_token_ptr = &input_token;
	}
    } while (self->major_status == GSS_S_CONTINUE_NEEDED);

    /* Success */
    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    if (creds != GSS_C_NO_CREDENTIAL)
    {
	OM_uint32 minor_status;
	
	gss_release_cred(&minor_status, &creds);
    }

    if (tmp_gss_context != GSS_C_NO_CONTEXT)
    {
	gss_buffer_desc output_token_desc  = GSS_C_EMPTY_BUFFER;
	OM_uint32 minor_status;

	gss_delete_sec_context(&minor_status,
			       &tmp_gss_context,
			       &output_token_desc);
	
	/* XXX Should deal with output_token_desc here */
    }

    return return_value;
}


int
GSI_SOCKET_delegation_accept_ext(GSI_SOCKET *self,
				 char *delegated_credentials,
				 int delegated_credentials_len)
{
    gss_ctx_id_t		tmp_gss_context = GSS_C_NO_CONTEXT;
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    int				token_status;
    int				return_value = GSI_SOCKET_ERROR;
#ifdef GSI_SOCKET_SSLEAY
    char			*x509_user_deleg_proxy_save = NULL;
#endif /* GSI_SOCKET_SSLEAY */
    char			*delegated_creds;
    
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
    
    if (self->gss_context == GSS_C_NO_CONTEXT)
    {
	self->error_string = strdup("GSI_SOCKET not authenticated");
	return GSI_SOCKET_ERROR;
    }
	
    self->major_status = globus_gss_assist_acquire_cred(&self->minor_status,
							GSS_C_ACCEPT,
							&creds);

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }

#ifdef GSI_SOCKET_SSLEAY
    /* Save current value of X509_USER_DELEG_PROXY */
    x509_user_deleg_proxy_save = getenv("X509_USER_DELEG_PROXY");
#endif /* GSI_SOCKET_SSLEAY */

    self->major_status =
	globus_gss_assist_accept_sec_context(&self->minor_status,
					     &tmp_gss_context,
					     creds,
					     NULL, /* peer name */
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

    
#ifdef GSI_SOCKET_SSLEAY
    /* Get location of delegated proxy and restore X509_USER_DELEG_PROXY */
    delegated_creds = getenv("X509_USER_DELEG_PROXY");
    
    if (x509_user_deleg_proxy_save == NULL)
    {
	myunsetenv("X509_USER_DELEG_PROXY");
    }
    else
    {
	mysetenv("X509_USER_DELEG_PROXY", x509_user_deleg_proxy_save, 1);
    }
#endif /* GSI_SOCKET_SSLEAY */

    if (self->major_status != GSS_S_COMPLETE)
    {
	goto error;
    }

    if (delegated_creds == NULL)
    {
	self->error_string =  strdup("No credentials received.");
	goto error;
    }
    
    if (snprintf(delegated_credentials, delegated_credentials_len,
		 "%s", delegated_creds) == -1)
    {
	self->error_string = strdup("Delegated credentials buffer too small.");
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

    if (tmp_gss_context != GSS_C_NO_CONTEXT)
    {
	gss_buffer_desc output_token_desc  = GSS_C_EMPTY_BUFFER;
	OM_uint32 minor_status;

	gss_delete_sec_context(&minor_status,
			       &tmp_gss_context,
			       &output_token_desc);
	
	/* XXX Should deal with output_token_desc here */
    }

    return return_value;
}
