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
    char			*client_name;
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
    int length_array[4];
    int length = 0;
    
    if (read_all(sock, (char *) length_array, sizeof(length_array)) < 0)
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
    int length_array[4];
    
    length_array[0] = (length >> 24) & 0xFF;
    length_array[1] = (length >> 16) & 0xFF;
    length_array[2] = (length >> 8) & 0xFF;
    length_array[3] = length & 0xFF;
    
    return write_all(sock, (char *) length_array, sizeof(length_array));
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
    
    *((int *)p_buffer_size) = buffer_len;
    
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
    return write_token(*((int *) sock), (char *) buffer, buffer_size);
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

    if (self->client_name != NULL)
    {
	free(self->client_name);
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
	    return -1;
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
	    return -1;
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
	    return -1;
	}
		
	total_chars += chars;
	buffer = &buffer[chars];
	bufferlen -= chars;
    }

    if (self->minor_status)
    {
	chars = append_gss_status(buffer, bufferlen,
				  self->minor_status,
				  GSS_C_MECH_CODE);

	if (chars == -1)
	{
	    return -1;
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
GSI_SOCKET_authentication_init(GSI_SOCKET *self)
{
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    char			*server_name = NULL;
    int				token_status;
    struct sockaddr_in		server_addr;
    int				server_addr_len = sizeof(server_addr);
    struct hostent		*server_info;
    OM_uint32			req_flags = 0;

    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    if (self->gss_context != GSS_C_NO_CONTEXT)
    {
	self->error_string = strdup("GSI_SOCKET already authenticated");
	return GSI_SOCKET_ERROR;
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
    gss_release_cred(&self->minor_status, &creds);
    free(server_name);
    
    return GSI_SOCKET_SUCCESS;
    
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
    
    return GSI_SOCKET_ERROR;
}


int
GSI_SOCKET_authentication_accept(GSI_SOCKET *self)
{
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    int				token_status;


    if (self == NULL)
    {	
	return GSI_SOCKET_ERROR;
    }

    if (self->gss_context != GSS_C_NO_CONTEXT)
    {
	self->error_string = strdup("GSI_SOCKET already authenticated");
	return GSI_SOCKET_ERROR;
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
					     &self->client_name,
					     NULL, /* ret_flags */
					     NULL, /* u2u flag */
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
    gss_release_cred(&self->minor_status, &creds);

    return GSI_SOCKET_SUCCESS;
    
  error:
    if (creds != GSS_C_NO_CREDENTIAL)
    {
	OM_uint32 minor_status;

	gss_release_cred(&minor_status, &creds);
    }
    
    return GSI_SOCKET_ERROR;
}


int
GSI_SOCKET_get_client_name(GSI_SOCKET *self,
			   char *buffer,
			   const int buffer_len)
{
    int return_value;
    
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }
    
    if (buffer == NULL)
    {
	self->error_number = EINVAL;
	return GSI_SOCKET_ERROR;
    }
    
    if (self->client_name == NULL)
    {
	self->error_string = strdup("Client not authenticated");
	return GSI_SOCKET_ERROR;
    }
    
    return_value = snprintf(buffer, buffer_len, self->client_name);

    if (return_value == -1)
    {
	return GSI_SOCKET_TRUNCATED;
    }
    
    return return_value;
}


int
GSI_SOCKET_write_buffer(GSI_SOCKET *self,
			const char *buffer,
			const size_t buffer_len)
{
    int return_value;
    
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

    return return_value;
    
  error:
    return GSI_SOCKET_ERROR;
}

int
GSI_SOCKET_read_buffer(GSI_SOCKET *self,
		       char *buffer,
		       size_t buffer_len)
{
    int return_value;
    
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
	    
	    if (self->major_status != GSS_S_COMPLETE)
	    {
		OM_uint32 minor_status;
	    
		gss_release_buffer(&minor_status, &wrapped_buffer);
		goto error;
	    }
	
	    gss_release_buffer(&self->minor_status, &wrapped_buffer);
	
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
	/* User buffer is large enought to hold all data */
	memcpy(buffer, self->input_buffer_index, self->input_buffer_length);
	return_value = self->input_buffer_length;
	    
	/* Input buffer all read, so deallocate */
	free(self->input_buffer);
	self->input_buffer = NULL;
	self->input_buffer_index = NULL;
	self->input_buffer_length = 0;
    }
        
    return return_value;

  error:
    return GSI_SOCKET_ERROR;
    
}
