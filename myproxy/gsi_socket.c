/*
 * gsi_socket.c
 *
 * See gsi_socket.h for documentation.
 */

#include "gsi_socket.h"
#include "ssl_utils.h"
#include "verror.h"
#include "string_funcs.h"
#include "myproxy_log.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>

#include <gssapi.h>
#include <globus_gss_assist.h>

struct _gsi_socket 
{
    int				sock;
    int				allow_anonymous; /* Boolean */
    /* All these variables together indicate the last error we saw */
    char			*error_string;
    int				error_number;
    gss_ctx_id_t		gss_context;
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
 * read_token()
 *
 * Read and allocate a token from the given socket.
 */
static int
read_token(const int sock,
	   char **p_buffer,
	   size_t *p_buffer_size)
{
    enum header_fields 
    {
	flag                            = 0,
	major_version                   = 1,
	minor_version                   = 2,
	length_high_byte                = 3,
	length_low_byte                 = 4
    };

    char *bufferp;
    unsigned char header[5];
    int data_len;
    int buffer_len;
    

    assert(p_buffer != NULL);
    assert(p_buffer_size != NULL);
    
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

    *p_buffer = malloc(buffer_len);

    if (*p_buffer == NULL)
    {
	return -1;
    }

    bufferp = *p_buffer;
    
    memcpy(bufferp, header, sizeof(header));

    bufferp += sizeof(header);
    
    if (read_all(sock, bufferp, data_len) < 0)
    {
	free(*p_buffer);
	*p_buffer = NULL;
	return -1;
    }
    
    *p_buffer_size = buffer_len;

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
	gss_release_buffer(&self->minor_status, &output_token_desc);
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
	return my_strncpy(buffer, "GSI SOCKET not initialized", bufferlen);
    }

    if (self->error_string != NULL)
    {
	chars = my_strncpy(buffer, self->error_string, bufferlen-1);
	
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
	if (total_chars && bufferlen && *(buffer-1) != '\n') {
	    *buffer = '\n'; buffer++; total_chars++; bufferlen--;
	}

	chars = my_strncpy(buffer, strerror(self->error_number), bufferlen);

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
	if (total_chars && bufferlen && *(buffer-1) != '\n') {
	    *buffer = '\n'; buffer++; total_chars++; bufferlen--;
	}

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
GSI_SOCKET_allow_anonymous(GSI_SOCKET *self, const int value)
{
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    self->allow_anonymous = value;

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

int
GSI_SOCKET_check_creds(GSI_SOCKET *self)
{
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    int				return_value = GSI_SOCKET_ERROR;

    if (self == NULL) {	
	return GSI_SOCKET_ERROR;
    }

    self->major_status = globus_gss_assist_acquire_cred(&self->minor_status,
							GSS_C_BOTH,
							&creds);

    if (self->major_status != GSS_S_COMPLETE) {
	goto error;
    }
    
    /* Success */
    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    if (creds != GSS_C_NO_CREDENTIAL) {
	OM_uint32 minor_status;

	gss_release_cred(&minor_status, &creds);
    }
    
    return return_value;
}

int
GSI_SOCKET_authentication_init(GSI_SOCKET *self, char *accepted_peer_names[])
{
    int				token_status;
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    gss_name_t			server_gss_name = GSS_C_NO_NAME;
    OM_uint32			req_flags = 0, ret_flags = 0;
    int				return_value = GSI_SOCKET_ERROR;
    gss_buffer_desc		gss_buffer = { 0 }, tmp_gss_buffer = { 0 };
    gss_name_t			target_name = GSS_C_NO_NAME;
    gss_OID			target_name_type = GSS_C_NO_OID;
    int				i, rc=0;
    
    if (self == NULL)
    {
	return GSI_SOCKET_ERROR;
    }

    if (accepted_peer_names == NULL ||
	accepted_peer_names[0] == NULL) {
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

    if (self->major_status != GSS_S_COMPLETE) {
	if (self->allow_anonymous) {
	    req_flags |= GSS_C_ANON_FLAG;
	} else {
	    goto error;
	}
    }

    req_flags |= GSS_C_REPLAY_FLAG;
    req_flags |= GSS_C_MUTUAL_FLAG;
    req_flags |= GSS_C_CONF_FLAG;
    req_flags |= GSS_C_INTEG_FLAG;

    self->major_status =
	globus_gss_assist_init_sec_context(&self->minor_status,
					   creds,
					   &self->gss_context,
					   "GSI-NO-TARGET",
					   req_flags,
					   &ret_flags,
					   &token_status,
					   assist_read_token,
					   &self->sock,
					   assist_write_token,
					   &self->sock);

    if (self->major_status != GSS_S_COMPLETE) {
	goto error;
    }

    
    /* Verify that all service requests were honored. */
    req_flags &= ~(GSS_C_ANON_FLAG); /* GSI GSSAPI doesn't set this flag */
    if ((req_flags & ret_flags) != req_flags) {
      self->error_string =
	strdup("requested GSSAPI service not supported");
      goto error;
    }

    /* Check the authenticated identity of the server. */
    self->major_status = gss_inquire_context(&self->minor_status,
					     self->gss_context,
					     NULL,
					     &server_gss_name,
					     NULL, NULL, NULL, NULL, NULL);
    if (self->major_status != GSS_S_COMPLETE) {
	self->error_string = strdup("gss_inquire_context() failed");
	goto error;
    }

    self->major_status = gss_display_name(&self->minor_status,
					  server_gss_name, &gss_buffer, NULL);
    if (self->major_status != GSS_S_COMPLETE) {
	self->error_string = strdup("gss_display_name() failed");
	goto error;
    }

    self->peer_name = strdup(gss_buffer.value);
    myproxy_debug("server name: %s", self->peer_name);

    /* We told gss_assist_init_sec_context() not to check the server
       name so we can check it manually here. */
    for (i=0; accepted_peer_names[i] != NULL; i++) {
	myproxy_debug("checking if server name matches \"%s\"",
		      accepted_peer_names[i]);
	tmp_gss_buffer.value = (void *)accepted_peer_names[i];
	tmp_gss_buffer.length = strlen(accepted_peer_names[i]);
	if (strchr(accepted_peer_names[i],'@') && 
	    !strstr(accepted_peer_names[i],"CN=")) { 
	    target_name_type = GSS_C_NT_HOSTBASED_SERVICE;
	} else {
	    target_name_type = GSS_C_NO_OID;
	}
	self->major_status = gss_import_name(&self->minor_status,
					     &tmp_gss_buffer,
					     target_name_type,
					     &target_name);
	if (self->major_status != GSS_S_COMPLETE) {
	    char error_string[550];
	    sprintf(error_string, "failed to import GSS name \"%.500s\"",
		    accepted_peer_names[i]);
	    self->error_string = strdup(error_string);
	    goto error;
	}
	self->major_status = gss_compare_name(&self->minor_status,
					      server_gss_name,
					      target_name, &rc);
	if (self->major_status != GSS_S_COMPLETE) {
	    char error_string[1050];
	    sprintf(error_string,
		    "gss_compare_name(\"%.500s\",\"%.500s\") failed",
		    self->peer_name, accepted_peer_names[i]);
	    self->error_string = strdup(error_string);
	    goto error;
	}
	if (rc) {
	    myproxy_debug("server name accepted");
	    break;
	} else {
	    myproxy_debug("server name does not match");
	}
    }
    if (!rc) {		/* no match with acceptable target names */
	self->error_string = strdup("authenticated peer name does not match");
	return_value = GSI_SOCKET_UNAUTHORIZED;
	goto error;
    }

    /* Success */
    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    {
	OM_uint32 minor_status;
	gss_release_cred(&minor_status, &creds);
	gss_release_buffer(&minor_status, &gss_buffer);
	gss_release_name(&minor_status, &server_gss_name);
    }
    
    return return_value;
}


int
GSI_SOCKET_authentication_accept(GSI_SOCKET *self)
{
    gss_cred_id_t		creds = GSS_C_NO_CREDENTIAL;
    int				token_status;
    int				return_value = GSI_SOCKET_ERROR;

    if (self == NULL) {	
	return GSI_SOCKET_ERROR;
    }

    if (self->gss_context != GSS_C_NO_CONTEXT) {
	self->error_string = strdup("GSI_SOCKET already authenticated");
	goto error;
    }

    self->major_status = globus_gss_assist_acquire_cred(&self->minor_status,
							GSS_C_ACCEPT,
							&creds);

    if (self->major_status != GSS_S_COMPLETE) {
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

    if (self->major_status != GSS_S_COMPLETE) {
	goto error;
    }
    
    /* Success */
    return_value = GSI_SOCKET_SUCCESS;
    
  error:
    if (creds != GSS_C_NO_CREDENTIAL) {
	OM_uint32 minor_status;

	gss_release_cred(&minor_status, &creds);
    }
    
    return return_value;
}

int
GSI_SOCKET_get_peer_name(GSI_SOCKET *self,
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
				      1 /* encrypt */,
				      GSS_C_QOP_DEFAULT,
				      &unwrapped_buffer,
				      &conf_state,
				      &wrapped_buffer);
	
	if (self->major_status != GSS_S_COMPLETE)
	{
	    goto error;
	}
	
	if (!conf_state) {
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
				  (size_t *)&(self->input_buffer_length));
	
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

int GSI_SOCKET_read_token(GSI_SOCKET *self,
			  unsigned char **pbuffer,
			  size_t *pbuffer_len)
{
    int			bytes_read;
    unsigned char	*buffer;
    int			buffer_len;
    int			return_status = GSI_SOCKET_ERROR;
    
    bytes_read = read_token(self->sock,
			    (char **) &buffer,
			    &buffer_len);
    
    if (bytes_read == -1)
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
				   int lifetime,
				   const char *passphrase)
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

    if (self->gss_context == GSS_C_NO_CONTEXT)
    {
	self->error_string = strdup("GSI_SOCKET not authenticated");
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
    
    if (passphrase && passphrase[0] == '\0') {
	passphrase = NULL;
    }
    if (ssl_proxy_load_from_file(creds, source_credentials,
				 passphrase) == SSL_ERROR)
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
				 int delegated_credentials_len,
				 char *passphrase)
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
    
    if (self->gss_context == GSS_C_NO_CONTEXT)
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
    
    if (passphrase && passphrase[0] == '\0') {
	passphrase = NULL;
    }
    if (ssl_proxy_store_to_file(creds, filename, passphrase) == SSL_ERROR)
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
