
#include "gssapi_test_utils.h"


static int
get_token(
    int                                 fd,
    unsigned char **                    token,
    size_t *                            token_length);

static int
put_token(
    int                                 fd,
    unsigned char *                     token,
    size_t                              token_length);


static OM_uint32
accept_sec_context(
    int                                 client_fd,
    char **                             name,
    gss_ctx_id_t *                      context,
    gss_cred_id_t *                     delegated_cred,
    gss_cred_id_t                       credential);

static OM_uint32
init_sec_context(
    int                                 client_fd,
    gss_cred_id_t                       credential,
    gss_ctx_id_t *                      context);


gss_cred_id_t 
globus_gsi_gssapi_test_acquire_credential()
{
    gss_cred_id_t                       credential = GSS_C_NO_CREDENTIAL;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           minor_status;
    
    major_status = gss_acquire_cred(&minor_status,
                                    GSS_C_NO_NAME,
                                    GSS_C_INDEFINITE,
                                    GSS_C_NO_OID_SET,
                                    GSS_C_BOTH,
                                    &credential,
                                    NULL,
                                    NULL);
    
    if(major_status != GSS_S_COMPLETE)
    {
        globus_libc_printf("Failed to acquire credentials\n");
        return GSS_C_NO_CREDENTIAL;
    }
    
    return credential;
}

void 
globus_gsi_gssapi_test_release_credential(
    gss_cred_id_t *                     credential)
{
    OM_uint32                           minor_status;
    OM_uint32                           major_status = GSS_S_COMPLETE;

    major_status = gss_release_cred(&minor_status,
                                    credential);
}

globus_bool_t
globus_gsi_gssapi_test_authenticate(
    int                                 fd,
    globus_bool_t                       server, 
    gss_cred_id_t                       credential, 
    gss_ctx_id_t *                      context_handle, 
    char **                             user_id, 
    gss_cred_id_t *                     delegated_cred)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    
    if (server == GLOBUS_TRUE) 
    {
        major_status = accept_sec_context(fd, 
					  user_id,
					  context_handle, 
					  delegated_cred, 
					  credential);
    }
    else 
    {
        major_status = init_sec_context(fd,
					credential,
					context_handle);
    }

    return major_status == GSS_S_COMPLETE ? GLOBUS_TRUE : GLOBUS_FALSE;
}

void 
globus_gsi_gssapi_test_cleanup(
    gss_ctx_id_t *                      context_handle,
    char *                              userid,
    gss_cred_id_t *                     delegated_cred)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    
    if (userid != NULL)
    { 
        free(userid);
    }
    
    major_status = gss_delete_sec_context(&minor_status,
                                          context_handle,
                                          GSS_C_NO_BUFFER);
    
    if (delegated_cred != GSS_C_NO_CREDENTIAL)
    {
        major_status = gss_release_cred(&minor_status,
                                        delegated_cred);
    }
}


static int
get_token(
    int                                 fd,
    unsigned char **                    token,
    size_t *                            token_length)
{
    size_t                              num_read = 0;
    ssize_t                             n_read;
    unsigned char                       token_length_buffer[4];

    while(num_read < 4)
    {
        n_read = read(fd,
                      token_length_buffer + num_read,
                      4 - num_read);

        if(n_read < 0)
        {
            if(errno == EINTR)
            { 
                continue;
            }
            else
            { 
                return errno;
            }
        }
        else
        { 
            num_read += n_read;
        }
    }
    
    /* decode the token length from network byte order: 4 byte, big endian */

    *token_length  = (((size_t) token_length_buffer[0]) << 24) & 0xffff;
    *token_length |= (((size_t) token_length_buffer[1]) << 16) & 0xffff;
    *token_length |= (((size_t) token_length_buffer[2]) <<  8) & 0xffff;
    *token_length |= (((size_t) token_length_buffer[3])      ) & 0xffff;

    if(*token_length > 1<<24)
    {
        /* token too large */
        return 1;
    }
    
    *token = malloc(*token_length);

    if(*token == NULL)
    {
        return errno;
    }

    num_read = 0;

    while(num_read < *token_length)
    {
        n_read = read(fd,
                      *token + num_read,
                      *token_length - num_read);

        if(n_read < 0)
        {
            if(errno == EINTR)
            { 
                continue;
            }
            else
            { 
                return errno;
            }
        }
        else
        { 
            num_read += n_read;
        }
    }
    
    return 0;
}

static int
put_token(
    int                                 fd,
    unsigned char *                     token,
    size_t                              token_length)
{
    size_t                              num_written = 0;
    ssize_t                             n_written;
    unsigned char                       token_length_buffer[4];

    /* encode the token length in network byte order: 4 byte, big endian */

    token_length_buffer[0] = (unsigned char) ((token_length >> 24) & 0xff);
    token_length_buffer[1] = (unsigned char) ((token_length >> 16) & 0xff);
    token_length_buffer[2] = (unsigned char) ((token_length >>  8) & 0xff);
    token_length_buffer[3] = (unsigned char) ((token_length      ) & 0xff);

    while(num_written < 4)
    {
        n_written = write(fd,
                          token_length_buffer + num_written,
                          4 - num_written);
        if(n_written < 0)
        {
            if(errno == EINTR)
            { 
                continue;
            }
            else
            { 
                return errno;
            }
        }
        else
        { 
            num_written += n_written;
        }
    }
    
    num_written = 0;

    while(num_written < token_length)
    {
        n_written = write(fd,
                          token + num_written,
                          token_length - num_written);
        if(n_written < 0)
        {
            if(errno == EINTR)
            { 
                continue;
            }
            else
            { 
                return errno;
            }
        }
        else
        { 
            num_written += n_written;
        }
    }

    return 0;
}


static OM_uint32
accept_sec_context(
    int                                 client_fd,
    char **                             name,
    gss_ctx_id_t *                      context,
    gss_cred_id_t *                     delegated_cred,
    gss_cred_id_t                       credential)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           minor_status;
    OM_uint32                           minor_status2;
    OM_uint32                           ret_flags = 0;
    int                                 token_status = 0;
    gss_name_t                          client_name = GSS_C_NO_NAME;
    gss_buffer_desc                     input_token  = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc                     output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc                     name_buffer;
    gss_OID                             mech_type = GSS_C_NO_OID;
    OM_uint32                           time_ret;
    char *                              error_str;
    
    if(credential == GSS_C_NO_CREDENTIAL)
    {
        globus_libc_printf("Failed to acquire credentials\n");
        return 1;
    }

    do
    {
        token_status = get_token(client_fd,
                                 &input_token.value,
                                 &input_token.length);
        if(token_status != 0)
        {
            major_status = GSS_S_DEFECTIVE_TOKEN|GSS_S_CALL_INACCESSIBLE_READ;
            break;
        }

        major_status = gss_accept_sec_context(&minor_status,
                                              context,
                                              credential,
                                              &input_token,
                                              GSS_C_NO_CHANNEL_BINDINGS,
                                              &client_name,
                                              &mech_type,
                                              &output_token,
                                              &ret_flags,
                                              &time_ret,
                                              delegated_cred);

	if(major_status != GSS_S_COMPLETE &&
	   major_status != GSS_S_CONTINUE_NEEDED)
	{
	    abort();
	}

        if(output_token.length != 0)
        {
            token_status = put_token(client_fd,
                                      output_token.value,
                                      output_token.length);
            if(token_status != 0)
            {
                major_status =
                    GSS_S_DEFECTIVE_TOKEN|GSS_S_CALL_INACCESSIBLE_WRITE;
            }
	    
            gss_release_buffer(&minor_status2,
                               &output_token);
        }

        if (input_token.length > 0)
        {
            gss_release_buffer(&minor_status2,
                               &input_token);
        }

        if (GSS_ERROR(major_status))
        {
            if (context != GSS_C_NO_CONTEXT)
            {
		globus_libc_printf("Failed to establish security context (accept).");
		globus_gss_assist_display_status_str(&error_str,
						     NULL,
						     major_status,
						     minor_status,
						     0);
		printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);

                gss_delete_sec_context(&minor_status2,
                                       context,
                                       GSS_C_NO_BUFFER);
                break;
            }
        }
    }
    while(major_status & GSS_S_CONTINUE_NEEDED);

    /* authentication failed */

    if(major_status != GSS_S_COMPLETE)
    {
        return 1;
    }

    /* authentication succeeded, figure out who it is */

    major_status = gss_display_name(&minor_status,
				    client_name,
				    &name_buffer,
				    NULL);

    *name = (char *)name_buffer.value;

    gss_release_name(&minor_status2, &client_name);

    return major_status;
}


static OM_uint32
init_sec_context(
    int                                 client_fd,
    gss_cred_id_t                       credential,
    gss_ctx_id_t *                      context)
{
    OM_uint32			        minor_status2 = 0;
    OM_uint32			        minor_status = 0;
    OM_uint32			        major_status = GSS_S_COMPLETE;
    OM_uint32			        req_flags  = GSS_C_MUTUAL_FLAG|GSS_C_DELEG_FLAG;
    OM_uint32			        ret_flags  = 0;
    int				        token_status = 0;
    gss_name_t			        target_name = GSS_C_NO_NAME;
    globus_bool_t		        context_established = GLOBUS_FALSE;
    gss_OID *			        actual_mech_type = NULL;
    OM_uint32			        time_ret;
    gss_buffer_desc		        input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc 		        output_token = GSS_C_EMPTY_BUFFER;
    char *                              error_str;

    major_status = gss_inquire_cred(&minor_status,
				    credential,
				    &target_name,
				    NULL,
				    NULL,
				    NULL);

    if(major_status != GSS_S_COMPLETE)
    {
	globus_libc_printf("Failed to determine my name\n");
	return 1;
    }

    while(!context_established)
    {
	major_status = gss_init_sec_context(&minor_status,
					    credential,
					    context,
					    target_name,
					    GSS_C_NO_OID, /*mech_type*/
					    req_flags,
					    0, /* default time */
					    GSS_C_NO_CHANNEL_BINDINGS,
					    &input_token,
					    actual_mech_type,
					    &output_token,
					    &ret_flags,
					    &time_ret);
	if(major_status != GSS_S_COMPLETE &&
	   major_status != GSS_S_CONTINUE_NEEDED)
	{
	    abort();
	}
	/* free any token we've just processed */
	if(input_token.length > 0)
	{
	    gss_release_buffer(&minor_status2,
                               &input_token);
	}
	
	/* and send any new token to the server */
	if(output_token.length != 0)
	{
	    token_status = put_token(client_fd,
				     output_token.value,
				     output_token.length);
	    if(token_status != 0)
	    {
		major_status =
		    GSS_S_DEFECTIVE_TOKEN|GSS_S_CALL_INACCESSIBLE_WRITE;
	    }
            gss_release_buffer(&minor_status,
                               &output_token);
	}
	
	if (GSS_ERROR(major_status))
	{
	    globus_libc_printf("Failed to establish security context (init).");
	    globus_gss_assist_display_status_str(&error_str,
						 NULL,
						 major_status,
						 minor_status,
						 0);
	    printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
	    
	    if (*context != GSS_C_NO_CONTEXT)
	    {
		gss_delete_sec_context(&minor_status2,
				       context,
				       GSS_C_NO_BUFFER);
		break;
	    }
	}
	
	if(major_status & GSS_S_CONTINUE_NEEDED)
	{
	    token_status = get_token(client_fd,
				     &input_token.value,
				     &input_token.length);
	    if(token_status != 0)
	    {
		major_status = 
		    GSS_S_DEFECTIVE_TOKEN | GSS_S_CALL_INACCESSIBLE_READ;
		break;
	    }
	}
	else
	{
	    context_established = 1;
	}
    } /* while() */

    if (target_name != GSS_C_NO_NAME)
    {
        gss_release_name(&minor_status2,&target_name);
    }

    return major_status;
}
