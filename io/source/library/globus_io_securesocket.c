/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_io_securesocket.c Globus I/O toolset (secure socket layer)
 *
 * $Source$
 * $Date$
 * $Revision$
 * $State$
 * $Author$
 */

/**
 * RCS Identification for this file
 */
static char *rcsid = "$Header$";
#endif


/**
 * @defgroup security Security.
 *
 * Globus I/O provides a convenient way to use GSI (or other
 * GSSAPI-based) security in network communications.
 *
 * This section section describes the data types associated with
 * Globus I/O security interface. These data types are used in concert
 * with Globus I/O TCP attributes.
 */
/******************************************************************************
                 Include header files
******************************************************************************/
#include "globus_l_io.h"


/******************************************************************************
               Module Specific Constants
******************************************************************************/
#if !defined(INADDR_LOOPBACK)
#   if defined(WORDS_BIGENDIAN)
#       define INADDR_LOOPBACK 0x7f000000
#   else
#       define INADDR_LOOPBACK 0x0000007f
#   endif
#endif


/******************************************************************************
               Module Specific Type Definitions
******************************************************************************/

/* This structure contains two copies of the buffer returned from the
 * GSS_Unwrap. The "orig" copy is kept around so that we can free the pointer
 * we were given, the "buffer" copy is modified in the case of a partial
 * data copy from the buffer to the user's data buffer.
 */
typedef struct
{
    gss_buffer_desc         buffer;
    gss_buffer_desc         orig;
} globus_io_buffer_t;

typedef struct
{
    globus_byte_t *         token;
    globus_size_t           token_to_read;
    globus_size_t           token_length;
    globus_byte_t           token_length_buffer[5];
    globus_size_t           token_length_read;
    globus_size_t           token_offset;
    globus_bool_t           error_occurred;
#ifdef TARGET_ARCH_WIN32
	// The following four variables are needed for secure reads
	globus_byte_t *	mysteryBuffer; // a pointer to the buffer that bytes should be read into
	globus_size_t	mysteryNumberOfBytes; // the number of bytes to throttle the mystery read
	globus_size_t *	mysteryUpdateRead; // a pointer to the field that stores the number of bytes read
	globus_size_t *	mysteryUpdateToRead; // a pointer to the field that stores the number of bytes left to read
#endif
} globus_io_input_token_t;

typedef struct
{
    globus_byte_t *         buf;
    globus_size_t           max_nbytes;
    globus_size_t           wait_for_nbytes;
    globus_size_t           nbytes_read;
    void *              arg;
    globus_io_read_callback_t       callback;
    globus_io_handle_t *        handle;
    globus_bool_t	    selecting;
#ifdef TARGET_ARCH_WIN32
	// The following four variables are needed for secure reads
	globus_byte_t *	mysteryBuffer; // a pointer to the buffer that bytes should be read into
	globus_size_t	mysteryNumberOfBytes; // the number of bytes to throttle the mystery read
	globus_size_t *	mysteryUpdateRead; // a pointer to the field that stores the number of bytes read
	globus_size_t *	mysteryUpdateToRead; // a pointer to the field that stores the number of bytes left to read
#endif
} globus_io_secure_read_info_t;

static
globus_bool_t
globus_l_io_is_ssl_packet(void * token);

static
globus_result_t
globus_l_io_read_input_token(
    globus_io_handle_t *    handle,
    globus_io_input_token_t *   input_token);

static
globus_result_t
globus_l_io_securesocket_call_auth_callback(
    globus_io_handle_t *    handle);

typedef struct globus_io_authentication_info_s globus_io_authentication_info_t;

typedef void (* globus_io_authentication_callback_t)(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result,
    globus_io_authentication_info_t *   auth_info);

/* globus_io_authentication_info_t
 *
 * This structure contains state information during authentication.
 * The buffers are used to manage sending and receiving tokens.
 * The flags and *_stat items are common to init and accept
 * The final two options are unique to the accept, to pass
 * authentication information up the stream to allow for authorization
 * checks.
 *
 * The complete and complete_arg contain the callback and callback arg to
 * call after authentication is completed or failed.
 * The iteration function is called once a complete cycle of sending
 * and receiving tokens is done.
 */
struct globus_io_authentication_info_s
{
    globus_io_input_token_t             input_token;
    
    globus_byte_t *                     output_buffer;
    globus_size_t                       output_buflen;
    globus_size_t                       output_offset;

    globus_byte_t *                     output_buffer_header;
    globus_size_t                       output_header_len;
    globus_size_t                       output_header_offset;

    OM_uint32                           flags;
    OM_uint32                           ret_flags;

    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;

    globus_io_authentication_callback_t callback;
    void *                              callback_arg;

    globus_io_callback_t                iteration;

    /* If we are initiating a connection, and we did not
     * receive any token from the server, then we should return
     * connection_refused, instead of authentication_failed.
     */
    globus_bool_t                       any_token_received;

    /* Additional for accept support */
    char *                              name;
    globus_bool_t                       user_to_user;

    /* fields used by delegation functions */

    gss_cred_id_t                       cred_handle;
    gss_OID_set                         restriction_oids;
    gss_buffer_set_t                    restriction_buffers;
    OM_uint32                           time_req;
    OM_uint32                           time_rec;
    globus_io_delegation_callback_t     delegation_callback; 
} ;

typedef
struct globus_io_delegation_data_s
{
    OM_uint32                           time_rec;
    gss_cred_id_t                       cred_handle;
}
globus_io_delegation_data_t;

static
globus_result_t
globus_l_io_copy_unwrapped_data_to_buffer(
    globus_io_handle_t *        handle,
    globus_byte_t *         buf,
    globus_size_t           max_nbytes,
    globus_size_t *         nbytes_copied);

static
void 
globus_l_io_init_sec_context(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result);

static
void 
globus_l_io_accept_sec_context(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result);

static
void
globus_l_io_secure_connect_callback(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result,
    globus_io_authentication_info_t *   info);

static
void
globus_l_io_secure_accept_callback(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result,
    globus_io_authentication_info_t *   info);

static
void
globus_l_io_write_auth_token(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result);

static
void
globus_l_io_read_auth_token(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result);

static
void
globus_l_io_delegation_cb_wrapper(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result,
    globus_io_authentication_info_t *   auth_info);

static
void 
globus_l_io_accept_delegation(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result);

static
void 
globus_l_io_init_delegation(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result);

static
void
globus_l_io_delegation_cb(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result,
    gss_cred_id_t                       delegated_cred,
    OM_uint32                           time_rec);

/*
 * Function:    globus_i_io_setup_securesocket()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_i_io_setup_securesocket(
    globus_io_handle_t *        handle)
{
    return globus_i_io_setup_socket(handle);
}
/* globus_i_io_setup_securesocket() */

/*
 * Function:    globus_i_io_securesocket_register_accept()
 *
 * Description: called with globus_i_io_mutex locked
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_i_io_securesocket_register_accept(
    globus_io_handle_t *        handle,
    globus_io_callback_t        callback_func,
    void *              callback_arg)
{
    globus_i_io_callback_info_t *   info;
    globus_io_authentication_info_t *   accept_info;
    OM_uint32                   maj_stat;
    OM_uint32                   min_stat;
    globus_object_t *               err;
    globus_result_t                 rc;
#ifdef TARGET_ARCH_WIN32
	int returnCode;
#endif
    
    info = (globus_i_io_callback_info_t *)
        globus_malloc(sizeof(globus_i_io_callback_info_t));
    info->callback = callback_func;
    info->callback_arg = callback_arg;
    info->handle = handle;

    if(handle->securesocket_attr.credential == GSS_C_NO_CREDENTIAL)
    {
        maj_stat = globus_gss_assist_acquire_cred(
            &min_stat,
            GSS_C_ACCEPT,
            &handle->securesocket_attr.credential);
        if(maj_stat != GSS_S_COMPLETE)
        {
            err = globus_io_error_construct_no_credentials(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                (int) maj_stat,
                (int) min_stat,
                0);
            
            globus_free(info);
            
            return globus_error_put(err);
        }
    }

    /* if we're willing to accept extensions set the correct option */

    if(handle->securesocket_attr.extension_oids != GSS_C_NO_OID_SET)
    {
        gss_buffer_desc                 oid_buffer;
        
        oid_buffer.value = (void *) handle->securesocket_attr.extension_oids;
        oid_buffer.length = 1;
        
        maj_stat = gss_set_sec_context_option(
            &min_stat,
            &handle->context,
            (gss_OID) GSS_APPLICATION_WILL_HANDLE_EXTENSIONS,
            &oid_buffer);

        if(maj_stat != GSS_S_COMPLETE)
        {
            err = globus_io_error_construct_authentication_failed(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                (int) maj_stat,
                (int) min_stat,
                0);
            
            globus_free(info);
            
            return globus_error_put(err);
        }
    }
    
    accept_info = (globus_io_authentication_info_t *)
        globus_malloc(sizeof(globus_io_authentication_info_t));

    memset(&accept_info->input_token,
           '\0',
           sizeof(globus_io_input_token_t));

    accept_info->output_buffer = GLOBUS_NULL;
    accept_info->output_buflen = 0;
    accept_info->output_offset = 0;

    accept_info->output_buffer_header = GLOBUS_NULL;
    accept_info->output_header_len = 0;
    accept_info->output_header_offset = 0;
       
    accept_info->ret_flags = 0;
    if(handle->securesocket_attr.channel_mode ==
       GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP)
    {
        accept_info->ret_flags = GSS_C_GLOBUS_SSL_COMPATIBLE;
    }
    if(handle->securesocket_attr.protection_mode == GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE)
    {
        accept_info->ret_flags |= GSS_C_CONF_FLAG;
    }

    switch(handle->securesocket_attr.proxy_mode)
    {
    case GLOBUS_IO_SECURE_PROXY_MODE_NONE:
        break;
    case GLOBUS_IO_SECURE_PROXY_MODE_LIMITED:
        accept_info->ret_flags |= GSS_C_GLOBUS_LIMITED_PROXY_FLAG;
        break;
    case GLOBUS_IO_SECURE_PROXY_MODE_MANY:
        accept_info->ret_flags |= GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG;  
        break;
    } 

    accept_info->maj_stat = 0;
    accept_info->min_stat = 0;

    accept_info->callback = globus_l_io_secure_accept_callback;
    accept_info->callback_arg = info;
    accept_info->name = GLOBUS_NULL;
    accept_info->user_to_user = GLOBUS_NULL;

    accept_info->iteration = globus_l_io_accept_sec_context;
    accept_info->any_token_received = GLOBUS_FALSE;
    accept_info->delegation_callback = GLOBUS_NULL;
    
    handle->state = GLOBUS_IO_HANDLE_STATE_AUTHENTICATING;

    /* I need a token before I can start the iterations, so:
     */
    accept_info->maj_stat = GSS_S_CONTINUE_NEEDED;
    
    rc = globus_i_io_start_operation(
        handle,
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
    
    if(rc == GLOBUS_SUCCESS)
    {
        rc = globus_i_io_register_operation(
            handle,
            globus_l_io_read_auth_token,
            accept_info,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_READ_OPERATION);
        
        if(rc != GLOBUS_SUCCESS)
        {
            globus_i_io_end_operation(
                handle, 
                GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        }
#ifdef TARGET_ARCH_WIN32
		else
		{
			// post a packet in order to trigger the callback
			returnCode= globus_i_io_windows_post_completion( 
						handle, 
						WinIoReading );
			if ( returnCode ) // a fatal error occurred
			{
				// unregister the read operation
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE, 
							GLOBUS_I_IO_READ_OPERATION);
				// end the operation
				globus_i_io_end_operation(
					handle, 
					GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						returnCode );
				return globus_error_put(err);
			}
		}
#endif
    }
    
    return rc;
}
/* globus_i_io_securesocket_register_accept() */

/*
 * Function:    globus_i_io_securesocket_register_connect_callback()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
void
globus_i_io_securesocket_register_connect_callback(
    void *              callback_arg,
    globus_io_handle_t *        handle,
    globus_result_t         result)
{
    globus_i_io_callback_info_t *   info;
    globus_object_t *           err = GLOBUS_NULL;
    OM_uint32               maj_stat;
    OM_uint32               min_stat;
    OM_uint32               flags = 0;
    globus_io_authentication_info_t *   init_info;
    int                 rc;
    globus_netlen_t         optlen;
    int                 optval;
    
    
    info = (globus_i_io_callback_info_t *) callback_arg;

    globus_i_io_mutex_lock();
    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        goto error_exit;
    }
    optlen = sizeof(optval);

#ifndef TARGET_ARCH_WIN32
    /* Check to verify that an in progress connection completed */
/*                                            After select indicates */
/*                writability,  use  getsockopt(2)   to   read   the */
/*                SO_ERROR  option  at level SOL_SOCKET to determine */
/*                whether connect completed  successfully  (SO_ERROR */
/*                is zero) or unsuccessfully (SO_ERROR is one of the */
/*                usual error codes  listed  above,  explaining  the */
/*                reason for the failure). */
    rc = getsockopt(handle->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
    if(optval != 0 || rc != 0)
    {
        err = globus_io_error_construct_system_failure(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            optval);
        goto error_exit;
    }
#endif


    switch(handle->securesocket_attr.delegation_mode)
    {
    case GLOBUS_IO_SECURE_DELEGATION_MODE_NONE:
        break;
    case GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY:
        flags |= GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG |
            GSS_C_DELEG_FLAG;
        break;
    case GLOBUS_IO_SECURE_DELEGATION_MODE_FULL_PROXY:
        flags |= GSS_C_DELEG_FLAG;
        break;
    }

    switch(handle->securesocket_attr.proxy_mode)
    {
    case GLOBUS_IO_SECURE_PROXY_MODE_NONE:
        break;
    case GLOBUS_IO_SECURE_PROXY_MODE_LIMITED:
        flags |= GSS_C_GLOBUS_LIMITED_PROXY_FLAG;
        break;
    case GLOBUS_IO_SECURE_PROXY_MODE_MANY:
        flags |= GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG;
        break;
    } 
    
    switch(handle->securesocket_attr.channel_mode)
    {
    case GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP:
        flags |= GSS_C_GLOBUS_SSL_COMPATIBLE;
        break;
    default:
        break;
    }
    switch(handle->securesocket_attr.protection_mode)
    {
    case GLOBUS_IO_SECURE_PROTECTION_MODE_NONE:
    case GLOBUS_IO_SECURE_PROTECTION_MODE_SAFE:
        break;
    case GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE:
        flags |= GSS_C_CONF_FLAG;
        break;
    }

    if(handle->securesocket_attr.credential == GSS_C_NO_CREDENTIAL &&
       handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL)
    {
        maj_stat = globus_gss_assist_acquire_cred(
            &min_stat,
            GSS_C_INITIATE,
            &handle->securesocket_attr.credential);
        if(maj_stat != GSS_S_COMPLETE)
        {
            
            err = globus_io_error_construct_no_credentials(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                (int) maj_stat,
                (int) min_stat,
                0);
            goto error_exit;
        }
    }

    if(handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_ANONYMOUS)
    {
        flags |= GSS_C_ANON_FLAG;
    }
    
    switch(handle->securesocket_attr.authorization_mode)
    {
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST:
    {
        struct sockaddr_in         addr;
        struct hostent             host;
        struct hostent *           hp;
        char                       buf[4096];
        globus_netlen_t            namelen = sizeof(addr);
        int                        rc;
        int                        save_errno;
        int                        herror;
        
#ifndef TARGET_ARCH_WIN32
        rc = getpeername(handle->fd,
#else
        rc = getpeername( (SOCKET)handle->io_handle,
#endif
                         (struct sockaddr *) &addr,
                         &namelen);
        if(rc != 0)
        {
            save_errno = errno;
            err = globus_io_error_construct_system_failure(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                save_errno);
            goto error_exit;
        }
        
        if(ntohl(addr.sin_addr.s_addr) == INADDR_LOOPBACK)
        {
            rc = globus_libc_gethostname(buf, 4096);
            
            if(rc != 0)
            {
                save_errno = errno;
                err = globus_io_error_construct_system_failure(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle,
                    save_errno);
                goto error_exit;
            }
        }
        else
        {
            hp = globus_libc_gethostbyaddr_r((char *) &addr.sin_addr,
                                             (int)sizeof(addr.sin_addr),
                                             AF_INET,
                                             &host,
                                             buf,
                                             4096, 
                                             &herror);
            if(hp == GLOBUS_NULL)
            {
                save_errno = errno;
                err = globus_io_error_construct_system_failure(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle,
                    save_errno);
                goto error_exit;
            }
            
            if(strchr(hp->h_name, '.') == GLOBUS_NULL)
            {
                int i;
                int found_alias = 0;
                
                for(i = 0; hp->h_aliases[i] != GLOBUS_NULL; i++)
                {
                    if(strchr(hp->h_aliases[i], '.') != GLOBUS_NULL)
                    {
                        memmove(buf,
                                hp->h_aliases[i],
                                strlen(hp->h_aliases[i])+1);
                        found_alias = 1;
                        break;
                    }
                }
                
                if(!found_alias)
                {
                    memmove(buf, hp->h_name, strlen(hp->h_name)+1);   
                }
            }
            else
            {
                memmove(buf, hp->h_name, strlen(hp->h_name)+1);   
            }
        }
        if(handle->securesocket_attr.authorized_identity != GLOBUS_NULL)
        {
            globus_libc_free(handle->securesocket_attr.authorized_identity);
        }
        handle->securesocket_attr.authorized_identity =
            globus_libc_malloc(strlen("host@") + strlen(buf) + 1);
        sprintf(handle->securesocket_attr.authorized_identity, "host@%s", buf);
    }
    flags |= GSS_C_MUTUAL_FLAG;
    break;
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF:
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY:
        flags |= GSS_C_MUTUAL_FLAG;
        break;
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK:
        flags |= GSS_C_MUTUAL_FLAG;
        if(handle->securesocket_attr.authorized_identity != GLOBUS_NULL)
        {
            globus_libc_free(handle->securesocket_attr.authorized_identity);
        }
        handle->securesocket_attr.authorized_identity =
            globus_libc_strdup("GSI-NO-TARGET");
        break;
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE:
        globus_assert(GLOBUS_FALSE ||
                      "unsupported authorization mode");
        goto error_exit;
    }

    if(handle->securesocket_attr.extension_oids != GSS_C_NO_OID_SET)
    {
        gss_buffer_desc                 oid_buffer;
        
        oid_buffer.value = (void *) handle->securesocket_attr.extension_oids;
        oid_buffer.length = 1;
        
        maj_stat = gss_set_sec_context_option(
            &min_stat,
            &handle->context,
            (gss_OID) GSS_APPLICATION_WILL_HANDLE_EXTENSIONS,
            &oid_buffer);

        if(maj_stat != GSS_S_COMPLETE)
        {
            err = globus_io_error_construct_authentication_failed(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                (int) maj_stat,
                (int) min_stat,
                0);
            goto error_exit;
        }
    }
    
    init_info = (globus_io_authentication_info_t *)
        globus_malloc(sizeof(globus_io_authentication_info_t));

    memset(&init_info->input_token,
           '\0',
           sizeof(globus_io_input_token_t));

    init_info->output_buffer = GLOBUS_NULL;
    init_info->output_buflen = 0;
    init_info->output_offset = 0;

    init_info->output_buffer_header = GLOBUS_NULL;
    init_info->output_header_len = 0;
    init_info->output_header_offset = 0;

    init_info->flags = flags;
    init_info->ret_flags = 0;

    init_info->maj_stat = 0;
    init_info->min_stat = 0;

    init_info->callback = globus_l_io_secure_connect_callback;
    init_info->callback_arg = info;
    init_info->name = GLOBUS_NULL;
    init_info->user_to_user = GLOBUS_NULL;

    init_info->iteration = globus_l_io_init_sec_context;
    init_info->any_token_received = GLOBUS_FALSE;
    init_info->delegation_callback = GLOBUS_NULL;
    
    handle->state = GLOBUS_IO_HANDLE_STATE_AUTHENTICATING;

    globus_i_io_mutex_unlock();

    init_info->iteration(init_info,
                         handle,
                         GLOBUS_SUCCESS);

    return;

error_exit:
    globus_i_io_end_operation(
        handle, 
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
    globus_i_io_close(handle);
    
    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
    globus_i_io_mutex_unlock();
    info->callback(info->callback_arg,
                   handle,
                   globus_error_put(err));
    globus_free(info);
}
/* globus_i_io_securesocket_register_connect_callback() */

/*
 * Function:    globus_i_io_securesocket_set_attr()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_i_io_securesocket_set_attr(
    globus_io_handle_t *        handle,
    globus_io_attr_t *          attr)
{
    globus_object_t *           err = GLOBUS_NULL;
    globus_object_t *           securesocket_attr;
    globus_i_io_securesocketattr_instance_t *
        instance;
    static char *           myname=
        "globus_i_io_securesocket_set_attr";

    securesocket_attr =
        globus_object_upcast(attr->attr,
                             GLOBUS_IO_OBJECT_TYPE_SECURESOCKETATTR);
    
    globus_assert(securesocket_attr != GLOBUS_NULL);
    
    instance = (globus_i_io_securesocketattr_instance_t *)
        globus_object_get_local_instance_data(securesocket_attr);

    globus_assert(instance);

    if(handle->state == GLOBUS_IO_HANDLE_STATE_LISTENING)
    {
        /* If handler is a a listener we can change any sec attributes we want
         * For now I'm not touching attributes where mem mgmt is unclear
         */ 
        
        handle->securesocket_attr.authentication_mode =
            instance->authentication_mode;
        handle->securesocket_attr.authorization_mode =
            instance->authorization_mode;
        handle->securesocket_attr.channel_mode =
            instance->channel_mode;
        handle->securesocket_attr.delegation_mode =
            instance->delegation_mode;
        handle->securesocket_attr.proxy_mode =
            instance->proxy_mode;
        /*
          handle->securesocket_attr.credential =
          instance->credential;
        */
        if(handle->securesocket_attr.authorized_identity)
        {
            free(handle->securesocket_attr.authorized_identity);
            handle->securesocket_attr.authorized_identity = NULL;
        }

        if(instance->authorized_identity)
        { 
            handle->securesocket_attr.authorized_identity =
                strdup(instance->authorized_identity);
        }

        handle->securesocket_attr.auth_callback =
            instance->auth_callback;
        handle->securesocket_attr.auth_callback_arg =
            instance->auth_callback_arg;
        /*
        handle->securesocket_attr.extension_oids =
            instance->extension_oids;
        */
    }
    else
    { 
    
        if(instance->authentication_mode !=
           handle->securesocket_attr.authentication_mode)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "authentication_mode");
            
            goto error_exit;
        }

        if(instance->authorization_mode !=
           handle->securesocket_attr.authorization_mode)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "authorization_mode");

            goto error_exit;
        }

        if(instance->channel_mode !=
           handle->securesocket_attr.channel_mode)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "channel_mode");

            goto error_exit;
        }

        if(instance->delegation_mode !=
           handle->securesocket_attr.delegation_mode)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "delegation_mode");
            
            goto error_exit;
        }

    
        if(instance->proxy_mode !=
           handle->securesocket_attr.proxy_mode)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "proxy_mode");
            
            goto error_exit;
        }

    
        if(instance->credential !=
           handle->securesocket_attr.credential)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "credential");

            goto error_exit;
        }

        if(instance->authorized_identity != NULL &&
           handle->securesocket_attr.authorized_identity != NULL &&
           handle->securesocket_attr.authorization_mode == GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY &&
           strcmp(instance->authorized_identity,
                  handle->securesocket_attr.authorized_identity) != 0)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "authorized_identity");
            
            goto error_exit;
        }

        if(instance->auth_callback !=
           handle->securesocket_attr.auth_callback)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "authorization_callback");
            
            goto error_exit;
        }

        if(instance->auth_callback_arg !=
           handle->securesocket_attr.auth_callback_arg)
        {
            err = globus_io_error_construct_immutable_attribute(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "attr",
                2,
                myname,
                "authorization_callback_arg");
            
            goto error_exit;
        }

        if(handle->securesocket_attr.extension_oids == GSS_C_NO_OID_SET)
        {
            if(instance->extension_oids != GSS_C_NO_OID_SET)
            {
                err = globus_io_error_construct_immutable_attribute(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    "attr",
                    2,
                    myname,
                    "extension_oids");  
            }
        }
        else
        {
            if(instance->extension_oids == GSS_C_NO_OID_SET)
            {
                err = globus_io_error_construct_immutable_attribute(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    "attr",
                    2,
                    myname,
                    "extension_oids");  
            }
            else
            {
                gss_OID_set_desc *          handle_ext_oids;
                gss_OID_set_desc *          instance_ext_oids;
                OM_uint32                   maj_stat;
                OM_uint32                   min_stat;
                int                         i;
                int                         present;
                
                handle_ext_oids = (gss_OID_set_desc *)
                    handle->securesocket_attr.extension_oids;

                instance_ext_oids = (gss_OID_set_desc *)
                    instance->extension_oids;
            
                if(handle_ext_oids->count != instance_ext_oids->count)
                {
                    err = globus_io_error_construct_immutable_attribute(
                        GLOBUS_IO_MODULE,
                        GLOBUS_NULL,
                        "attr",
                        2,
                        myname,
                        "extension_oids");    
                }
                else
                {
                    for(i=0;i<handle_ext_oids->count;i++)
                    {
                        maj_stat = gss_test_oid_set_member(
                            &min_stat,
                            (gss_OID) &instance_ext_oids->elements[i],
                            handle->securesocket_attr.extension_oids,
                            &present);
                        if(maj_stat != GSS_S_COMPLETE ||
                           !present)
                        {
                            err = globus_io_error_construct_immutable_attribute(
                                GLOBUS_IO_MODULE,
                                GLOBUS_NULL,
                                "attr",
                                2,
                                myname,
                                "extension_oids");  
                        }
                    }
                }
            }
        }
    }

    return globus_i_io_socket_set_attr(handle,
                                       attr);
error_exit:
    return globus_error_put(err);
}
/* globus_i_io_securesocket_set_attr() */

/*
 * Function:    globus_i_io_securesocket_wrap_buffer()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_i_io_securesocket_wrap_buffer(
    globus_io_handle_t *        handle,
    globus_byte_t *         buf,
    globus_size_t           buf_size,
    struct iovec **         iov,
    globus_size_t *         iovcnt)
{
    OM_uint32               maj_stat;
    OM_uint32               min_stat;
    int                 conf_state;
    gss_buffer_desc         data;
    globus_object_t *           err = GLOBUS_NULL;
    int                 iov_index;
    globus_size_t           wrapped = 0;
    static char *           myname=
        "globus_i_io_securesocket_wrap_buffer";
    gss_buffer_desc                 wrapped_buffer;
    globus_bool_t           send_length = GLOBUS_FALSE;


    if((handle->securesocket_attr.channel_mode == GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR) ||
       (buf_size == 0))
    {
        *iov = GLOBUS_NULL;
        *iovcnt = 0;
        return GLOBUS_SUCCESS;
    }

    /*
     * Check for GSSAPI type by inspecting the token returned from
     * GSS_Wrap
     */
    data.value = buf;
    data.length = (handle->max_wrap_length) > buf_size ?
        buf_size :
        handle->max_wrap_length;
    
    maj_stat = gss_wrap(&min_stat,
                        handle->context,
                        handle->securesocket_attr.protection_mode ==
                        GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE,
                        GSS_C_QOP_DEFAULT,
                        &data,
                        &conf_state,
                        &wrapped_buffer);

    if(maj_stat != GSS_S_COMPLETE)
    {
        *iov = GLOBUS_NULL;
        *iovcnt = 0;

        goto gss_exit;
    }

    (*iovcnt) = buf_size / handle->max_wrap_length;
    if(buf_size % handle->max_wrap_length != 0)
    {
        (*iovcnt)++;
    }

    if(! globus_l_io_is_ssl_packet(wrapped_buffer.value))
    {
        send_length = GLOBUS_TRUE;
        (*iovcnt) *= 2; /* add in length fields before each packet */
    }

    (*iov) = (struct iovec *)
        globus_malloc(sizeof(struct iovec) * (*iovcnt));
    
    iov_index = 0;
    if(send_length)
    {
        (*iov)[iov_index].iov_base = globus_malloc(4);
        *(((unsigned char *) (*iov)[iov_index].iov_base)) = 
            (unsigned char) ((wrapped_buffer.length >> 24) & 0xff);
        *(((unsigned char *) (*iov)[iov_index].iov_base)+1) = 
            (unsigned char) ((wrapped_buffer.length >> 16) & 0xff);
        *(((unsigned char *) (*iov)[iov_index].iov_base)+2) = 
            (unsigned char) ((wrapped_buffer.length >>  8) & 0xff);
        *(((unsigned char *) (*iov)[iov_index].iov_base)+3) = 
            (unsigned char) ((wrapped_buffer.length      ) & 0xff);
        (*iov)[iov_index].iov_len = 4;
        iov_index++;
    }

    (*iov)[iov_index].iov_base = wrapped_buffer.value;
    (*iov)[iov_index].iov_len = wrapped_buffer.length;
    iov_index++;

    wrapped = data.length;
    
    for( ;
         iov_index < (*iovcnt);
         wrapped += data.length)
    {
        data.value = buf + wrapped;
        data.length = (handle->max_wrap_length + wrapped) > buf_size ?
            buf_size - wrapped :
            handle->max_wrap_length;

        maj_stat = gss_wrap(&min_stat,
                            handle->context,
                            handle->securesocket_attr.protection_mode ==
                            GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE,
                            GSS_C_QOP_DEFAULT,
                            &data,
                            &conf_state,
                            &wrapped_buffer);

        if(maj_stat != GSS_S_COMPLETE)
        {
            int cnt;
        
            for(cnt = iov_index-1; cnt >= 0; cnt--)
            {
                globus_free((*iov)[cnt].iov_base);
            }
            globus_free(*iov);
            *iov = GLOBUS_NULL;
            *iovcnt = 0;

            goto gss_exit;
        }

        if(send_length)
        {
            (*iov)[iov_index].iov_base = globus_malloc(4);
            *(((unsigned char *) (*iov)[iov_index].iov_base)) = 
                (unsigned char) ((wrapped_buffer.length >> 24) & 0xff);
            *(((unsigned char *) (*iov)[iov_index].iov_base)+1) = 
                (unsigned char) ((wrapped_buffer.length >> 16) & 0xff);
            *(((unsigned char *) (*iov)[iov_index].iov_base)+2) = 
                (unsigned char) ((wrapped_buffer.length >>  8) & 0xff);
            *(((unsigned char *) (*iov)[iov_index].iov_base)+3) = 
                (unsigned char) ((wrapped_buffer.length      ) & 0xff);
            (*iov)[iov_index].iov_len = 4;
            iov_index++;
        }
        (*iov)[iov_index].iov_base = wrapped_buffer.value;
        (*iov)[iov_index].iov_len = wrapped_buffer.length;
        iov_index++;
    }

    return GLOBUS_SUCCESS;

gss_exit:
    switch(maj_stat)
    {
    case GSS_S_COMPLETE:
        return GLOBUS_SUCCESS;
    case GSS_S_CONTEXT_EXPIRED:
        err = globus_io_error_construct_context_expired(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            maj_stat,
            min_stat,
            0);
        break;

    case GSS_S_CREDENTIALS_EXPIRED:
        err = globus_io_error_construct_credentials_expired(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            maj_stat,
            min_stat,
            0);
        break;

    case GSS_S_FAILURE:
    case GSS_S_NO_CONTEXT:
    case GSS_S_BAD_QOP:
    default:
        globus_assert(GLOBUS_FALSE && "gss_wrap() failed");

        err = globus_io_error_construct_internal_error(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            myname);
        break;
    }
    err = globus_io_error_construct_bad_protection(
        GLOBUS_IO_MODULE,
        err,
        handle,
        maj_stat,
        min_stat,
        0);

    return globus_error_put(err);
}
/* globus_i_io_securesocket_wrap_buffer() */

/*
 * Function:    globus_i_io_securesocket_wrap_iov()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_i_io_securesocket_wrap_iov(
    globus_io_handle_t *        handle,
    struct iovec *          iov,
    globus_size_t           iovcnt,
    struct iovec **         new_iov,
    globus_size_t *         new_iovcnt)
{
    OM_uint32               maj_stat;
    OM_uint32               min_stat;
    int                 conf_state;
    gss_buffer_desc         data;
    globus_object_t *           err = GLOBUS_NULL;
    int                 src_iov_index;
    int                 dst_iov_index;
    globus_size_t           this_iov_wrapped;
    static char *           myname="globus_i_io_securesocket_wrap_iov";
    gss_buffer_desc                 wrapped_buffer;
    globus_bool_t           send_length = GLOBUS_FALSE;

    if(handle->securesocket_attr.channel_mode == GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR)
    {
        *new_iov = GLOBUS_NULL;
        *new_iovcnt = 0;
        return GLOBUS_SUCCESS;
    }

    data.value = iov[0].iov_base;
    data.length = (handle->max_wrap_length) > iov[0].iov_len ?
        iov[0].iov_len :
        handle->max_wrap_length;
    
    maj_stat = gss_wrap(&min_stat,
                        handle->context,
                        handle->securesocket_attr.protection_mode ==
                        GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE,
                        GSS_C_QOP_DEFAULT,
                        &data,
                        &conf_state,
                        &wrapped_buffer);

    if(maj_stat != GSS_S_COMPLETE)
    {
        *new_iov = GLOBUS_NULL;
        *new_iovcnt = 0;

        goto gss_exit;
    }

    /* compute the number of destination iovec struct we'll need */
    *new_iovcnt = 0;
    for(src_iov_index = 0; src_iov_index < iovcnt; src_iov_index++)
    {
        int             tmp_size;

        tmp_size = (int) iov[src_iov_index].iov_len;

        while(tmp_size > (int) handle->max_wrap_length)
        {
            (*new_iovcnt)++;
            if(tmp_size < handle->max_wrap_length)
            {
                tmp_size = 0;
            }
            else
            {
                tmp_size -= handle->max_wrap_length;
            }
        } 
        (*new_iovcnt)++;
    }
    if(! globus_l_io_is_ssl_packet(wrapped_buffer.value))
    {
        /* add in the number of length packets */
        *new_iovcnt *= 2;
        send_length = GLOBUS_TRUE;
    }

    (*new_iov) = (struct iovec *)
        globus_malloc(sizeof(struct iovec) * (*new_iovcnt));

    src_iov_index = 0;
    dst_iov_index = 0;

    /* Pack the first token we wrapped above (to check for SSL packets)
     * into the iovec
     */
    if(send_length)
    {
        (*new_iov)[dst_iov_index].iov_base = globus_malloc(4);
        *(((unsigned char *) (*new_iov)[dst_iov_index].iov_base)) = 
            (unsigned char) ((wrapped_buffer.length >> 24) & 0xff);
        *(((unsigned char *) (*new_iov)[dst_iov_index].iov_base)+1) = 
            (unsigned char) ((wrapped_buffer.length >> 16) & 0xff);
        *(((unsigned char *) (*new_iov)[dst_iov_index].iov_base)+2) = 
            (unsigned char) ((wrapped_buffer.length >>  8) & 0xff);
        *(((unsigned char *) (*new_iov)[dst_iov_index].iov_base)+3) = 
            (unsigned char) ((wrapped_buffer.length      ) & 0xff);
        (*new_iov)[dst_iov_index].iov_len = 4;
        dst_iov_index++;
    }
    (*new_iov)[dst_iov_index].iov_base = wrapped_buffer.value;
    (*new_iov)[dst_iov_index].iov_len = wrapped_buffer.length;
    dst_iov_index++;
    this_iov_wrapped = data.length;

    /* Pack the rest of the tokens into the iovec */
    while(dst_iov_index < *new_iovcnt)
    {
        while(this_iov_wrapped < iov[src_iov_index].iov_len)
        {
            data.value = ((char *) iov[src_iov_index].iov_base) +
                this_iov_wrapped;
            if(iov[src_iov_index].iov_len - this_iov_wrapped >
               handle->max_wrap_length)
            {
                data.length = handle->max_wrap_length;
            }
            else
            {
                data.length = 
                    iov[src_iov_index].iov_len - this_iov_wrapped;
            }
            maj_stat = gss_wrap(&min_stat,
                                handle->context,
                                handle->securesocket_attr.protection_mode ==
                                GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE,
                                GSS_C_QOP_DEFAULT,
                                &data,
                                &conf_state,
                                &wrapped_buffer);

            if(maj_stat != GSS_S_COMPLETE)
            {
                int cnt;
        
                for(cnt = dst_iov_index-1; cnt >= 0; cnt--)
                {
                    globus_free((*new_iov)[cnt].iov_base);
                }
            
                globus_free(*new_iov);
                *new_iov = GLOBUS_NULL;
                *new_iovcnt = 0;
                goto gss_exit;
            }
            this_iov_wrapped += data.length;
            if(send_length)
            {
                (*new_iov)[dst_iov_index].iov_base = globus_malloc(4);
                *(((unsigned char *) (*new_iov)[dst_iov_index].iov_base)) = 
                    (unsigned char) ((wrapped_buffer.length >> 24) & 0xff);
                *(((unsigned char *) (*new_iov)[dst_iov_index].iov_base)+1) = 
                    (unsigned char) ((wrapped_buffer.length >> 16) & 0xff);
                *(((unsigned char *) (*new_iov)[dst_iov_index].iov_base)+2) = 
                    (unsigned char) ((wrapped_buffer.length >>  8) & 0xff);
                *(((unsigned char *) (*new_iov)[dst_iov_index].iov_base)+3) = 
                    (unsigned char) ((wrapped_buffer.length      ) & 0xff);
                (*new_iov)[dst_iov_index].iov_len = 4;
                dst_iov_index++;
            }
            (*new_iov)[dst_iov_index].iov_base = wrapped_buffer.value;
            (*new_iov)[dst_iov_index].iov_len = wrapped_buffer.length;
            dst_iov_index++;
        }
        this_iov_wrapped = 0;
        src_iov_index++;
    }

    return GLOBUS_SUCCESS;

gss_exit:
    switch(maj_stat)
    {
    case GSS_S_COMPLETE:
        return GLOBUS_SUCCESS;
    case GSS_S_CONTEXT_EXPIRED:
        err = globus_io_error_construct_context_expired(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            maj_stat,
            min_stat,
            0);
        break;

    case GSS_S_CREDENTIALS_EXPIRED:
        err = globus_io_error_construct_credentials_expired(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            maj_stat,
            min_stat,
            0);
        break;

    case GSS_S_FAILURE:
    case GSS_S_NO_CONTEXT:
    case GSS_S_BAD_QOP:
    default:
        globus_assert(GLOBUS_FALSE && "gss_wrap() failed");

        err = globus_io_error_construct_internal_error(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            myname);
        break;
    }
    err = globus_io_error_construct_bad_protection(
        GLOBUS_IO_MODULE,
        err,
        handle,
        maj_stat,
        min_stat,
        0);

    return globus_error_put(err);
}
/* globus_i_io_securesocket_wrap_iov() */

/*
 * Function:    globus_l_io_securesocket_unwrap_data()
 *
 * Description: called with globus_i_io_mutex already locked
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_l_io_securesocket_unwrap_data(
    globus_io_handle_t *        handle)
{
    globus_io_input_token_t *       buffer;
    globus_io_buffer_t *        new_unwrapped_buffer;
    OM_uint32               maj_stat;
    OM_uint32               min_stat;
    int                 conf_state=0;
    gss_qop_t               qop_state = GSS_C_QOP_DEFAULT;
    globus_object_t *           err;

    /* try to unwrap any complete GSS packets */
    while(!globus_fifo_empty(&handle->wrapped_buffers))
    {
        /* look at the first packet. It contains a fifo of
         * data fragments, which combine to be a GSS packet
         */
        buffer = (globus_io_input_token_t *)
            globus_fifo_peek(&handle->wrapped_buffers);

        /* if the packet is complete (i.e., all of the fragments have
         * arrived), we can unwrap it.
         */
        if(buffer->token_to_read == 0)
        {
            gss_buffer_desc         token_buf;

            /* remove the packet from the fifo */
            globus_fifo_dequeue(&handle->wrapped_buffers);

            token_buf.value = (void *) buffer->token;
            token_buf.length = buffer->token_length;

            new_unwrapped_buffer = (globus_io_buffer_t *)
                globus_malloc(sizeof(globus_io_buffer_t));

            maj_stat = gss_unwrap(
                &min_stat,
                handle->context,
                &token_buf,
                &new_unwrapped_buffer->buffer,
                &conf_state,
                &qop_state);

            globus_free(token_buf.value);

            new_unwrapped_buffer->orig.value =
                new_unwrapped_buffer->buffer.value;
            new_unwrapped_buffer->orig.length =
                new_unwrapped_buffer->buffer.length;

            globus_fifo_enqueue(&handle->unwrapped_buffers,
                                new_unwrapped_buffer);

            buffer->token = GLOBUS_NULL;
            globus_free(buffer);

            if(maj_stat != GSS_S_COMPLETE ||
               (handle->securesocket_attr.protection_mode ==
                GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE &&
                conf_state == 0))
            {
                err = globus_io_error_construct_bad_protection(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle,
                    maj_stat,
                    min_stat,
                    0);
                return globus_error_put(err);
            }
        }
        else
        {
            break;
        }
    }
    return GLOBUS_SUCCESS;
}
/* globus_l_io_securesocket_unwrap_data() */

/*
 * Function:    globus_l_i_secure_read_callback()
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
static
void
globus_l_io_secure_read_callback(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result)
{
    globus_io_input_token_t *       buffer;
    globus_size_t           amt_read;
    globus_result_t         rc;
    globus_io_secure_read_info_t *  secure_read_info;
    globus_object_t *           err = GLOBUS_NULL;
#ifdef TARGET_ARCH_WIN32
	char dataWasUnwrapped= GLOBUS_FALSE;
	int returnCode;
#endif
    
    secure_read_info = (globus_io_secure_read_info_t *) arg;

    globus_i_io_mutex_lock();

    /* read wrapped token data from the handle */
    if(result == GLOBUS_SUCCESS)
    {
        /* If we were called with selecting == true, then we
	 * will need to try to read a new token, otherwise we
	 * will just use data in the buffer.
         */
	if(secure_read_info->selecting)
        {
	    /* if this is the first time we've tried to access
	     * data from this handle since the last unwrap, then
	     * the fifo of wrapped buffers may be empty so we'll need
	     * to allocate a new one.
             */
	    if(globus_fifo_empty(&handle->wrapped_buffers))
            {
		buffer = (globus_io_input_token_t *) 
		    globus_malloc(sizeof(globus_io_input_token_t));

		memset(buffer,
		       '\0',
		       sizeof(globus_io_input_token_t));
		/* Set this to a dummy non-zero value. Once the header
		 * has been parsed, this will be updated.
		 */
		buffer->token_to_read = 1;
	       
		globus_fifo_enqueue(&handle->wrapped_buffers,
				    buffer);
            }
	    /* This buffer will either be just allocated, or a partially
	     * filled token buffer from a previous read
	     */
	    buffer = (globus_io_input_token_t *) 
		globus_fifo_tail_peek(&handle->wrapped_buffers);

#ifdef TARGET_ARCH_WIN32
		// update the number of bytes read in case an asynchronous read
		// has just completed
		// WARNING: neither field will point to a valid address if this
		// function has been entered because of a fake completion packet
		if ( handle->winIoOperation_read.numberOfBytesProcessed > 0 )
		{
			if ( buffer->mysteryUpdateRead != NULL )
			{
				*(buffer->mysteryUpdateRead)+= 
				 handle->winIoOperation_read.numberOfBytesProcessed;
			}
			if ( buffer->mysteryUpdateToRead != NULL )
			{
				*(buffer->mysteryUpdateToRead)-= 
				 handle->winIoOperation_read.numberOfBytesProcessed;
			}
		}
#endif
        result = globus_l_io_read_input_token(handle,
                                              buffer);
#ifdef TARGET_ARCH_WIN32
			// The call to globus_l_io_securesocket_unwrap_data() below
			// may destroy the wrapped buffer, which is pointed to by
			// the local variable, "buffer". Consequently, "buffer" will
			// point to deallocated memory following that call.
			//
			// store the reading field data in case another read
			// has to be posted
			secure_read_info->mysteryBuffer= 
			 buffer->mysteryBuffer;
			secure_read_info->mysteryNumberOfBytes= 
			 buffer->mysteryNumberOfBytes;
			secure_read_info->mysteryUpdateRead=
			 buffer->mysteryUpdateRead;
			secure_read_info->mysteryUpdateToRead=
			 buffer->mysteryUpdateToRead;
#endif
            if(result != GLOBUS_SUCCESS)
            {
		err = globus_error_get(result);

		if(globus_io_eof(err) &&
		   !globus_fifo_empty(&handle->unwrapped_buffers))
		{
		    globus_object_free(err);

		    err = GLOBUS_NULL;
		}
		else
		{
		    goto error_exit;
		}
            }
	    else if(buffer->token_to_read == 0)
	    {
		result = globus_l_io_securesocket_unwrap_data(handle);
		if(result != GLOBUS_SUCCESS)
		{
		    err = globus_error_get(result);

		    goto error_exit;
		}
        
#ifdef TARGET_ARCH_WIN32
			// if the token_to_read variable was zero, then there must
			// have been a token to unwrap; and if 
			// globus_l_io_securesocket_unwrap_data() returned
			// successfully, the data must have been unwrapped and the
			// wrapped buffer discarded
			dataWasUnwrapped= GLOBUS_TRUE;
#endif        
	    }
        }
    }
    else
    {
        err = globus_error_get(result);
    }

    /* copy unwrapped data into user buffer */
    rc = globus_l_io_copy_unwrapped_data_to_buffer(
        handle,
        secure_read_info->buf + secure_read_info->nbytes_read,
        secure_read_info->max_nbytes - secure_read_info->nbytes_read,
        &amt_read);

    secure_read_info->nbytes_read += amt_read;
    if(rc != GLOBUS_SUCCESS)
    {
        err = globus_error_get(rc);
    }

    if(err != GLOBUS_NULL)
    {
        goto error_exit;
    }
    if(secure_read_info->nbytes_read >= secure_read_info->wait_for_nbytes)
    {
        globus_i_io_end_operation(handle, GLOBUS_I_IO_READ_OPERATION);
        /* callback now */
        globus_i_io_mutex_unlock();
        secure_read_info->callback(secure_read_info->arg,
                                   handle,
                                   GLOBUS_SUCCESS,
                                   secure_read_info->buf,
                                   secure_read_info->nbytes_read);
        globus_free(secure_read_info);
    }
    else
    {
        /* re-register read */
	secure_read_info->selecting = GLOBUS_TRUE;
        rc = globus_i_io_register_operation(
            handle,
            globus_l_io_secure_read_callback,
            secure_read_info,
            globus_i_io_default_destructor,
            GLOBUS_TRUE,
            GLOBUS_I_IO_READ_OPERATION);
        
        if(rc != GLOBUS_SUCCESS)
        {
            err = globus_error_get(rc);

            goto error_exit;
        }
#ifdef TARGET_ARCH_WIN32
		// first check whether the data was unwrapped; if so, post a
		// fake completion packet, otherwise post another read
		if ( dataWasUnwrapped )
        //if( globus_fifo_empty( &handle->wrapped_buffers ) )
		{
			returnCode= globus_i_io_windows_post_completion( 
					handle, 
					WinIoReading );
			if ( returnCode ) // serious error occurred
			{
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE, 
							GLOBUS_I_IO_READ_OPERATION);

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						returnCode );
				goto error_exit;
			}
		}
		else
		{
			returnCode= globus_i_io_windows_read( 
						handle, 
						secure_read_info->mysteryBuffer,
						secure_read_info->mysteryNumberOfBytes,
						1 );
			if ( returnCode == -1 )
			{
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE, 
							GLOBUS_I_IO_READ_OPERATION);

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						returnCode );
				goto error_exit;
			}
		}
#endif
        globus_i_io_mutex_unlock();
    }

    if(err != GLOBUS_SUCCESS)
    {
        globus_object_free(err);
    }
    return;

error_exit:
    globus_i_io_end_operation(handle, GLOBUS_I_IO_READ_OPERATION);
    
    globus_i_io_mutex_unlock();

    secure_read_info->callback(secure_read_info->arg,
                               handle,
                               globus_error_put(err),
                               secure_read_info->buf,
                               secure_read_info->nbytes_read);

    globus_free(secure_read_info);

    return;
}
/* globus_l_i_secure_read_callback() */

/*
 * Function:    globus_l_io_copy_unwrapped_data_to_buffer()
 *
 * Description: must be called with globus_i_io_mutex already locked
 *
 * Parameters:
 *
 * Returns:
 */
static
globus_result_t
globus_l_io_copy_unwrapped_data_to_buffer(
    globus_io_handle_t *        handle,
    globus_byte_t *         buf,
    globus_size_t           max_nbytes,
    globus_size_t *         nbytes_copied)
{
    globus_size_t           num_read=0;

    /* read data from the unwrapped buffers into the user-specified buffer */
    while(!globus_fifo_empty(&handle->unwrapped_buffers) &&
          num_read < max_nbytes)
    {
        globus_io_buffer_t *        buffer;
        globus_size_t           to_copy;

        buffer = (globus_io_buffer_t *)
            globus_fifo_peek(&handle->unwrapped_buffers);

        if(buffer->buffer.length + num_read < max_nbytes)
        {
            to_copy = buffer->buffer.length;
        }
        else 
        {
            to_copy = max_nbytes - num_read;
        }
        memcpy(buf + num_read,
               buffer->buffer.value,
               to_copy);

        num_read += to_copy;
        buffer->buffer.length -= to_copy;
        buffer->buffer.value = (globus_byte_t *) buffer->buffer.value +
            to_copy;

        if(buffer->buffer.length == 0)
        {
            globus_fifo_dequeue(&handle->unwrapped_buffers);
            globus_free(buffer->orig.value);
            globus_free(buffer);
        }
    }

    *nbytes_copied = num_read;

    return GLOBUS_SUCCESS;
}
/* globus_l_io_copy_unwrapped_data_to_buffer() */

/*
 * Function:    globus_i_io_securesocket_register_read()
 *
 * Description: called with globus_i_io_mutex already locked
 *
 * Parameters:
 *
 * Returns:
 */
globus_result_t
globus_i_io_securesocket_register_read(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buf,
    globus_size_t                       max_nbytes,
    globus_size_t                       wait_for_nbytes,
    globus_io_read_callback_t           callback,
    void *                              callback_arg)
{
    globus_result_t         rc;
    globus_object_t *           err;
    globus_size_t           num_read;
#ifdef TARGET_ARCH_WIN32
	int returnCode;
#endif

    globus_assert(handle != GLOBUS_NULL);

    /*
     * unwrap any data which has been read, but not processed,
     * and place it in a queue in the handle
     */
    rc = globus_l_io_securesocket_unwrap_data(handle);
    if(rc != GLOBUS_SUCCESS)
    {
        err = globus_error_get(rc);

        goto error_exit;
    }
    
    /* copy data from the queued up list of unwrapped buffers
     * in the handle to the user's buffer
     */
    rc = globus_l_io_copy_unwrapped_data_to_buffer(
        handle,
        buf,
        max_nbytes,
        &num_read);

    if(rc != GLOBUS_SUCCESS)
    {
        err = globus_error_get(rc);

        goto error_exit;
    }

    {
        globus_io_secure_read_info_t    *secure_read_info;

        secure_read_info = (globus_io_secure_read_info_t *)
            globus_malloc(sizeof(globus_io_secure_read_info_t));
        secure_read_info->buf = buf;
        secure_read_info->max_nbytes = max_nbytes;
        secure_read_info->wait_for_nbytes = wait_for_nbytes;
        secure_read_info->nbytes_read = num_read;
        secure_read_info->arg = callback_arg;
        secure_read_info->callback = callback;
	secure_read_info->selecting = (num_read >= wait_for_nbytes)
                                            ? GLOBUS_FALSE /* don't select */
                                            : GLOBUS_TRUE /* select */;

        /* we need to get more data from the network if we haven't
         * copied enough data from the buffer, otherwise, we just need
         * to kick out an event from the handle_events loop
         */
        rc = globus_i_io_start_operation(
            handle,
            GLOBUS_I_IO_READ_OPERATION);
    
        if(rc == GLOBUS_SUCCESS)
        {
            rc = globus_i_io_register_operation(
                handle,
                globus_l_io_secure_read_callback,
                secure_read_info,
                globus_i_io_default_destructor,
                secure_read_info->selecting,
		GLOBUS_I_IO_READ_OPERATION);
            
            if(rc != GLOBUS_SUCCESS)
            {
                globus_i_io_end_operation(handle, GLOBUS_I_IO_READ_OPERATION);
            }
        }
            
        if(rc != GLOBUS_SUCCESS)
        {
            err = globus_error_get(rc);
            globus_free(secure_read_info);

            goto error_exit;
        }
#ifdef TARGET_ARCH_WIN32
		// post a completion packet only if data is needed
		else if( num_read < wait_for_nbytes )
		{
			returnCode= globus_i_io_windows_post_completion( 
					handle, 
					WinIoReading );
			if ( returnCode ) // serious error occurred
			{
				globus_i_io_unregister_operation( handle, GLOBUS_TRUE, 
				 GLOBUS_I_IO_READ_OPERATION );

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						returnCode );
				goto error_exit;
			}
		}
#endif /* TARGET_ARCH_WIN32 */
    }

    return GLOBUS_SUCCESS;
    
error_exit:

    return globus_error_put(err);
}
/* globus_i_io_securesocket_register_read() */


static
void 
globus_l_io_init_sec_context(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result)
{
    globus_io_authentication_info_t *   init_info;
    globus_object_t *           err;
#ifdef TARGET_ARCH_WIN32
	int rc;
#endif

    init_info = (globus_io_authentication_info_t *) arg;
    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_init_sec_context(): entering, fd=%d\n", 
        handle->fd));

    globus_i_io_mutex_lock();

    init_info->maj_stat = globus_gss_assist_init_sec_context_async(
        &init_info->min_stat,
        handle->securesocket_attr.credential,
        &handle->context,
        handle->securesocket_attr.authorized_identity,
        init_info->flags,
        &init_info->ret_flags,
        init_info->input_token.token,
        init_info->input_token.token_length,
        (void **) &init_info->output_buffer,
        &init_info->output_buflen);

    if(init_info->input_token.token)
    {
        globus_free(init_info->input_token.token);
        memset(&init_info->input_token,
               '\0',
               sizeof(globus_io_input_token_t));
    }
    if(init_info->maj_stat != GSS_S_COMPLETE &&
       init_info->maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        err = globus_io_error_construct_authentication_failed(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            (int) init_info->maj_stat,
            (int) init_info->min_stat,
            0);
    
        goto error_exit;
    }
    else if(init_info->maj_stat == GSS_S_COMPLETE &&
            handle->securesocket_attr.protection_mode == GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE &&
            ((init_info->ret_flags & GSS_C_CONF_FLAG) == 0))
    {
        /* Required encryption, but didn't get it */
        err = globus_io_error_construct_bad_protection(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            (int) init_info->maj_stat,
            (int) init_info->min_stat,
            0);
        goto error_exit;
    }
    
    result = GLOBUS_SUCCESS;
    
    if(init_info->output_buflen != 0)
    {
        /* send token asynchronously. When completed, this will register
         * a receive of the input token, or call the user code, depending
         * on init_info->maj_stat
         */
        result = globus_i_io_register_operation(
            handle,
            globus_l_io_write_auth_token,
            init_info,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
#ifdef TARGET_ARCH_WIN32
		if ( result == GLOBUS_SUCCESS )
		{
			// post a packet in order to trigger the callback
			rc= globus_i_io_windows_post_completion( 
				handle, 
				WinIoWriting );
			if ( rc ) // a fatal error occurred
			{
				// unregister the write operation
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE,
				 GLOBUS_I_IO_WRITE_OPERATION );

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						rc );
				goto error_exit;
			}
		}
#endif
    }
    else
    {
        if(init_info->maj_stat == GSS_S_CONTINUE_NEEDED)
        {
            /* get another token */
            result = globus_i_io_register_operation(
                handle,
                globus_l_io_read_auth_token,
                init_info,
                GLOBUS_NULL,
                GLOBUS_TRUE,
                GLOBUS_I_IO_READ_OPERATION);
#ifdef TARGET_ARCH_WIN32
			if ( result == GLOBUS_SUCCESS )
			{
				// post a packet in order to trigger the callback
				rc= globus_i_io_windows_post_completion( 
					handle, 
					WinIoReading );
				if ( rc ) // a fatal error occurred
				{
					// unregister the read operation
					globus_i_io_unregister_operation( handle, 
					 GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION );

					err = globus_io_error_construct_system_failure(
							GLOBUS_IO_MODULE,
							GLOBUS_NULL,
							handle,
							rc );
					goto error_exit;
				}
			}
#endif
        }
        else
        {
            if(handle->securesocket_attr.auth_callback)
            {
                result = globus_l_io_securesocket_call_auth_callback(handle);
                if(result != GLOBUS_SUCCESS)
                {
                    /* not authorized */
                    err = globus_error_get(result);
                    goto error_exit;
                }
            }
            
            globus_i_io_end_operation(
                handle, 
                GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        
            globus_i_io_mutex_unlock();

            /* completed */
            init_info->callback(init_info->callback_arg,
                                handle,
                                GLOBUS_SUCCESS,
                                init_info);
            globus_free(init_info);
            
            goto exit;
        }
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        goto error_exit;
    }
    
    globus_i_io_mutex_unlock();
exit:    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_init_sec_context(): exiting, fd=%d\n", 
        handle->fd));
        
    return;
    
error_exit:
    
    err = globus_io_error_construct_authentication_failed(
        GLOBUS_IO_MODULE,
        err,
        handle,
        (int) init_info->maj_stat,
        (int) init_info->min_stat,
        0);
    
    globus_i_io_end_operation(
        handle, 
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        
    globus_i_io_close(handle);
    handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
    
    globus_i_io_mutex_unlock();
    init_info->callback(init_info->callback_arg,
                        handle,
                        globus_error_put(err),
                        init_info);
    globus_free(init_info);
    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_init_sec_context(): exiting with error, fd=%d\n", 
        handle->fd));
}
/* globus_l_io_init_sec_context() */

static
void 
globus_l_io_accept_sec_context(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result)
{
    globus_io_authentication_info_t *   accept_info;
    globus_object_t *           err;
#ifdef TARGET_ARCH_WIN32
	int rc;
#endif

    accept_info = (globus_io_authentication_info_t *) arg;

    globus_i_io_mutex_lock();

    accept_info->maj_stat = globus_gss_assist_accept_sec_context_async(
        &accept_info->min_stat,
        &handle->context,
        handle->securesocket_attr.credential,
        &accept_info->name,
        &accept_info->ret_flags,
        &accept_info->user_to_user,
        accept_info->input_token.token,
        accept_info->input_token.token_length,
        (void **) &accept_info->output_buffer,
        &accept_info->output_buflen,
        &handle->delegated_credential);

    if(accept_info->input_token.token)
    {
        globus_free(accept_info->input_token.token);
        memset(&accept_info->input_token,
               '\0',
               sizeof(globus_io_input_token_t));
    }
    if(accept_info->maj_stat != GSS_S_COMPLETE &&
       accept_info->maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        err = globus_io_error_construct_authentication_failed(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            (int) accept_info->maj_stat,
            (int) accept_info->min_stat,
            0);
        goto error_exit;
    }
    else if(accept_info->maj_stat == GSS_S_COMPLETE &&
            handle->securesocket_attr.protection_mode == GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE &&
            ((accept_info->ret_flags & GSS_C_CONF_FLAG) == 0))
    {
        /* Required encryption, but didn't get it */
        err = globus_io_error_construct_bad_protection(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            (int) accept_info->maj_stat,
            (int) accept_info->min_stat,
            0);
        goto error_exit;
    }
    
    result = GLOBUS_SUCCESS;
    if(accept_info->output_buflen != 0)
    {
        /* send token asynchronously. When completed, this will register
         * a receive of the input token, or call the user code, depending
         * on init_info->maj_stat
         */
        result = globus_i_io_register_operation(
            handle,
            globus_l_io_write_auth_token,
            accept_info,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
#ifdef TARGET_ARCH_WIN32
		if ( result == GLOBUS_SUCCESS )
		{
			// post a packet in order to trigger the callback
			rc= globus_i_io_windows_post_completion( 
				handle, 
				WinIoWriting );
			if ( rc ) // a fatal error occurred
			{
				// unregister the write operation
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE,
				 GLOBUS_I_IO_WRITE_OPERATION );
				goto error_exit;
			}
		}
#endif
    }
    else
    {
        if(accept_info->maj_stat == GSS_S_CONTINUE_NEEDED)
        {
            /* get another token */
            result = globus_i_io_register_operation(
                handle,
                globus_l_io_read_auth_token,
                accept_info,
                GLOBUS_NULL,
                GLOBUS_TRUE,
                GLOBUS_I_IO_READ_OPERATION);
#ifdef TARGET_ARCH_WIN32
			// post a packet in order to trigger the callback
			rc= globus_i_io_windows_post_completion( 
				 handle, 
				 WinIoReading );
			if ( rc ) // a fatal error occurred
			{
				// unregister the read operation
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE,
				 GLOBUS_I_IO_READ_OPERATION );

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						rc );
				goto error_exit;
			}
#endif
        }
        else
        {
            globus_i_io_end_operation(
                handle, 
                GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        
            globus_i_io_mutex_unlock();
            /* completed */
            accept_info->callback(accept_info->callback_arg,
                                  handle,
                                  GLOBUS_SUCCESS,
                                  accept_info);
            if(accept_info->name)
            {
                globus_free(accept_info->name);
            }
            globus_free(accept_info);

            return;
        }
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        goto error_exit;
    }
    
    globus_i_io_mutex_unlock();

    return;
    
error_exit:

    err = globus_io_error_construct_authentication_failed(
        GLOBUS_IO_MODULE,
        err,
        handle,
        (int) accept_info->maj_stat,
        (int) accept_info->min_stat,
        0);
    
    globus_i_io_end_operation(
        handle, 
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        
    globus_i_io_mutex_unlock();

    accept_info->callback(accept_info->callback_arg,
                          handle,
                          globus_error_put(err),
                          accept_info);
    if(accept_info->name)
    {
        globus_free(accept_info->name);
    }
    globus_free(accept_info);
}

static
void
globus_l_io_write_auth_token(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result)
{
    globus_io_authentication_info_t *   init_info;
    globus_object_t *           err;
#ifdef TARGET_ARCH_WIN32
	globus_byte_t * mysteryBuffer;
	globus_size_t numberOfBytes;
	int rc;
#endif

    init_info = (globus_io_authentication_info_t *) arg;
    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_write_auth_token(): entering, fd=%d\n", 
        handle->fd));
        
    globus_i_io_mutex_lock();
    if(init_info->output_buffer_header == GLOBUS_NULL)
    {
        /* If this is not an SSL token, then we must prepend a
         * four-byte length header
         */
        if(handle->securesocket_attr.channel_mode ==
           GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP ||
           (handle->securesocket_attr.channel_mode ==
            GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR &&
            (handle->securesocket_attr.delegation_mode !=
             GLOBUS_IO_SECURE_DELEGATION_MODE_NONE ||
             init_info->delegation_callback != NULL))||
           ! globus_l_io_is_ssl_packet(init_info->output_buffer) )
        {
            init_info->output_buffer_header = globus_malloc(4);
            *(((unsigned char *) init_info->output_buffer_header)) = 
                (unsigned char) ((init_info->output_buflen >> 24) & 0xff);
            *(((unsigned char *) init_info->output_buffer_header+1)) = 
                (unsigned char) ((init_info->output_buflen >> 16) & 0xff);
            *(((unsigned char *) init_info->output_buffer_header+2)) = 
                (unsigned char) ((init_info->output_buflen >>  8) & 0xff);
            *(((unsigned char *) init_info->output_buffer_header+3)) = 
                (unsigned char) ((init_info->output_buflen      ) & 0xff);

            init_info->output_header_offset = 0;
            init_info->output_header_len = 4;
        }
    }

    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);

        goto error_exit;
    }

    if(init_info->output_header_offset < init_info->output_header_len)
    {
        globus_size_t       amt_sent;

        result =
            globus_i_io_try_write(
                handle,
                init_info->output_buffer_header +
                init_info->output_header_offset,
                init_info->output_header_len -
                init_info->output_header_offset,
                &amt_sent);
        if(result != GLOBUS_SUCCESS)
        {
            err = globus_error_get(result);

            goto error_exit;
        }

        init_info->output_header_offset += amt_sent;
        if(init_info->output_header_offset == init_info->output_header_len)
        {
            /* sent entire token length */
        }
        else
        {
#ifdef TARGET_ARCH_WIN32
			// store the necessary information for purposes of posting
			// another write below
			mysteryBuffer= init_info->output_buffer_header + 
				init_info->output_header_offset;
			numberOfBytes= init_info->output_header_len - 
				init_info->output_header_offset;
#endif
            goto continue_write;
        }
    }

    if(init_info->output_buffer)
    {
        globus_size_t       amt_sent;

        result = globus_i_io_try_write(handle,
                                       init_info->output_buffer +
                                       init_info->output_offset,
                                       init_info->output_buflen -
                                       init_info->output_offset,
                                       &amt_sent);
        if(result != GLOBUS_SUCCESS)
        {
            err = globus_error_get(result);

            goto error_exit;
        }

        init_info->output_offset += amt_sent;
        if(init_info->output_offset == init_info->output_buflen)
        {
            /* sent entire token, so free token length and token */
            if(init_info->output_buffer_header)
            {
                globus_free(init_info->output_buffer_header);
                init_info->output_buffer_header = GLOBUS_NULL;
            }
            init_info->output_header_len = 0;
            init_info->output_header_offset = 0;

            globus_free(init_info->output_buffer);
            init_info->output_buffer = GLOBUS_NULL;
            init_info->output_buflen = 0;
            init_info->output_offset = 0;
        }
        else
        {
#ifdef TARGET_ARCH_WIN32
			// store the necessary information for purposes of posting
			// another write below
			mysteryBuffer= init_info->output_buffer + 
				init_info->output_offset;
			numberOfBytes= init_info->output_buflen - 
				init_info->output_offset;
#endif
            goto continue_write;
        }
    }

    /* all of the output token is sent... schedule read of input token, or
     * completion
     */
    if(init_info->maj_stat == GSS_S_COMPLETE)
    {
        result = GLOBUS_SUCCESS;

        if(handle->securesocket_attr.auth_callback)
        {
            result = globus_l_io_securesocket_call_auth_callback(handle);
            if(result != GLOBUS_SUCCESS) 
            {
                /* Not authorized */
                globus_i_io_close(handle);
                handle->state = GLOBUS_IO_HANDLE_STATE_INVALID;
            }
        }
        
        globus_i_io_end_operation(
            handle, 
            GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
                
        globus_i_io_mutex_unlock();

        init_info->callback(init_info->callback_arg,
                            handle,
                            result,
                            init_info);
        if(init_info->name)
        {
            globus_free(init_info->name);
        }
        globus_free(init_info);

        goto do_return;
    }

    /* once we've sent a token, and we know that we are not done yet,
     * we need to read another token to feed into the iterator
     */
    result = globus_i_io_register_operation(
        handle,
        globus_l_io_read_auth_token,
        init_info,
        GLOBUS_NULL,
        GLOBUS_TRUE,
        GLOBUS_I_IO_READ_OPERATION);

    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);

        goto error_exit;
    }
#ifdef TARGET_ARCH_WIN32
	else
	{
		// post a packet in order to trigger the callback
		rc= globus_i_io_windows_post_completion( 
				handle, 
				WinIoReading );
		if ( rc ) // a fatal error occurred
		{
			// unregister the read operation
			globus_i_io_unregister_operation( handle, GLOBUS_FALSE,
			 GLOBUS_I_IO_READ_OPERATION );

			err = globus_io_error_construct_system_failure(
					GLOBUS_IO_MODULE,
					GLOBUS_NULL,
					handle,
					rc );
			goto error_exit;
		}
	}
#endif

    globus_i_io_mutex_unlock();

do_return:    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_write_auth_token(): exiting, fd=%d\n", 
        handle->fd));
        
    return;

continue_write:

    result = globus_i_io_register_operation(
        handle,
        globus_l_io_write_auth_token,
        init_info,
        GLOBUS_NULL,
        GLOBUS_TRUE,
        GLOBUS_I_IO_WRITE_OPERATION);
    
    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);

        goto error_exit;
    }
#ifdef TARGET_ARCH_WIN32
	else // post another write
	{		
		rc= globus_i_io_windows_write( handle, 
			mysteryBuffer, 
			numberOfBytes, 
			1, 0 );
		if ( rc == -1 ) // a fatal error occurred
		{
			// unregister the write; NOTE: if we post the write before
			// calling the registration function, the completion packet
			// might return before the registration function can be called
			// in a multi-threaded environment
			globus_i_io_unregister_operation( handle, GLOBUS_FALSE,
			 GLOBUS_I_IO_WRITE_OPERATION );

			err = globus_io_error_construct_system_failure(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				handle,
				errno );
			goto error_exit;
		}
	}
#endif
    
    globus_i_io_mutex_unlock();
    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_write_auth_token(): exiting, fd=%d\n", 
        handle->fd));
    return;

error_exit:
    err = globus_io_error_construct_authentication_failed(
        GLOBUS_IO_MODULE,
        err,
        handle,
        (int) init_info->maj_stat,
        (int) init_info->min_stat,
        0);
    
    globus_i_io_end_operation(
        handle, 
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
            
    globus_i_io_mutex_unlock();

    init_info->callback(init_info->callback_arg,
                        handle,
                        globus_error_put(err),
                        init_info);
    globus_free(init_info);
    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_write_auth_token(): exiting with error, fd=%d\n", 
        handle->fd));
}
/* globus_l_io_write_auth_token() */

static
void
globus_l_io_read_auth_token(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result)
{
    globus_io_authentication_info_t *   init_info;
    globus_object_t *           err;
#ifdef TARGET_ARCH_WIN32
	int rc;
#endif

    init_info = (globus_io_authentication_info_t *) arg;
    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_read_auth_token(): entering, fd=%d\n", 
        handle->fd));
        
    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        goto error_exit;
    }

#ifdef TARGET_ARCH_WIN32
	// update the number of bytes read in case an asynchronous read
	// has just completed
	// WARNING: neither field will point to a valid address if this
	// function has been entered because of a fake completion packet
	if ( handle->winIoOperation_read.numberOfBytesProcessed > 0 )
	{
		if ( init_info->input_token.mysteryUpdateRead != NULL )
		{
			*(init_info->input_token.mysteryUpdateRead)+= 
			  handle->winIoOperation_read.numberOfBytesProcessed;
		}
		if ( init_info->input_token.mysteryUpdateToRead != NULL )
		{
			*(init_info->input_token.mysteryUpdateToRead)-= 
			  handle->winIoOperation_read.numberOfBytesProcessed;
		}
	}
#endif

    result = globus_l_io_read_input_token(handle,
                                          &init_info->input_token);
                 

    if(init_info->input_token.token_length_read != 0)
    {
        init_info->any_token_received = GLOBUS_TRUE;
    }

    if(init_info->input_token.error_occurred)
    {
        err = globus_error_get(result);
        goto error_exit;
    }
    else if(init_info->input_token.token != GLOBUS_NULL &&
            init_info->input_token.token_to_read == 0)
    {
        /* read entire token, 
         * register init handler to continue the GSSAPI authenticaiton
         */
        init_info->iteration(init_info,
                             handle,
                             GLOBUS_SUCCESS);
    
        goto do_return;
    }
    
    globus_i_io_mutex_lock();
    result = globus_i_io_register_operation(
        handle,
        globus_l_io_read_auth_token,
        init_info,
        GLOBUS_NULL,
        GLOBUS_TRUE,
        GLOBUS_I_IO_READ_OPERATION);
    
    if(result != GLOBUS_SUCCESS)
    {
	    globus_i_io_mutex_unlock();
        err = globus_error_get(result);

        goto error_exit;
    }

#ifdef TARGET_ARCH_WIN32
	// post another read
	rc= globus_i_io_windows_read( handle, 
		init_info->input_token.mysteryBuffer,
		init_info->input_token.mysteryNumberOfBytes,
		 1 );
	if ( rc == -1 ) // a fatal error occurred
	{
		// unregister the read operation
		globus_i_io_unregister_operation( handle, GLOBUS_FALSE,
		 GLOBUS_I_IO_READ_OPERATION );
	    globus_i_io_mutex_unlock();

		err = globus_io_error_construct_system_failure(
			GLOBUS_IO_MODULE,
			GLOBUS_NULL,
			handle,
			errno );
		goto error_exit;
	}
#endif
    globus_i_io_mutex_unlock();
    
do_return:
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_read_auth_token(): exiting, fd=%d\n", 
        handle->fd));

    return;

error_exit:
    if(init_info->any_token_received)
    {
        /* If we were in the middle of authentication, or after it
         * completed, chain the error result from the read to an
         * authentication error
         */
        err = globus_io_error_construct_authentication_failed(
            GLOBUS_IO_MODULE,
            err,
            handle,
            (int) init_info->maj_stat,
            (int) init_info->min_stat,
            0);
    }
    
    globus_i_io_mutex_lock();
    globus_i_io_end_operation(
        handle, 
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
    globus_i_io_mutex_unlock();
    
    init_info->callback(init_info->callback_arg,
                        handle,
                        globus_error_put(err),
                        init_info);
    if(init_info->input_token.token)
    {
        globus_free(init_info->input_token.token);
        memset(&init_info->input_token,
               '\0',
               sizeof(globus_io_input_token_t));
    }
    if(init_info->name)
    {
        globus_free(init_info->name);
    }
    globus_free(init_info);
    
    globus_i_io_debug_printf(3, (stderr, 
        "globus_l_io_read_auth_token(): exiting with error, fd=%d\n", 
        handle->fd));
}
/* globus_l_io_read_auth_token() */

static
void
globus_l_io_secure_connect_callback(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result,
    globus_io_authentication_info_t *   init_info)
{
    globus_i_io_callback_info_t *   callback_info;
    globus_object_t *           err = GLOBUS_SUCCESS;

    callback_info = (globus_i_io_callback_info_t *) arg;

    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);

        goto error_exit;
    }
    if(handle->securesocket_attr.channel_mode !=
       GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR)
    {
        OM_uint32           max_input_size;
        
        init_info->maj_stat =
            gss_wrap_size_limit(&init_info->min_stat,
                                handle->context,
                                handle->securesocket_attr.protection_mode ==
                                GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE,
                                GSS_C_QOP_DEFAULT,
                                1<<30,
                                &max_input_size);
        if(init_info->maj_stat != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
        handle->max_wrap_length = (globus_size_t) max_input_size;
        
        globus_fifo_init(&handle->wrapped_buffers);
        globus_fifo_init(&handle->unwrapped_buffers);
    }

    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
    
    callback_info->callback(callback_info->callback_arg,
                            handle,
                            GLOBUS_SUCCESS);
    globus_free(callback_info);

    return;

error_exit:
    if(err == GLOBUS_SUCCESS)
    {
        err = globus_io_error_construct_authentication_failed(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            (int) init_info->maj_stat,
            (int) init_info->min_stat,
            0);
    }
    
    callback_info->callback(callback_info->callback_arg,
                            handle,
                            globus_error_put(err));
    globus_free(callback_info);
}
/* globus_l_io_secure_connect_callback() */

/* called with mutex --unlocked-- */
static
void
globus_l_io_secure_accept_callback(
    void *              arg,
    globus_io_handle_t *        handle,
    globus_result_t         result,
    globus_io_authentication_info_t *   info)
{
    globus_i_io_callback_info_t *   callback_info;
    globus_object_t *           err;

    callback_info = (globus_i_io_callback_info_t *) arg;

    if(result != GLOBUS_SUCCESS)
    {
        callback_info->callback(callback_info->callback_arg,
                                handle,
                                result);
        globus_free(callback_info);
        return;
    }

    globus_i_io_mutex_lock();

    /* do authorization now */
    switch(handle->securesocket_attr.authorization_mode)
    {
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF:
        if(info->user_to_user != GLOBUS_TRUE)
        {
            /* authorized */
            goto no_authorization;
        }
        else
        {
            break;
        }
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY:
        if(strcmp(info->name,
                  handle->securesocket_attr.authorized_identity) == 0)
        {
            /* authorized */
            break;
        }
        else
        {
            goto no_authorization;
        }
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK:
        globus_i_io_mutex_unlock();
        if(handle->securesocket_attr.auth_callback(
               handle->securesocket_attr.auth_callback_arg,
               handle,
               GLOBUS_SUCCESS,
               info->name,
               handle->context))
        {
            globus_i_io_mutex_lock();
            /* authorized */
            break;
        }
        else
        {
            globus_i_io_mutex_lock();
            goto no_authorization;
        }
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST:
    case GLOBUS_IO_SECURE_AUTHORIZATION_MODE_NONE:
        goto no_authorization;
    }
    
    /* determine maximum message size for later wrap()s */
    if(handle->securesocket_attr.channel_mode !=
       GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR)
    {
        OM_uint32           max_input_size;
        
        info->maj_stat =
            gss_wrap_size_limit(&info->min_stat,
                                handle->context,
                                handle->securesocket_attr.protection_mode ==
                                GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE,
                                GSS_C_QOP_DEFAULT,
                                1<<30,
                                &max_input_size);
        if(info->maj_stat != GLOBUS_SUCCESS)
        {
            goto error_exit;
        }
        handle->max_wrap_length = (globus_size_t) max_input_size;
        
        globus_fifo_init(&handle->wrapped_buffers);
        globus_fifo_init(&handle->unwrapped_buffers);
    }

    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;

    globus_i_io_mutex_unlock();
    callback_info->callback(callback_info->callback_arg,
                            handle,
                            GLOBUS_SUCCESS);
    globus_free(callback_info);

    return;

no_authorization:
    err = globus_io_error_construct_authorization_failed(
        GLOBUS_IO_MODULE,
        GLOBUS_NULL,
        handle,
        (int) info->maj_stat,
        (int) info->min_stat,
        0);

    globus_i_io_mutex_unlock();
    callback_info->callback(callback_info->callback_arg,
                            handle,
                            globus_error_put(err));
    globus_free(callback_info);
    return;

error_exit:
    err = globus_io_error_construct_authentication_failed(
        GLOBUS_IO_MODULE,
        GLOBUS_NULL,
        handle,
        (int) info->maj_stat,
        (int) info->min_stat,
        0);

    globus_i_io_mutex_unlock();
    callback_info->callback(callback_info->callback_arg,
                            handle,
                            globus_error_put(err));
    globus_free(callback_info);
}
/* globus_l_io_secure_accept_callback() */

static
globus_bool_t
globus_l_io_is_ssl_packet(void * token)
{
    unsigned char * t = (unsigned char *) token;
    
    if((t[0] >= 20 &&
        t[0] <= 26 &&
        (t[1] == 3 && (t[2] == 0 || t[2] == 1) ||
         t[1] == 2 && t[2] == 0)) ||
       ((t[0] & 0x80) && t[2] == 1)) 
    {
        return GLOBUS_TRUE;
    }
    else
    {
        return GLOBUS_FALSE;
    }
}
/* globus_l_io_is_ssl_packet() */

/*
 * Function:    globus_l_io_read_input_token()
 *
 */
static
globus_result_t
globus_l_io_read_input_token(
    globus_io_handle_t *                handle,
    globus_io_input_token_t *           input_token)
{
    globus_result_t                     result;
    globus_size_t                       amt_read;
    globus_object_t *                   err;
    int                                 save_errno;
    static int                          count=0;

    count++;
    
    /* read the token length header if we haven't already? */
    if(input_token->token_length_read < 4)
    {
        result = globus_i_io_try_read(handle,
                                      input_token->token_length_buffer +
                                      input_token->token_length_read,
                                      4 - input_token->token_length_read,
                                      &amt_read);
        if(result != GLOBUS_SUCCESS)
        {
            goto read_failed_exit;
        }
        input_token->token_length_read += amt_read;

        if(input_token->token_length_read < 4)
        {
#ifdef TARGET_ARCH_WIN32
			// store necessary information in order to post another read
			input_token->mysteryBuffer= input_token->token_length_buffer 
				+ input_token->token_length_read;
			input_token->mysteryNumberOfBytes= 
				4 - input_token->token_length_read;
			input_token->mysteryUpdateRead= 
				&(input_token->token_length_read);
			input_token->mysteryUpdateToRead= NULL;
#endif
            return GLOBUS_SUCCESS;
        }
    }

    /* parsed the token length header if we haven't already? */
    if(input_token->token == GLOBUS_NULL)
    {
        if(! globus_l_io_is_ssl_packet(input_token->token_length_buffer))
        {
            globus_byte_t *         c;
        
            c = input_token->token_length_buffer;
        
            input_token->token_length  = ((globus_size_t) (*((c)++))) << 24;
            input_token->token_length |= ((globus_size_t) (*((c)++))) << 16;
            input_token->token_length |= ((globus_size_t) (*((c)++))) << 8;
            input_token->token_length |= ((globus_size_t) (*((c)++)));
        
            input_token->token_to_read = input_token->token_length;
            input_token->token_offset  = 0;

            input_token->token = (globus_byte_t *) globus_libc_malloc(input_token->token_length);
            save_errno = errno;

            if(input_token->token == GLOBUS_NULL)
            {
                input_token->error_occurred = GLOBUS_TRUE;
                err = globus_io_error_construct_system_failure(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle,
                    save_errno);
                return globus_error_put(err);
            }
        }
        else
        {
            result = globus_i_io_try_read(handle,
                                          input_token->token_length_buffer +
                                          input_token->token_length_read,
                                          5 - input_token->token_length_read,
                                          &amt_read);
            if(result != GLOBUS_SUCCESS)
            {
                goto read_failed_exit;
            }
            else if(amt_read < (5 - input_token->token_length_read))
            {
#ifdef TARGET_ARCH_WIN32
				// store necessary information in order to post another read
				input_token->mysteryBuffer= input_token->token_length_buffer 
					+ input_token->token_length_read;
				input_token->mysteryNumberOfBytes= 
					5 - input_token->token_length_read;
				input_token->mysteryUpdateRead= 
					&(input_token->token_length_read);
				input_token->mysteryUpdateToRead= NULL;
#endif
                return GLOBUS_SUCCESS;
            }
            else
            {
                globus_byte_t *         c;
        
                c = input_token->token_length_buffer;
                if (*c & 0x80)
                {
                    input_token->token_length  = ((globus_size_t) (*((c)++)) & 0x7f) << 8;
                    input_token->token_length |= ((globus_size_t) (*((c)++))) ;
                    input_token->token_length += 2;
                }
                else
                {
                    c = input_token->token_length_buffer + 3;
                    input_token->token_length  = ((globus_size_t) (*((c)++))) << 8;
                    input_token->token_length |= ((globus_size_t) (*((c)++))) ;
                    input_token->token_length += 5;
                }

                input_token->token = (globus_byte_t *) globus_libc_malloc(input_token->token_length);
                save_errno = errno;
        
                if(input_token->token == GLOBUS_NULL)
                {
                    input_token->error_occurred = GLOBUS_TRUE;
                    err = globus_io_error_construct_system_failure(
                        GLOBUS_IO_MODULE,
                        GLOBUS_NULL,
                        handle,
                        save_errno);
                    return globus_error_put(err);
                }
                memcpy(input_token->token,
                       input_token->token_length_buffer,
                       5);
                input_token->token_to_read = input_token->token_length - 5;
                input_token->token_offset = 5;
            }
        }
    }

    
    /* Read the token if we haven't already? */
    if(input_token->token_to_read > 0)
    {
        result = globus_i_io_try_read(handle,
                                      input_token->token +
                                      input_token->token_offset,
                                      input_token->token_to_read,
                                      &amt_read);
        if(result != GLOBUS_SUCCESS)
        {
            goto read_failed_exit;
        }
        input_token->token_to_read -= amt_read;
        input_token->token_offset += amt_read;

        if(input_token->token_to_read != 0)
        {
#ifdef TARGET_ARCH_WIN32
			// store necessary information in order to post another read
			input_token->mysteryBuffer= input_token->token +
				input_token->token_offset;
			input_token->mysteryNumberOfBytes= input_token->token_to_read;
			input_token->mysteryUpdateRead= &(input_token->token_offset);
			input_token->mysteryUpdateToRead= &(input_token->token_to_read);
#endif
            return GLOBUS_SUCCESS;
        }
    }

    return GLOBUS_SUCCESS;

read_failed_exit:
    input_token->error_occurred = GLOBUS_TRUE;
    
    return result;
}
/* globus_l_io_read_input_token() */

/**
 * Asynchronous credential delegation initiation.
 *
 * This call initiates credential delegation. It is assumed that the
 * user will synchronize this call with the accepting side. It is also
 * assumed that user will not try to send or read data while this
 * operation is in progress (i.e. the user should not operate on the
 * Globus IO handle until the callback is received) and that the read
 * buffer has been flushed before this function is called.
 *
 * @param handle
 *        The handle to use for this operation. The handle must be of
 *        the type GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED and must
 *        contain a valid security context.
 * @param cred_handle
 *        The credential to be delegated. If this parameter is set to
 *        GSS_C_NO_CREDENTIAL, the credential will be obtained from
 *        the security context in the Globus IO handle.
 * @param restriction_oids
 *        A sequence of restriction OIDs
 * @param restriction_buffers
 *        A sequence of restriction buffers, each of which corresponds
 *        to a OID in the restriction_oids parameter
 * @param time_req
 *        The time in seconds the delegated credential will be valid.
 * @param callback
 *        Function to be called once the delegation is finished.
 * @param callback_arg
 *        Parameter to the callback function.
 *
 * @return 
 *        This function returns GLOBUS_SUCCESS or a result pointing
 *        to an error object.
 *
 * @ingroup security
 */

globus_result_t
globus_io_register_init_delegation(
    globus_io_handle_t *                handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    globus_io_delegation_callback_t     callback,
    void *                              callback_arg)
{
    globus_io_authentication_info_t *   init_info;
    globus_result_t                     rc = GLOBUS_SUCCESS;
    int                                 save_errno;
    static char *                       myname =
        "globus_io_register_init_delegation";

    /* argument checking goes here */

    if(handle == GLOBUS_NULL)
    {
        rc = globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "handle",
                1,
                myname));
    
        return rc;
    }

    if(cred_handle == GSS_C_NO_CREDENTIAL)
    {
        rc = globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "cred_handle",
                1,
                myname));
    
        return rc;
    }

    if(callback == GLOBUS_NULL)
    {
        rc = globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "callback",
                1,
                myname));
    
        return rc;
    }

    if(handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE ||
       handle->securesocket_attr.channel_mode ==
       GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP)
    {
        rc = globus_error_put(
            globus_io_error_construct_bad_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "handle",
                1,
                myname));
    
        return rc;

    }
    
    init_info = (globus_io_authentication_info_t *) globus_malloc(
        sizeof(globus_io_authentication_info_t));

    if(init_info == GLOBUS_NULL)
    {
        save_errno = errno;
        rc = globus_error_put(
            globus_io_error_construct_system_failure(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                save_errno));
        return rc;
    }

    memset(init_info,0,sizeof(globus_io_authentication_info_t));
    
    init_info->callback = globus_l_io_delegation_cb_wrapper;
    init_info->delegation_callback = callback;
    init_info->callback_arg = callback_arg;
    init_info->cred_handle = cred_handle;
    init_info->restriction_oids = restriction_oids;
    init_info->restriction_buffers = restriction_buffers;
    init_info->time_req = time_req;
    init_info->iteration = globus_l_io_init_delegation;
    init_info->any_token_received = GLOBUS_FALSE;
    
    globus_i_io_mutex_lock();
    
    rc = globus_i_io_start_operation(
        handle,
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
    
    if(rc == GLOBUS_SUCCESS)
    {
        rc = globus_i_io_register_operation(
            handle,
            globus_l_io_init_delegation,
            init_info,
            GLOBUS_NULL,
            GLOBUS_FALSE,
            GLOBUS_I_IO_READ_OPERATION);
        
        if(rc != GLOBUS_SUCCESS)
        {
            globus_i_io_end_operation(
                handle, 
                GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        }
    }
    
    globus_i_io_mutex_unlock();
    
    if(rc != GLOBUS_SUCCESS)
    {
        globus_free(init_info);
    }

    return rc;
} /* globus_io_register_init_delegation */


/**
 * Blocking credential delegation initiation.
 *
 * This call initiates credential delegation. It is assumed that the
 * user will synchronize this call with the accepting side. It is also
 * assumed that user will not try to send or read data while this
 * operation is in progress (i.e. the user should not operate on the
 * Globus IO handle until this call returns) and that the read
 * buffer has been flushed before this function is called.
 *
 * @param handle
 *        The handle to use for this operation. The handle must be of
 *        the type GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED and must
 *        contain a valid security context.
 * @param cred_handle
 *        The credential to be delegated. If this parameter is set to
 *        GSS_C_NO_CREDENTIAL, the credential will be obtained from
 *        the security context in the Globus IO handle.
 * @param restriction_oids
 *        A sequence of restriction OIDs
 * @param restriction_buffers
 *        A sequence of restriction buffers, each of which corresponds
 *        to a OID in the restriction_oids parameter
 * @param time_req
 *        The time in seconds the delegated credential will be valid.
 *
 * @return 
 *        This function returns GLOBUS_SUCCESS or a result pointing
 *        to an error object.
 *
 * @ingroup security
 */

globus_result_t
globus_io_init_delegation(
    globus_io_handle_t *                handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req)
{
    globus_i_io_monitor_t               monitor;
    globus_result_t                     rc;

    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.nbytes = 0;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    monitor.data = globus_malloc(sizeof(globus_io_delegation_data_t));
    
    handle->blocking_read = GLOBUS_TRUE;
    handle->blocking_write = GLOBUS_TRUE;
    
    rc = globus_io_register_init_delegation(handle,
                                            cred_handle,
                                            restriction_oids,
                                            restriction_buffers,
                                            time_req,
                                            globus_l_io_delegation_cb,
                                            &monitor);
    if(rc != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.err = globus_error_get(rc);
        monitor.use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);    
        }
    }
    globus_mutex_unlock(&monitor.mutex);
    
    handle->blocking_read = GLOBUS_FALSE;
    handle->blocking_write = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    globus_free(monitor.data);
    
    if(monitor.use_err)
    {
        return globus_error_put(monitor.err);
    }
    else
    {
        return GLOBUS_SUCCESS;
    }
}

/**
 * Asynchronous credential delegation accept.
 *
 * This call accepts credential delegation. It is assumed that the
 * user will synchronize this call with the initiating side. It is also
 * assumed that user will not try to send or read data while this
 * operation is in progress (i.e. the user should not operate on the
 * Globus IO handle until the callback is received) and that the read
 * buffer has been flushed before this function is called.
 *
 * @param handle
 *        The handle to use for this operation. The handle must be of
 *        the type GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED and must
 *        contain a valid security context.
 * @param restriction_oids
 *        A sequence of restriction OIDs
 * @param restriction_buffers
 *        A sequence of restriction buffers, each of which corresponds
 *        to a OID in the restriction_oids parameter
 * @param time_req
 *        Parameter indicating the time the caller wants the
 *        credential to be valid for.
 * @param callback
 *        Function to be called once the delegation is finished. The
 *        delegated credential is passed to the user through this
 *        callback. 
 * @param callback_arg
 *        Parameter to the callback function.
 *
 * @return 
 *        This function returns GLOBUS_SUCCESS or a result pointing
 *        to an error object.
 *
 * @ingroup security
 */

globus_result_t
globus_io_register_accept_delegation(
    globus_io_handle_t *                handle,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    globus_io_delegation_callback_t     callback,
    void *                              callback_arg)
{
    globus_io_authentication_info_t *   accept_info;
    globus_result_t                     rc = GLOBUS_SUCCESS;
    int                                 save_errno;
    static char *                       myname =
        "globus_io_register_accept_delegation";
    
    /* argument checking goes here */

    if(handle == GLOBUS_NULL)
    {
        rc = globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "handle",
                1,
                myname));
        
        return rc;
    }

    if(callback == GLOBUS_NULL)
    {
        rc = globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "callback",
                1,
                myname));
    
        return rc;
    }

    if(handle->securesocket_attr.authentication_mode ==
       GLOBUS_IO_SECURE_AUTHENTICATION_MODE_NONE ||
       handle->securesocket_attr.channel_mode ==
       GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP)
    {
        rc = globus_error_put(
            globus_io_error_construct_bad_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "handle",
                1,
                myname));
    
        return rc;

    }
    
    accept_info = (globus_io_authentication_info_t *) globus_malloc(
        sizeof(globus_io_authentication_info_t));

    if(accept_info == GLOBUS_NULL)
    {
        save_errno = errno;
        rc = globus_error_put(
            globus_io_error_construct_system_failure(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                save_errno));
        
        return rc;
    }
    
    memset(accept_info,0,sizeof(globus_io_authentication_info_t));
    
    accept_info->callback = globus_l_io_delegation_cb_wrapper;
    accept_info->delegation_callback = callback;
    accept_info->callback_arg = callback_arg;
    accept_info->restriction_oids = restriction_oids;
    accept_info->restriction_buffers = restriction_buffers;
    accept_info->cred_handle = GSS_C_NO_CREDENTIAL;
    accept_info->iteration = globus_l_io_accept_delegation;
    accept_info->any_token_received = GLOBUS_FALSE;
    
    globus_i_io_mutex_lock();
    
    rc = globus_i_io_start_operation(
        handle,
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
    
    if(rc == GLOBUS_SUCCESS)
    {
        rc = globus_i_io_register_operation(
            handle,
            globus_l_io_accept_delegation,
            accept_info,
            GLOBUS_NULL,
            GLOBUS_FALSE,
            GLOBUS_I_IO_READ_OPERATION);
        
        if(rc != GLOBUS_SUCCESS)
        {
            globus_i_io_end_operation(
                handle, 
                GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        }
    }
    
    globus_i_io_mutex_unlock();
    
    if(rc != GLOBUS_SUCCESS)
    {
        globus_free(accept_info);
    }
    
    return rc;
}


/**
 * Blocking credential delegation accept.
 *
 * This call accepts credential delegation. It is assumed that the
 * user will synchronize this call with the initiating side. It is also
 * assumed that user will not try to send or read data while this
 * operation is in progress (i.e. the user should not operate on the
 * Globus IO handle until this function returns) and that the read
 * buffer has been flushed before this function is called.
 *
 * @param handle
 *        The handle to use for this operation. The handle must be of
 *        the type GLOBUS_IO_HANDLE_TYPE_TCP_CONNECTED and must
 *        contain a valid security context.
 * @param delegated_cred
 *        This parameter will contain the delegated credential upon
 *        success. 
 * @param restriction_oids
 *        A sequence of restriction OIDs
 * @param restriction_buffers
 *        A sequence of restriction buffers, each of which corresponds
 *        to a OID in the restriction_oids parameter
 * @param time_req
 *        Parameter indicating the time the caller wants the
 *        credential to be valid for.
 * @param time_rec
 *        Parameter returning the actual time in seconds the received
 *        credential is valid for.  
 * @return 
 *        This function returns GLOBUS_SUCCESS or a result pointing
 *        to an error object.
 *
 * @ingroup security
 */

globus_result_t
globus_io_accept_delegation(
    globus_io_handle_t *                handle,
    gss_cred_id_t *                     delegated_cred,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec)
{
    globus_i_io_monitor_t               monitor;
    globus_result_t                     rc;
    static char *                       myname =
        "globus_io_accept_delegation";

    if(delegated_cred == GLOBUS_NULL)
    {
        rc = globus_error_put(
            globus_io_error_construct_null_parameter(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                "delegated_cred",
                1,
                myname));
    
        return rc;
    }
    
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.nbytes = 0;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    monitor.data = globus_malloc(sizeof(globus_io_delegation_data_t));
    
    handle->blocking_read = GLOBUS_TRUE;
    handle->blocking_write = GLOBUS_TRUE;
    
    rc = globus_io_register_accept_delegation(handle,
                                              restriction_oids,
                                              restriction_buffers,
                                              time_req,
                                              globus_l_io_delegation_cb,
                                              &monitor);
    if(rc != GLOBUS_SUCCESS)
    {
        monitor.done = GLOBUS_TRUE;
        monitor.err = globus_error_get(rc);
        monitor.use_err = GLOBUS_TRUE;
    }
    
    globus_mutex_lock(&monitor.mutex);
    {
        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);    
        }
    }
    globus_mutex_unlock(&monitor.mutex);
    
    handle->blocking_read = GLOBUS_FALSE;
    handle->blocking_write = GLOBUS_FALSE;
    
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    if(monitor.use_err)
    {
        globus_free(monitor.data);
        return globus_error_put(monitor.err);
    }
    else
    {
        *delegated_cred = ((globus_io_delegation_data_t *)
                           monitor.data)->cred_handle;
        if(time_rec != NULL)
        {
            *time_rec = ((globus_io_delegation_data_t *)
                         monitor.data)->time_rec;
        }
        
        globus_free(monitor.data);
        return GLOBUS_SUCCESS;
    }
}

static
void 
globus_l_io_init_delegation(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result) 
{
    globus_io_authentication_info_t *   init_info;
    globus_object_t *                   err;
    gss_buffer_desc *                   token_ptr;
    gss_buffer_desc                     input_token;
    gss_buffer_desc                     output_token; 
#ifdef TARGET_ARCH_WIN32
	int rc;
#endif
    
    init_info = (globus_io_authentication_info_t *) arg;

    globus_i_io_mutex_lock();

    if(init_info->input_token.token)
    {
        input_token.value = init_info->input_token.token;
        input_token.length = init_info->input_token.token_length;
        token_ptr = &input_token;
    }
    else
    {
        token_ptr = GSS_C_NO_BUFFER;
    }
    
    init_info->maj_stat = gss_init_delegation(
        &init_info->min_stat,
        handle->context,
        init_info->cred_handle,
        GSS_C_NO_OID,
        init_info->restriction_oids,
        init_info->restriction_buffers,
        token_ptr,
        init_info->flags,
        init_info->time_req,
        &output_token);

    if(init_info->input_token.token)
    {
        globus_free(init_info->input_token.token);
        memset(&init_info->input_token,
               '\0',
               sizeof(globus_io_input_token_t));
    }

    if(init_info->maj_stat != GSS_S_COMPLETE &&
       init_info->maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        err = globus_io_error_construct_authentication_failed(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            (int) init_info->maj_stat,
            (int) init_info->min_stat,
            0);
    
        goto error_exit;
    }

    init_info->output_buflen = output_token.length;
    init_info->output_buffer = output_token.value;
    
    result = GLOBUS_SUCCESS;
    if(init_info->output_buflen != 0)
    {
        /* send token asynchronously. When completed, this will register
         * a receive of the input token, or call the user code, depending
         * on init_info->maj_stat
         */
        result = globus_i_io_register_operation(
            handle,
            globus_l_io_write_auth_token,
            init_info,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
#ifdef TARGET_ARCH_WIN32
		if ( result == GLOBUS_SUCCESS )
		{
			// post a packet in order to trigger the callback
			rc= globus_i_io_windows_post_completion( 
				handle, 
				WinIoWriting );
			if ( rc ) // a fatal error occurred
			{
				// unregister the write operation
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE,
				 GLOBUS_I_IO_WRITE_OPERATION );

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						rc );
				goto error_exit;
			}
		}
#endif
    }
    else
    {
        if(init_info->maj_stat == GSS_S_CONTINUE_NEEDED)
        {
            /* get another token */
            result = globus_i_io_register_operation(
                handle,
                globus_l_io_read_auth_token,
                init_info,
                GLOBUS_NULL,
                GLOBUS_TRUE,
                GLOBUS_I_IO_READ_OPERATION);
#ifdef TARGET_ARCH_WIN32
			if ( result == GLOBUS_SUCCESS )
			{
				// post a packet in order to trigger the callback
				rc= globus_i_io_windows_post_completion( 
					handle, 
					WinIoReading );
				if ( rc ) // a fatal error occurred
				{
					// unregister the read operation
					globus_i_io_unregister_operation( handle, 
					 GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION );

					err = globus_io_error_construct_system_failure(
							GLOBUS_IO_MODULE,
							GLOBUS_NULL,
							handle,
							rc );
					goto error_exit;
				}
			}
#endif
        }
        else
        {
            globus_i_io_end_operation(
                handle, 
                GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
                
            globus_i_io_mutex_unlock();

            /* completed */
            init_info->callback(init_info->callback_arg,
                                handle,
                                GLOBUS_SUCCESS,
                                init_info);
            globus_free(init_info);
            
            return;
        }
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        goto error_exit;
    }
    
    globus_i_io_mutex_unlock();
    
    return;
    
error_exit:

    err = globus_io_error_construct_authentication_failed(
        GLOBUS_IO_MODULE,
        err,
        handle,
        (int) init_info->maj_stat,
        (int) init_info->min_stat,
        0);
    
    globus_i_io_end_operation(
        handle, 
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
                
    globus_i_io_mutex_unlock();
    init_info->callback(init_info->callback_arg,
                        handle,
                        globus_error_put(err),
                        init_info);
    globus_free(init_info);
}

static
void 
globus_l_io_accept_delegation(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result)
{
    globus_io_authentication_info_t *   accept_info;
    globus_object_t *                   err;
    gss_buffer_desc *                   token_ptr;
    gss_buffer_desc                     input_token;
    gss_buffer_desc                     output_token;
    gss_OID                             mech_type; 
#ifdef TARGET_ARCH_WIN32
	int rc;
#endif
    
    accept_info = (globus_io_authentication_info_t *) arg;

    globus_i_io_mutex_lock();

    output_token.length = 0;
    
    if(accept_info->input_token.token)
    {
        input_token.value = accept_info->input_token.token;
        input_token.length = accept_info->input_token.token_length;
        token_ptr = &input_token;
    }
    else
    {
        token_ptr = GSS_C_NO_BUFFER;
    }
    
    accept_info->maj_stat = gss_accept_delegation(
        &accept_info->min_stat,
        handle->context,
        accept_info->restriction_oids,
        accept_info->restriction_buffers,
        token_ptr,
        accept_info->flags,
        accept_info->time_req,
        &accept_info->time_rec,
        &accept_info->cred_handle,
        &mech_type,
        &output_token);

    if(accept_info->input_token.token)
    {
        globus_free(accept_info->input_token.token);
        memset(&accept_info->input_token,
               '\0',
               sizeof(globus_io_input_token_t));
    }

    if(accept_info->maj_stat != GSS_S_COMPLETE &&
       accept_info->maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        err = globus_io_error_construct_authentication_failed(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle,
            (int) accept_info->maj_stat,
            (int) accept_info->min_stat,
            0);
    
        goto error_exit;
    }

    accept_info->output_buflen = output_token.length;
    accept_info->output_buffer = output_token.value;
    
    result = GLOBUS_SUCCESS;
    if(accept_info->output_buflen != 0)
    {
        /* send token asynchronously. When completed, this will register
         * a receive of the input token, or call the user code, depending
         * on accept_info->maj_stat
         */
        result = globus_i_io_register_operation(
            handle,
            globus_l_io_write_auth_token,
            accept_info,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
#ifdef TARGET_ARCH_WIN32
		if ( result == GLOBUS_SUCCESS )
		{
			// post a packet in order to trigger the callback
			rc= globus_i_io_windows_post_completion( 
				handle, 
				WinIoWriting );
			if ( rc ) // a fatal error occurred
			{
				// unregister the write operation
				globus_i_io_unregister_operation( handle, GLOBUS_FALSE,
				 GLOBUS_I_IO_WRITE_OPERATION );

				err = globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						rc );
				goto error_exit;
			}
		}
#endif
    }
    else
    {
        if(accept_info->maj_stat == GSS_S_CONTINUE_NEEDED)
        {
            /* get another token */
            result = globus_i_io_register_operation(
                handle,
                globus_l_io_read_auth_token,
                accept_info,
                GLOBUS_NULL,
                GLOBUS_TRUE,
                GLOBUS_I_IO_READ_OPERATION);
#ifdef TARGET_ARCH_WIN32
			if ( result == GLOBUS_SUCCESS )
			{
				// post a packet in order to trigger the callback
				rc= globus_i_io_windows_post_completion( 
					handle, 
					WinIoReading );
				if ( rc ) // a fatal error occurred
				{
					// unregister the read operation
					globus_i_io_unregister_operation( handle, 
					 GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION );

					err = globus_io_error_construct_system_failure(
							GLOBUS_IO_MODULE,
							GLOBUS_NULL,
							handle,
							rc );
					goto error_exit;
				}
			}
#endif
        }
        else
        {
            globus_i_io_end_operation(
                handle, 
                GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        
            globus_i_io_mutex_unlock();

            /* completed */
            accept_info->callback(accept_info->callback_arg,
                                  handle,
                                  GLOBUS_SUCCESS,
                                  accept_info);
            globus_free(accept_info);
            return;
        }
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        goto error_exit;
    }
    
    globus_i_io_mutex_unlock();
    return;
    
error_exit:

    err = globus_io_error_construct_authentication_failed(
        GLOBUS_IO_MODULE,
        err,
        handle,
        (int) accept_info->maj_stat,
        (int) accept_info->min_stat,
        0);
    
    globus_i_io_end_operation(
        handle, 
        GLOBUS_I_IO_READ_OPERATION | GLOBUS_I_IO_WRITE_OPERATION);
        
    globus_i_io_mutex_unlock();
    accept_info->callback(accept_info->callback_arg,
                          handle,
                          globus_error_put(err),
                          accept_info);
    globus_free(accept_info);
}

static
void
globus_l_io_delegation_cb_wrapper(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    globus_io_authentication_info_t *   auth_info)
{
    (auth_info->delegation_callback)(arg,
                                     handle,
                                     result,
                                     auth_info->cred_handle,
                                     auth_info->time_rec);
    return;
}

static
void
globus_l_io_delegation_cb(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    gss_cred_id_t                       delegated_cred,
    OM_uint32                           time_rec)
{
    globus_i_io_monitor_t *             monitor;
    globus_object_t *                   err;

    err = globus_error_get(result);

    monitor = (globus_i_io_monitor_t *) arg;

    globus_mutex_lock(&monitor->mutex);

    ((globus_io_delegation_data_t *) monitor->data)->cred_handle =
        delegated_cred;
    ((globus_io_delegation_data_t *) monitor->data)->time_rec =
        time_rec;
    monitor->done = GLOBUS_TRUE;
    if(result != GLOBUS_SUCCESS)
    {
        monitor->use_err = GLOBUS_TRUE;
        monitor->err = err;
    }
    
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}

/**
 * Call the authorization callback for a handle.
 *
 * This function calls the user's authorization callback to allow
 * the user to decide whether to authorize the connection or not.
 * This function is used when the user wants an authorization callback
 * on the "connect" side of a secure connection. In that case, we must
 * extract the subject name of the target from the security context.
 *
 * Called with i/o mutex locked.
 *
 * @param handle
 *        Handle to authorize.
 *
 * @retval GLOBUS_SUCCESS
 *         User has authorized the connection.
 * @retval GLOBUS_IO_ERROR_AUTHORIZATION_FAILED
 *         User has denied authorization.
 */
static
globus_result_t
globus_l_io_securesocket_call_auth_callback(
    globus_io_handle_t *        handle)
{
    globus_result_t         result;
    gss_name_t              peer;
    gss_buffer_desc         peer_name_buffer;
    OM_uint32               maj_stat;
    OM_uint32               min_stat;
    int                     initiator;
    
    peer_name_buffer.length = (size_t) 0;
    peer_name_buffer.value = GLOBUS_NULL;

    maj_stat = gss_inquire_context(&min_stat,
                                   handle->context,
                                   GLOBUS_NULL,
                                   GLOBUS_NULL,
                                   GLOBUS_NULL,
                                   GLOBUS_NULL,
                                   GLOBUS_NULL,
                                   &initiator,
                                   GLOBUS_NULL);

    globus_assert(maj_stat == GSS_S_COMPLETE);

    maj_stat = gss_inquire_context(&min_stat,
                                   handle->context,
                                   initiator ? GLOBUS_NULL : &peer,
                                   initiator ? &peer : GLOBUS_NULL,
                                   GLOBUS_NULL,
                                   GLOBUS_NULL,
                                   GLOBUS_NULL,
                                   GLOBUS_NULL,
                                   GLOBUS_NULL);

    if(maj_stat == GSS_S_COMPLETE)
    {
        maj_stat = gss_display_name(&min_stat,
                                    peer,
                                    &peer_name_buffer,
                                    GLOBUS_NULL);
        if(maj_stat != GSS_S_COMPLETE)
        {
            /* Error creating name string */
            peer_name_buffer.length = (size_t) 0;
            peer_name_buffer.value = GLOBUS_NULL;
        }
        gss_release_name(&min_stat, &peer);
    }

    if(! handle->securesocket_attr.auth_callback(
           handle->securesocket_attr.auth_callback_arg,
           handle,
           GLOBUS_SUCCESS,
           (char *) peer_name_buffer.value,
           handle->context))
    {
        /* not authorized */
        result = globus_error_put(
            globus_io_error_construct_authorization_failed(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle,
                0,
                0,
                0));
    }
    else
    {
        result = GLOBUS_SUCCESS;
    }

    if(peer_name_buffer.value)
    {
        gss_release_buffer(&min_stat, &peer_name_buffer);
    }

    return result;
}
/* globus_l_io_securesocket_call_auth_callback() */
