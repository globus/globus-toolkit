#include "globus_i_xio_gsi.h"
#include "version.h"

static
void
globus_l_xio_gsi_read_token_cb(
    struct globus_i_xio_op_s *              op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg);


static
void
globus_l_xio_gsi_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

static int
globus_l_xio_gsi_activate();

static int
globus_l_xio_gsi_deactivate();


static globus_module_descriptor_t  globus_i_xio_gsi_module =
{
    "globus_xio_gsi",
    globus_l_xio_gsi_activate,
    globus_l_xio_gsi_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

GlobusDebugDefine(GLOBUS_XIO_GSI);


/*
 *  initialize a driver attribute
 */
static
globus_result_t
globus_l_xio_gsi_attr_init(
    void **                             out_attr)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_gsi_attr_init);
    GlobusXIOGSIDebugEnter();
    
    /*
     *  create a tcp attr structure and intialize its values
     */
    attr = (globus_l_attr_t *) malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    *attr = globus_l_xio_gsi_attr_default;
    *out_attr = attr;

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOGSIDebugExitWithError();
    return result;
}

/*
 *  modify the attribute structure
 */
static
globus_result_t
globus_l_xio_gsi_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_attr_t *                   attr;
    gss_cred_id_t *                     out_cred;
    OM_uint32 *                         out_flags;
    globus_bool_t *                     out_bool;
    globus_xio_gsi_protection_level_t * out_prot_level;
    globus_xio_gsi_proxy_mode_t *       out_proxy_mode;
    globus_xio_gsi_proxy_mode_t         proxy_mode;
    globus_xio_gsi_delegation_mode_t *  out_delegation_mode;
    globus_xio_gsi_delegation_mode_t    delegation_mode;
    globus_result_t                     result;
    globus_size_t *                     out_size;
    GlobusXIOName(globus_l_xio_gsi_attr_cntl);
    GlobusXIOGSIDebugEnter();

    attr = (globus_l_attr_t *) driver_attr;
    switch(cmd) 
    {
        /**
         * Credential
         */
      case GLOBUS_XIO_GSI_SET_CREDENTIAL:
        attr->credential = va_arg(ap, gss_cred_id_t);
        break;
      case GLOBUS_XIO_GSI_GET_CREDENTIAL:
        out_cred = va_arg(ap, gss_cred_id_t *);
        *out_cred = attr->credential;
        break;
        
        /**
         * GSSAPI flags
         */
      case GLOBUS_XIO_GSI_SET_GSSAPI_REQ_FLAGS:
        attr->req_flags = va_arg(ap, OM_uint32);
        break;
      case GLOBUS_XIO_GSI_GET_GSSAPI_REQ_FLAGS:
        out_flags = va_arg(ap, OM_uint32 *);
        *out_flags = attr->req_flags;
        break;
        /* allow setting of flags one by one */
      case GLOBUS_XIO_GSI_SET_PROXY_MODE:
        proxy_mode = va_arg(ap, globus_xio_gsi_proxy_mode_t);
        if(proxy_mode == GLOBUS_XIO_GSI_PROXY_MODE_FULL)
        {
            attr->req_flags &= (~GSS_C_GLOBUS_LIMITED_PROXY_FLAG &
                                ~GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG);
        }
        else if(proxy_mode == GLOBUS_XIO_GSI_PROXY_MODE_LIMITED)
        {
            attr->req_flags |= GSS_C_GLOBUS_LIMITED_PROXY_FLAG;
            attr->req_flags &= ~GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG;
        }
        else if(proxy_mode == GLOBUS_XIO_GSI_PROXY_MODE_MANY)
        {
            attr->req_flags &= ~GSS_C_GLOBUS_LIMITED_PROXY_FLAG;
            attr->req_flags |= GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG;
        }
        break;
      case GLOBUS_XIO_GSI_GET_PROXY_MODE:
        out_proxy_mode = va_arg(ap, globus_xio_gsi_proxy_mode_t *);
        if(attr->req_flags & GSS_C_GLOBUS_LIMITED_PROXY_FLAG)
        {
            *out_proxy_mode = GLOBUS_XIO_GSI_PROXY_MODE_LIMITED;
        }
        else if(attr->req_flags & GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG)
        {
            *out_proxy_mode = GLOBUS_XIO_GSI_PROXY_MODE_MANY;
        }
        else
        { 
             *out_proxy_mode = GLOBUS_XIO_GSI_PROXY_MODE_FULL;
        }
        break;
      case GLOBUS_XIO_GSI_SET_DELEGATION_MODE:
        delegation_mode = va_arg(ap, globus_xio_gsi_delegation_mode_t);
        if(delegation_mode == GLOBUS_XIO_GSI_DELEGATION_MODE_NONE)
        {
            attr->req_flags &= (~GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG &
                                ~GSS_C_DELEG_FLAG);
        }
        else if(delegation_mode == GLOBUS_XIO_GSI_DELEGATION_MODE_FULL)
        { 
            attr->req_flags |= GSS_C_DELEG_FLAG;
            attr->req_flags &= ~GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG;
            attr->req_flags &= ~GSS_C_GLOBUS_SSL_COMPATIBLE;
            attr->wrap_tokens = GLOBUS_TRUE;
        }
        else if(delegation_mode == GLOBUS_XIO_GSI_DELEGATION_MODE_LIMITED)
        {
            attr->req_flags |= GSS_C_DELEG_FLAG;
            attr->req_flags |= GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG;
            attr->req_flags &= ~GSS_C_GLOBUS_SSL_COMPATIBLE;
            attr->wrap_tokens = GLOBUS_TRUE;            
        }
        break;
      case GLOBUS_XIO_GSI_GET_DELEGATION_MODE:
        out_delegation_mode = va_arg(ap, globus_xio_gsi_delegation_mode_t *);

        if(attr->req_flags & GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG)
        {
            *out_delegation_mode = GLOBUS_XIO_GSI_DELEGATION_MODE_LIMITED;
        }
        else if(attr->req_flags & GSS_C_DELEG_FLAG)
        {
            *out_delegation_mode = GLOBUS_XIO_GSI_DELEGATION_MODE_FULL;
        }
        else
        {
            *out_delegation_mode = GLOBUS_XIO_GSI_DELEGATION_MODE_NONE;
        }
        break;
      case GLOBUS_XIO_GSI_SET_SSL_COMPATIBLE:
        attr->req_flags |= GSS_C_GLOBUS_SSL_COMPATIBLE;
        attr->req_flags &= ~(GSS_C_DELEG_FLAG |
                             GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG);
        attr->wrap_tokens = GLOBUS_FALSE;
        break;
      case GLOBUS_XIO_GSI_SET_ANON:
        attr->req_flags |= GSS_C_ANON_FLAG;
        attr->req_flags &= ~(GSS_C_DELEG_FLAG |
                             GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG);
        break;

        /**
         * Wrap mode
         */
      case GLOBUS_XIO_GSI_SET_WRAP_MODE:
        attr->wrap_tokens = va_arg(ap, globus_bool_t);
        break;
      case GLOBUS_XIO_GSI_GET_WRAP_MODE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->wrap_tokens;
        break;

        /**
         * Read buffer size
         */
      case GLOBUS_XIO_GSI_SET_BUFFER_SIZE:
        attr->buffer_size = va_arg(ap, globus_size_t);

        /* having a reasonable min buffer size simplifies the code */
        
        if(attr->buffer_size < 512)
        {
            attr->buffer_size = 512;
        }
        break;
      case GLOBUS_XIO_GSI_GET_BUFFER_SIZE:
        out_size = va_arg(ap, globus_size_t *);
        *out_size = attr->buffer_size;
        break;

        /**
         * Protection level
         */
      case GLOBUS_XIO_GSI_SET_PROTECTION_LEVEL:
        attr->prot_level = va_arg(ap, globus_xio_gsi_protection_level_t);

        /* make sure that the right req flags are set */
        
        if(attr->prot_level == GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY)
        {
            attr->req_flags |= GSS_C_CONF_FLAG;
        }
        else if(attr->prot_level == GLOBUS_XIO_GSI_PROTECTION_LEVEL_INTEGRITY)
        {
            attr->req_flags |= GSS_C_INTEG_FLAG;
        }
        break;
      case GLOBUS_XIO_GSI_GET_PROTECTION_LEVEL:
        out_prot_level = va_arg(ap, globus_xio_gsi_protection_level_t *);
        *out_prot_level = attr->prot_level;
        break;
        
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
    }

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
    
 error_invalid:
    GlobusXIOGSIDebugExitWithError();
    return result;
}

/*
 *  copy an attribute structure
 */
static
globus_result_t
globus_l_xio_gsi_attr_copy(
    void **                             dst,
    void *                              src)
{
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_gsi_attr_copy);
    GlobusXIOGSIDebugEnter();

    attr = (globus_l_attr_t *) malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    memcpy(attr, src, sizeof(globus_l_attr_t));

    *dst = attr;

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
    
 error_attr:
    GlobusXIOGSIDebugExitWithError();
    return result;
}

/*
 *  destroy an attr structure
 */
static
globus_result_t
globus_l_xio_gsi_attr_destroy(
    void *                              driver_attr)
{
    globus_l_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_gsi_attr_destroy);
    GlobusXIOGSIDebugEnter();
    
    attr = (globus_l_attr_t *) driver_attr;

    free(driver_attr);

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
}

/*
 *  initialize target structure
 */
static
globus_result_t
globus_l_xio_gsi_target_init(
    void **                             out_target,
    void *                              driver_attr,
    const char *                        contact_string)
{
    globus_l_target_t *                 target;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_gsi_target_init);
    GlobusXIOGSIDebugEnter();

    /* create the target structure and copy the contact string into it */
    target = (globus_l_target_t *) malloc(sizeof(globus_l_target_t));
    if(!target)
    {
        result = GlobusXIOErrorMemory("target");
        goto error_target;
    }

    target->target_name = GSS_C_NO_NAME;
    target->init = GLOBUS_TRUE;

    *out_target = target;

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
    
 error_target:
    GlobusXIOGSIDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_xio_gsi_target_cntl(
    void *                              driver_target,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_target_t *                 target;
    globus_result_t                     result;
    gss_name_t *                        out_name;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    GlobusXIOName(globus_l_xio_gsi_target_cntl);
    GlobusXIOGSIDebugEnter();

    target = (globus_l_target_t *) driver_target;

    /* Q: should more stuff go in here? */
    
    switch(cmd)
    {
      case GLOBUS_XIO_GSI_GET_TARGET_NAME:
        out_name = va_arg(ap, gss_name_t *);
        *out_name = target->target_name;
        break;
      case GLOBUS_XIO_GSI_SET_TARGET_NAME:
        if(target->target_name != GSS_C_NO_NAME)
        {
            gss_release_name(&minor_status,
                             target->target_name);
            target->target_name = GSS_C_NO_NAME;
        }

        major_status = gss_duplicate_name(&minor_status,
                                          va_arg(ap, gss_name_t),
                                          &target->target_name);
        if(GSS_ERROR(major_status))
        {
            result = GlobusXIOErrorWrapGSSFailed("gss_duplicate_name",
                                                 major_status,
                                                 minor_status);
        }
        break;
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
    
 error_invalid:
    GlobusXIOGSIDebugExitWithError();
    return result;
}

/*
 *  destroy the target structure
 */
static
globus_result_t
globus_l_xio_gsi_target_destroy(
    void *                              driver_target)
{
    globus_l_target_t *                 target;
    OM_uint32                           minor_status;
    
    GlobusXIOName(globus_l_xio_gsi_target_destroy);
    GlobusXIOGSIDebugEnter();

    target = (globus_l_target_t *) driver_target;
    
    if(target->target_name != GSS_C_NO_NAME)
    {
        gss_release_name(&minor_status,
                         target->target_name);
    }
    
    free(target);

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
}

void
globus_l_xio_gsi_accept_cb(
    globus_i_xio_op_t *                 op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_target_t *                 target;
    GlobusXIOName(globus_l_xio_gsi_accept_cb);
    GlobusXIOGSIDebugInternalEnter();
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_l_xio_gsi_target_init((void **) &target, NULL, NULL);

    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_gsi_target_init", result);
        goto error;
    }

    target->init = GLOBUS_FALSE;
    
    GlobusXIODriverFinishedAccept(op, target, result);
    
    GlobusXIOGSIDebugInternalExit();
    return;
    
 error:
    GlobusXIODriverFinishedAccept(op, NULL, result);
    GlobusXIOGSIDebugInternalExitWithError();
    return;
}

static globus_result_t
globus_l_xio_gsi_accept(
    void *                              driver_server,
    void *                              driver_attr,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    
    GlobusXIOName(globus_l_xio_gsi_accept);
    GlobusXIOGSIDebugEnter();
    
    GlobusXIODriverPassAccept(result, accept_op,
                              globus_l_xio_gsi_accept_cb, NULL);
    GlobusXIOGSIDebugExit();
    return result;
}


static
void
globus_l_xio_gsi_handle_destroy(
    globus_l_handle_t *                 handle)
{
    OM_uint32                           minor_status;
    GlobusXIOName(globus_l_xio_gsi_handle_free);
    GlobusXIOGSIDebugInternalEnter();

    if(handle->attr != NULL)
    {
        globus_l_xio_gsi_attr_destroy(handle->attr);
    }
    
    if(handle->context != GSS_C_NO_CONTEXT)
    {
        gss_delete_sec_context(&minor_status,
                               &handle->context,
                               GSS_C_NO_BUFFER);
    }

    if(handle->delegated_cred != GSS_C_NO_CREDENTIAL)
    {
        gss_release_cred(&minor_status,
                         &handle->delegated_cred);
    }

    if(handle->peer_name != GSS_C_NO_NAME)
    {
        gss_release_name(&minor_status,
                         &handle->peer_name);
    }

    if(handle->local_name != GSS_C_NO_NAME)
    {
        gss_release_name(&minor_status,
                         &handle->local_name);
    }

    if(handle->write_iovec != NULL)
    {
        free(handle->write_iovec);
    }

    if(handle->write_headers != NULL)
    {
        free(handle->write_headers);
    }

    if(handle->unwrapped_buffer != NULL)
    {
        free(handle->unwrapped_buffer);
    }
    
    free(handle->read_buffer);
    free(handle);

    GlobusXIOGSIDebugInternalExit();
    return;
}


static
globus_bool_t
globus_l_xio_gsi_is_ssl_token(
    void *                              token,
    globus_size_t *                     length)
{
    unsigned char * t = (unsigned char *) token;
    globus_bool_t                       result;

    GlobusXIOName(globus_l_xio_gsi_is_ssl_token);
    GlobusXIOGSIDebugInternalEnter();

    if((t[0] >= 20 &&
        t[0] <= 26 &&
        (t[1] == 3 && (t[2] == 0 || t[2] == 1) ||
         t[1] == 2 && t[2] == 0)) ||
       ((t[0] & 0x80) && t[2] == 1))
    {
        *length = (t[3] << 8) | t[4];
        *length += 5;
        result = GLOBUS_TRUE;
    }
    else
    {
        *length = ((globus_size_t) (*((t)++))) << 24;         
        *length |= ((globus_size_t) (*((t)++))) << 16;
        *length |= ((globus_size_t) (*((t)++))) << 8;
        *length |= ((globus_size_t) (*((t)++)));
        result = GLOBUS_FALSE;
    }
    
    GlobusXIOGSIDebugInternalExit();
    return result;
}

static globus_result_t
globus_l_xio_gsi_unwrapped_buffer_to_iovec(
    globus_l_handle_t *                 handle,
    globus_size_t *                     bytes_read)
{
    GlobusXIOName(globus_l_xio_gsi_unwrapped_buffer_to_iovec);
    GlobusXIOGSIDebugInternalEnter();
    
    *bytes_read = 0;
    
    for( ; handle->user_iovec_index < handle->user_iovec_count;
         handle->user_iovec_index++)
    {
        if(handle->user_iovec[handle->user_iovec_index].iov_len -
           handle->user_iovec_offset > handle->unwrapped_buffer_length -
           handle->unwrapped_buffer_offset)
        {
            *bytes_read += handle->unwrapped_buffer_length -
                handle->unwrapped_buffer_offset;
            memcpy(handle->user_iovec[handle->user_iovec_index].iov_base +
                   handle->user_iovec_offset,
                   &handle->unwrapped_buffer[handle->unwrapped_buffer_offset],
                   handle->unwrapped_buffer_length -
                   handle->unwrapped_buffer_offset);
            handle->user_iovec_offset += handle->unwrapped_buffer_length -
                handle->unwrapped_buffer_offset;
            handle->unwrapped_buffer_offset = 0;
            handle->unwrapped_buffer_length = 0;
            free(handle->unwrapped_buffer);
            handle->unwrapped_buffer = NULL;
            goto done;
        }
        else
        {
            memcpy(handle->user_iovec[handle->user_iovec_index].iov_base +
                   handle->user_iovec_offset,
                   &handle->unwrapped_buffer[handle->unwrapped_buffer_offset],
                   handle->user_iovec[handle->user_iovec_index].iov_len -
                   handle->user_iovec_offset);
            *bytes_read +=
                handle->user_iovec[handle->user_iovec_index].iov_len;
            handle->unwrapped_buffer_offset +=
                handle->user_iovec[handle->user_iovec_index].iov_len;
            handle->user_iovec_offset = 0; 
        }
    }

 done:    
    GlobusXIOGSIDebugInternalExit();
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gsi_wrapped_buffer_to_iovec(
    globus_l_handle_t *                 handle,
    globus_size_t *                     bytes_read,
    globus_size_t                       offset,
    globus_size_t                       frame_length)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_desc                     wrapped_buf;
    gss_buffer_desc                     unwrapped_buf;
    globus_result_t                     result;
    int                                 conf_state = 0;
    gss_qop_t                           qop_state = GSS_C_QOP_DEFAULT;

    GlobusXIOName(globus_l_xio_gsi_wrapped_buffer_to_iovec);
    GlobusXIOGSIDebugInternalEnter();
    
    wrapped_buf.value = &handle->read_buffer[offset];
    wrapped_buf.length = frame_length;

    major_status = gss_unwrap(&minor_status,
                              handle->context,
                              &wrapped_buf,
                              &unwrapped_buf,
                              &conf_state,
                              &qop_state);

    if(GSS_ERROR(major_status))
    {
        result = GlobusXIOErrorWrapGSSFailed("gss_unwrap",
                                             major_status,
                                             minor_status);
        GlobusXIOGSIDebugInternalExitWithError();
        return result;
    }

    handle->unwrapped_buffer = unwrapped_buf.value;
    handle->unwrapped_buffer_length = unwrapped_buf.length;
    handle->unwrapped_buffer_offset = 0;
    
    result = globus_l_xio_gsi_unwrapped_buffer_to_iovec(handle,
                                                        bytes_read);
    GlobusXIOGSIDebugInternalExit();
    return result;
}

static
void
globus_l_xio_gsi_write_token_cb(
    struct globus_i_xio_op_s *              op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
    globus_size_t                       wait_for;
    gss_buffer_desc                     tmp_buffer;
    OM_uint32                           minor_status;

    GlobusXIOName(globus_l_xio_gsi_write_token_cb);
    GlobusXIOGSIDebugInternalEnter();

    handle = (globus_l_handle_t *) user_arg;
     
    context = GlobusXIOOperationGetContext(op);

    tmp_buffer.length = handle->read_iovec[1].iov_len;
    tmp_buffer.value = handle->read_iovec[1].iov_base;

    gss_release_buffer(&minor_status, &tmp_buffer);
    
    handle->read_iovec[1].iov_base = handle->read_buffer;
    handle->read_iovec[1].iov_len = handle->attr->buffer_size;

    if(result != GLOBUS_SUCCESS)
    {
        goto error_pass_close;
    }
    
    if(handle->done == GLOBUS_TRUE)
    {
        if(handle->result != GLOBUS_SUCCESS)
        {
            goto error_pass_close;
        }
        
        GlobusXIODriverFinishedOpen(context, handle, op, result);
        GlobusXIOGSIDebugInternalExit();
        return;
    }
    else
    {
        iovec = &(handle->read_iovec[1]);
        iovec_count = 1;
        /* ssl record header is 5 bytes */
        wait_for = 5;
        handle->bytes_read = 0;

        GlobusXIODriverPassRead(result, op, iovec, iovec_count, wait_for,
                                globus_l_xio_gsi_read_token_cb, handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_pass_close;
        }
    }
    
    GlobusXIOGSIDebugInternalExit();
    return;
    
 error_pass_close:
    if(handle->result == GLOBUS_SUCCESS)
    { 
        handle->result = result;
    }
                
    GlobusXIODriverPassClose(result, op,
                             globus_l_xio_gsi_close_cb, handle);

    if(result != GLOBUS_SUCCESS)
    {
        globus_l_xio_gsi_handle_destroy(handle);
        GlobusXIODriverFinishedOpen(context, NULL, op, handle->result);

    }
    GlobusXIOGSIDebugInternalExitWithError();
    return;
}

static
void
globus_l_xio_gsi_read_token_cb(
    struct globus_i_xio_op_s *              op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_desc 		        output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc 		        input_token;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
    globus_size_t                       wait_for = 0;
    globus_size_t                       offset;
    
    GlobusXIOName(globus_l_xio_gsi_read_token_cb);
    GlobusXIOGSIDebugInternalEnter();

    handle = (globus_l_handle_t *) user_arg;

    context = GlobusXIOOperationGetContext(op);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_pass_close;
    }

    if(globus_l_xio_gsi_is_ssl_token(handle->read_buffer,
                                     &wait_for) ==
       GLOBUS_FALSE)
    {
        handle->bytes_read += nbytes;
        offset = wait_for + 4;
    
        /* grow read buffer so we can read a full token */
        
        if(offset > handle->attr->buffer_size)
        {
            unsigned char *                 tmp_ptr;

            tmp_ptr = realloc(handle->read_buffer,
                              offset);
            if(!tmp_ptr)
            {
                result = GlobusXIOErrorMemory("handle->read_buffer");
                goto error_pass_close;
            }

            handle->attr->buffer_size = offset;
            handle->read_buffer = tmp_ptr;
        }

        if(offset > handle->bytes_read)
        {
            handle->read_iovec[1].iov_base = &(handle->read_buffer[nbytes]);
            handle->read_iovec[1].iov_len = handle->attr->buffer_size - nbytes;
            iovec = &(handle->read_iovec[1]);
            iovec_count = 1;
            
            GlobusXIODriverPassRead(result, op, iovec, iovec_count, wait_for,
                                    globus_l_xio_gsi_read_token_cb, handle);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_pass_close;
            }
            GlobusXIOGSIDebugInternalExit();
            return;
        }
        else
        {
            input_token.length = wait_for;
            input_token.value = &handle->read_buffer[4];
        }
    }
    else
    {
        offset = nbytes;
        input_token.length = nbytes;
        input_token.value = handle->read_buffer;
    }

    if(handle->target->init == GLOBUS_TRUE)
    {
        major_status = gss_init_sec_context(&minor_status,
                                            handle->attr->credential,
                                            &handle->context,
                                            handle->target->target_name,
                                            handle->attr->mech_type,
                                            handle->attr->req_flags,
                                            handle->attr->time_req, 
                                            handle->attr->channel_bindings,
                                            &input_token,
                                            &handle->mech_used,
                                            &output_token,
                                            &handle->ret_flags,
                                            &handle->time_rec);
        if(GSS_ERROR(major_status))
        {
            result = GlobusXIOErrorWrapGSSFailed("gss_init_sec_context",
                                                 major_status,
                                                 minor_status);

            if(output_token.length == 0)
            {
                goto error_pass_close;
            }
            else
            {
                handle->result = result;
                handle->done = GLOBUS_TRUE;
            }
        }
        else if(major_status == GSS_S_COMPLETE)
        {
            handle->done = GLOBUS_TRUE;
            
            if(offset < handle->bytes_read)
            {
                handle->bytes_read -= offset;
                if(handle->attr->prot_level ==
                   GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE)
                { 
                    handle->unwrapped_buffer = malloc(handle->bytes_read);
                    if(!handle->unwrapped_buffer)
                    {
                        result = GlobusXIOErrorMemory(
                            "handle->unwrapped_buffer");
                        goto error_pass_close;
                    }

                    memcpy(handle->unwrapped_buffer,
                           &handle->read_buffer[offset],
                           handle->bytes_read);
                    handle->unwrapped_buffer_length = handle->bytes_read;
                    handle->unwrapped_buffer_offset = 0;
                    handle->bytes_read = 0;            
                }
                else
                {
                    memmove(handle->read_buffer,
                            &handle->read_buffer[offset],
                            handle->bytes_read);
                }
            }
            else
            {
                handle->bytes_read = 0;
            }

            major_status = gss_wrap_size_limit(
                &minor_status,
                handle->context,
                handle->attr->prot_level ==
                GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY,
                GSS_C_QOP_DEFAULT,
                (4294967295U),
                &handle->max_wrap_size);
            if(GSS_ERROR(major_status))
            {
                result = GlobusXIOErrorWrapGSSFailed("gss_wrap_size_limit",
                                                     major_status,
                                                     minor_status);
                goto error_pass_close;
            }

            major_status = gss_inquire_context(&minor_status,
                                               handle->context,
                                               &handle->local_name,
                                               &handle->peer_name,
                                               GLOBUS_NULL,
                                               GLOBUS_NULL,
                                               GLOBUS_NULL,
                                               GLOBUS_NULL,
                                               GLOBUS_NULL);
            if(GSS_ERROR(major_status))
            {
                result = GlobusXIOErrorWrapGSSFailed("gss_inquire_context",
                                                     major_status,
                                                     minor_status);
                goto error_pass_close;
            }
        }
    }
    else
    {
        major_status = gss_accept_sec_context(&minor_status,
                                              &handle->context,
                                              handle->attr->credential,
                                              &input_token,
                                              handle->attr->channel_bindings,
                                              &handle->peer_name,
                                              &handle->mech_used,
                                              &output_token,
                                              &handle->ret_flags,
                                              &handle->time_rec,
                                              &handle->delegated_cred);
        if(GSS_ERROR(major_status))
        {
            result = GlobusXIOErrorWrapGSSFailed("gss_accept_sec_context",
                                                 major_status,
                                                 minor_status);
            if(output_token.length == 0)
            {
                goto error_pass_close;
            }
            else
            {
                handle->result = result;
                handle->done = GLOBUS_TRUE;
            }
        }
        else if(major_status == GSS_S_COMPLETE)
        {
            handle->done = GLOBUS_TRUE;

            if(offset < handle->bytes_read)
            {
                handle->bytes_read -= offset;
                if(handle->attr->prot_level ==
                   GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE)
                { 
                    handle->unwrapped_buffer = malloc(handle->bytes_read);
                    if(!handle->unwrapped_buffer)
                    {
                        result = GlobusXIOErrorMemory(
                            "handle->unwrapped_buffer");
                        goto error_pass_close;
                    }

                    memcpy(handle->unwrapped_buffer,
                           &handle->read_buffer[offset],
                           handle->bytes_read);
                    handle->unwrapped_buffer_length = handle->bytes_read;
                    handle->unwrapped_buffer_offset = 0;
                    handle->bytes_read = 0;
                }
                else
                {
                    memmove(handle->read_buffer,
                            &handle->read_buffer[offset],
                            handle->bytes_read);
                }
            }
            else
            {
                handle->bytes_read = 0;
            }

            major_status = gss_wrap_size_limit(
                &minor_status,
                handle->context,
                handle->attr->prot_level ==
                GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY,
                GSS_C_QOP_DEFAULT,
                (4294967295U),
                &handle->max_wrap_size);
            if(GSS_ERROR(major_status))
            {
                result = GlobusXIOErrorWrapGSSFailed("gss_wrap_size_limit",
                                                     major_status,
                                                     minor_status);
                goto error_pass_close;
            }

            major_status = gss_inquire_context(&minor_status,
                                               handle->context,
                                               GLOBUS_NULL,
                                               &handle->local_name,
                                               GLOBUS_NULL,
                                               GLOBUS_NULL,
                                               GLOBUS_NULL,
                                               GLOBUS_NULL,
                                               GLOBUS_NULL);
            if(GSS_ERROR(major_status))
            {
                result = GlobusXIOErrorWrapGSSFailed("gss_inquire_context",
                                                     major_status,
                                                     minor_status);
                goto error_pass_close;
            }
        }
    }

    if(output_token.length != 0)
    {
        if(handle->attr->wrap_tokens == GLOBUS_TRUE)
        {
            iovec = handle->read_iovec;
            iovec_count = 2;
            GlobusLXIOGSICreateHeader(iovec[0], output_token.length);
            
            /* needs to be reset */
            
            iovec[1].iov_len = output_token.length;
            iovec[1].iov_base = output_token.value;
            
            wait_for = iovec[0].iov_len + iovec[1].iov_len;
        }
        else
        {
            iovec = &(handle->read_iovec[1]);
            iovec_count = 1;
            iovec[0].iov_len = output_token.length;
            iovec[0].iov_base = output_token.value;
            wait_for = iovec[0].iov_len;
        }
        
        GlobusXIODriverPassWrite(result, op, iovec, iovec_count, wait_for,
                                 globus_l_xio_gsi_write_token_cb, handle);
        if(result != GLOBUS_SUCCESS)
        {
            gss_release_buffer(&minor_status, &output_token);
            handle->read_iovec[1].iov_base = handle->read_buffer;
            handle->read_iovec[1].iov_len = handle->attr->buffer_size;
            goto error_pass_close;
        }
    }
    else if(handle->done == GLOBUS_TRUE)
    {
        GlobusXIODriverFinishedOpen(context, handle, op, result);
    }
    else
    {
        iovec = &(handle->read_iovec[1]);
        iovec_count = 1;
        /* ssl record header is 5 bytes */
        wait_for = 5;
        
        GlobusXIODriverPassRead(result, op, iovec, iovec_count, wait_for,
                                globus_l_xio_gsi_read_token_cb, handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_pass_close;
        }
    }
    GlobusXIOGSIDebugInternalExit();
    return;

 error_pass_close:
    if(handle->result == GLOBUS_SUCCESS)
    { 
        handle->result = result;
    }
                
    GlobusXIODriverPassClose(result, op,
                             globus_l_xio_gsi_close_cb, handle);
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_xio_gsi_handle_destroy(handle);
        GlobusXIODriverFinishedOpen(context, NULL, op, handle->result);

    }
    GlobusXIOGSIDebugInternalExitWithError();
    return;
}

/*
 *  open
 */
static
void
globus_l_xio_gsi_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
    globus_size_t                       wait_for;
    
    GlobusXIOName(globus_l_xio_gsi_open_cb);
    GlobusXIOGSIDebugInternalEnter();

    handle = (globus_l_handle_t *) user_arg;
    
    context = GlobusXIOOperationGetContext(op);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_destroy_handle;
    }
    
    if(handle->target->init == GLOBUS_TRUE)
    {
        OM_uint32                           major_status;
        OM_uint32                           minor_status;
        gss_buffer_desc 		    output_token = GSS_C_EMPTY_BUFFER;
        
        major_status = gss_init_sec_context(&minor_status,
                                            handle->attr->credential,
                                            &handle->context,
                                            handle->target->target_name,
                                            handle->attr->mech_type,
                                            handle->attr->req_flags,
                                            handle->attr->time_req, 
                                            handle->attr->channel_bindings,
                                            GSS_C_NO_BUFFER,
                                            &handle->mech_used,
                                            &output_token,
                                            &handle->ret_flags,
                                            &handle->time_rec);
        if(GSS_ERROR(major_status))
        {
            result = GlobusXIOErrorWrapGSSFailed("gss_init_sec_context",
                                                 major_status,
                                                 minor_status);

            if(output_token.length == 0)
            {
                goto error_destroy_handle;
            }
            else
            {
                handle->result = result;
                handle->done = GLOBUS_TRUE;
            }
        }
        else if(major_status == GSS_S_COMPLETE)
        {
            handle->done = GLOBUS_TRUE;

            major_status = gss_wrap_size_limit(
                &minor_status,
                handle->context,
                handle->attr->prot_level ==
                GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY,
                GSS_C_QOP_DEFAULT,
                (4294967295U),
                &handle->max_wrap_size);

            if(GSS_ERROR(major_status))
            {
                result = GlobusXIOErrorWrapGSSFailed("gss_wrap_size_limit",
                                                     major_status,
                                                     minor_status);
                if(output_token.length == 0)
                {
                    goto error_destroy_handle;
                }
                else
                {
                    handle->result = result;
                }
            }

            if(result == GLOBUS_SUCCESS)
            { 
                major_status = gss_inquire_context(&minor_status,
                                                   handle->context,
                                                   &handle->local_name,
                                                   &handle->peer_name,
                                                   GLOBUS_NULL,
                                                   GLOBUS_NULL,
                                                   GLOBUS_NULL,
                                                   GLOBUS_NULL,
                                                   GLOBUS_NULL);
                if(GSS_ERROR(major_status))
                {
                    result = GlobusXIOErrorWrapGSSFailed("gss_inquire_context",
                                                         major_status,
                                                         minor_status);
                    if(output_token.length == 0)
                    {
                        goto error_destroy_handle;
                    }
                    else
                    {
                        handle->result = result;
                    }
                }
            }
        }
        
        if(handle->attr->wrap_tokens == GLOBUS_TRUE)
        {
            iovec = handle->read_iovec;
            iovec_count = 2;
             GlobusLXIOGSICreateHeader(iovec[0], output_token.length);

            /* needs to be reset once I start reading */
            
            iovec[1].iov_len = output_token.length;
            iovec[1].iov_base = output_token.value;

            wait_for = iovec[0].iov_len + iovec[1].iov_len;
        }
        else
        {
            iovec = &(handle->read_iovec[1]);
            iovec_count = 1;
            iovec[0].iov_len = output_token.length;
            iovec[0].iov_base = output_token.value;
            wait_for = iovec[0].iov_len;
        }
        
        GlobusXIODriverPassWrite(result, op, iovec, iovec_count, wait_for,
                                 globus_l_xio_gsi_write_token_cb, handle);
        if(result != GLOBUS_SUCCESS)
        {
            gss_release_buffer(&minor_status, &output_token);
            handle->read_iovec[1].iov_base = handle->read_buffer;
            handle->read_iovec[1].iov_len = handle->attr->buffer_size;
            goto  error_pass_close;
        }
    }
    else
    {
        iovec = &(handle->read_iovec[1]);
        iovec_count = 1;
        /* ssl record header is 5 bytes */
        wait_for = 5;

        GlobusXIODriverPassRead(result, op, iovec, iovec_count, wait_for,
                                globus_l_xio_gsi_read_token_cb, handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto  error_pass_close;
        }
    }
    GlobusXIOGSIDebugInternalExit();
    return;

 error_pass_close:
    if(handle->result == GLOBUS_SUCCESS)
    { 
        handle->result = result;
    }
                
    GlobusXIODriverPassClose(result, op,
                             globus_l_xio_gsi_close_cb, handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = handle->result;
    }
    else
    {
        GlobusXIOGSIDebugInternalExitWithError();
        return;
    }
 error_destroy_handle:
    globus_l_xio_gsi_handle_destroy(handle);
    GlobusXIODriverFinishedOpen(context, NULL, op, result);
    GlobusXIOGSIDebugInternalExitWithError();
    return;
}   

static
globus_result_t
globus_l_xio_gsi_open(
    void *                              driver_target,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     result;
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    globus_l_target_t *                 target;
    globus_l_attr_t *                   attr;
    
    GlobusXIOName(globus_l_xio_gsi_open);
    GlobusXIOGSIDebugEnter();

    context = GlobusXIOOperationGetContext(op);
    target = (globus_l_target_t *) driver_target;
    attr = (globus_l_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_gsi_attr_default);
    
    handle = malloc(sizeof(globus_l_handle_t));

    if(!handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error;
    }

    memset(handle, 0, sizeof(globus_l_handle_t));
    
    handle->target = target;
    result = globus_l_xio_gsi_attr_copy((void **) &handle->attr, attr);

    if(result != GLOBUS_SUCCESS)
    {
        free(handle);
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_gsi_attr_copy", result);
        goto error;
    }
    
    handle->context = GSS_C_NO_CONTEXT;
    handle->delegated_cred = GSS_C_NO_CREDENTIAL;
    handle->peer_name = GSS_C_NO_NAME;
    handle->local_name = GSS_C_NO_NAME;
    handle->done = GLOBUS_FALSE;
    handle->result = GLOBUS_SUCCESS;
    handle->read_buffer = malloc(handle->attr->buffer_size);

    if(!handle->read_buffer)
    {
        globus_l_xio_gsi_attr_destroy(handle->attr);
        free(handle);
        result = GlobusXIOErrorMemory("handle->read_buffer");
        goto error;
    }

    handle->read_iovec[0].iov_len = 4;
    handle->read_iovec[0].iov_base = handle->header;
    handle->read_iovec[1].iov_len = handle->attr->buffer_size;
    handle->read_iovec[1].iov_base = handle->read_buffer;
    
    if(target->init == GLOBUS_FALSE)
    {
        handle->ret_flags = attr->req_flags;
    }
    
    GlobusXIODriverPassOpen(result, context, op,
                            globus_l_xio_gsi_open_cb, handle);

    if(result != GLOBUS_SUCCESS)
    {
        globus_l_xio_gsi_handle_destroy(handle);
        goto error;
    }

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
    
 error:
    GlobusXIOGSIDebugExitWithError();
    return result;
}

/*
 *  close
 */
static
void
globus_l_xio_gsi_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{   
    globus_l_handle_t *                 handle;
    globus_xio_context_t                context;
    
    GlobusXIOName(globus_l_xio_gsi_close_cb);
    GlobusXIOGSIDebugInternalEnter();

    context = GlobusXIOOperationGetContext(op);

    handle = (globus_l_handle_t *) user_arg;

    GlobusXIODriverFinishedOpen(context, NULL, op, handle->result);

    globus_l_xio_gsi_handle_destroy(handle);
    GlobusXIOGSIDebugInternalExit();
    return;
}   

static
globus_result_t
globus_l_xio_gsi_close(
    void *                              driver_handle,
    void *                              attr,
    globus_xio_context_t                context,
    globus_xio_operation_t              op)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    GlobusXIOName(globus_l_xio_gsi_close);
    GlobusXIOGSIDebugEnter();

    globus_l_xio_gsi_handle_destroy((globus_l_handle_t *) driver_handle);
    
    GlobusXIODriverPassClose(result, op, NULL, NULL);
    GlobusXIOGSIDebugExit();
    return result;
}

/*
 *  read
 */
void
globus_l_xio_gsi_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    globus_size_t                       wait_for;
    globus_size_t                       bytes_read;
    globus_size_t                       frame_length;
    globus_size_t                       offset;
    globus_size_t                       header;
    globus_bool_t                       ssl_record;
    globus_bool_t                       no_header = GLOBUS_FALSE;
    globus_result_t                     local_result = GLOBUS_SUCCESS;

    GlobusXIOName(globus_l_xio_gsi_read_cb);
    GlobusXIOGSIDebugInternalEnter();

    handle = (globus_l_handle_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        local_result = result;
        goto error;
    }
    
    if(handle->attr->prot_level == GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE) 
    {
        result = globus_l_xio_gsi_unwrapped_buffer_to_iovec(
            handle,&bytes_read);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_gsi_unwrapped_buffer_to_iovec", result);
        }
        else
        {
            handle->bytes_returned += bytes_read;
        }
        GlobusXIODriverFinishedRead(op, result, handle->bytes_returned);
        GlobusXIOGSIDebugInternalExit();
        return;
    }
    
    context = GlobusXIOOperationGetContext(op);
    
    wait_for = GlobusXIOOperationGetWaitFor(op);

    wait_for -= handle->bytes_returned;

    handle->bytes_read += nbytes;

    offset = 0;
    
    ssl_record = globus_l_xio_gsi_is_ssl_token(handle->read_buffer,
                                               &frame_length);

    if(ssl_record == GLOBUS_TRUE)
    {
        header = 0;
    }
    else
    {
        header = 4;
    }
            
    while(frame_length + offset + header <= handle->bytes_read &&
          wait_for > 0 &&
          no_header == GLOBUS_FALSE)
    {
        offset += header;
        
        local_result = globus_l_xio_gsi_wrapped_buffer_to_iovec(
            handle, &bytes_read, offset,
            frame_length);
        if(local_result != GLOBUS_SUCCESS)
        {
            local_result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_gsi_wrapped_buffer_to_iovec",local_result);
            goto error;
        }

        if(wait_for > bytes_read)
        {
            wait_for -= bytes_read;
        }
        else
        {
            wait_for = 0;
        }
        
        handle->bytes_returned += bytes_read;
        
        offset += frame_length;
        
        if(handle->bytes_read > offset + 5)
        {
            ssl_record = globus_l_xio_gsi_is_ssl_token(
                &handle->read_buffer[offset],
                &frame_length);
            if(ssl_record == GLOBUS_TRUE)
            {
                header = 0;
            }
            else
            {
                header = 4;
            }
        }
        else
        {
            no_header = GLOBUS_TRUE;
        }
    }

    if(handle->bytes_read > offset)
    {
        handle->bytes_read -= offset;                
        memmove(handle->read_buffer, &handle->read_buffer[offset],
               handle->bytes_read);
    }

    /* now that we have unwrapped as much as possible check result */
    
    if(result == GLOBUS_SUCCESS && wait_for > 0)
    {
        if(no_header == GLOBUS_TRUE)
        {
            wait_for = 5 - handle->bytes_read;
        }
        else
        {
            wait_for = frame_length - handle->bytes_read;

            if(frame_length + 4 > handle->attr->buffer_size)
            {
                unsigned char *                 tmp_ptr;
                
                tmp_ptr = realloc(handle->read_buffer,
                                         frame_length + 4);
                if(!tmp_ptr)
                {
                    local_result =
                        GlobusXIOErrorMemory("handle->read_buffer");
                    goto error;
                }
                
                handle->attr->buffer_size = frame_length + 4;
                handle->read_buffer = tmp_ptr;
            }
        }
        handle->read_iovec[1].iov_base =
            &(handle->read_buffer[handle->bytes_read]);
        handle->read_iovec[1].iov_len =
            handle->attr->buffer_size - handle->bytes_read;
        GlobusXIODriverPassRead(result, op, &(handle->read_iovec[1]),
                                1, wait_for,
                                globus_l_xio_gsi_read_cb, handle);
    }
    else
    {
        GlobusXIODriverFinishedRead(op, result, handle->bytes_returned);
    }
    GlobusXIOGSIDebugInternalExit();
    return;
    
 error:
    GlobusXIODriverFinishedRead(op, local_result, handle->bytes_returned);
    GlobusXIOGSIDebugInternalExitWithError();
    return;
}

static
globus_result_t
globus_l_xio_gsi_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_size_t                       wait_for;
    globus_size_t                       bytes_read;
    globus_size_t                       frame_length;
    globus_size_t                       offset;
    globus_size_t                       header;
    globus_bool_t                       ssl_record;
    globus_bool_t                       no_header = GLOBUS_TRUE;


    GlobusXIOName(globus_l_xio_gsi_read);
    GlobusXIOGSIDebugEnter();

    handle = (globus_l_handle_t *) driver_handle;
    
    wait_for = GlobusXIOOperationGetWaitFor(op);

    if(iovec_count < 1)
    {
        if(wait_for > 0)
        { 
            result = GlobusXIOErrorParameter("iovec_count");
        }
        GlobusXIODriverFinishedRead(op, result, 0);
        GlobusXIOGSIDebugExit();
        return result;
    }

    handle->bytes_returned = 0;
    handle->user_iovec = iovec;
    handle->user_iovec_count = iovec_count;
    handle->user_iovec_index = 0;
    handle->user_iovec_offset = 0;

    if(handle->unwrapped_buffer_length != 0)
    {
        result = globus_l_xio_gsi_unwrapped_buffer_to_iovec(
            handle,&bytes_read);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_gsi_unwrapped_buffer_to_iovec", result);
            goto error;
        }
        
        if(wait_for > bytes_read)
        { 
            wait_for -= bytes_read;
        }
        else
        {
            wait_for = 0;
        }
        
        handle->bytes_returned += bytes_read;
    }

    if(wait_for > 0 && handle->bytes_read != 0)
    {
        if(handle->bytes_read < 5)
        {
            no_header = GLOBUS_TRUE;
        }
        else
        {
            no_header = GLOBUS_FALSE;

            offset = 0;
            
            ssl_record = globus_l_xio_gsi_is_ssl_token(handle->read_buffer,
                                                       &frame_length);
            if(ssl_record == GLOBUS_TRUE)
            {
                header = 0;
            }
            else
            {
                header = 4;
            }
            
            while(frame_length + offset + header < handle->bytes_read &&
                  wait_for > 0 &&
                  no_header == GLOBUS_FALSE)
            {
                offset += header;
                result = globus_l_xio_gsi_wrapped_buffer_to_iovec(
                    handle, &bytes_read, offset, frame_length);
                if(result != GLOBUS_SUCCESS)
                {
                    result = GlobusXIOErrorWrapFailed(
                        "globus_l_xio_gsi_wrapped_buffer_to_iovec", result);
                    goto error;
                }

                if(wait_for > bytes_read)
                { 
                    wait_for -= bytes_read;
                }
                else
                {
                    wait_for = 0;
                }

                handle->bytes_returned += bytes_read;

                offset += frame_length;
                
                if(handle->bytes_read > offset + 4)
                {
                    ssl_record = globus_l_xio_gsi_is_ssl_token(
                        &handle->read_buffer[offset],
                        &frame_length);
                    if(ssl_record == GLOBUS_TRUE)
                    { 
                        header = 0;
                    }
                    else
                    { 
                        header = 4;
                    }
                }
                else
                {
                    no_header = GLOBUS_TRUE;
                }
            }

            if(handle->bytes_read > offset)
            {
                handle->bytes_read -= offset;                
                memmove(handle->read_buffer, &handle->read_buffer[offset],
                       handle->bytes_read);
            }
        }
    }

    if(wait_for == 0)
    {
        GlobusXIODriverFinishedRead(op, result, handle->bytes_returned);
    }
    else if(handle->attr->prot_level != GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE)
    {
        if(no_header == GLOBUS_TRUE)
        {
            wait_for = 5 - handle->bytes_read;
        }
        else
        {
            wait_for = frame_length - handle->bytes_read;

            if(frame_length + 4 > handle->attr->buffer_size)
            {
                unsigned char *                 tmp_ptr;
                
                tmp_ptr = realloc(handle->read_buffer,
                                         frame_length + 4);
                if(!tmp_ptr)
                {
                    result =
                        GlobusXIOErrorMemory("handle->read_buffer");
                    goto error;
                }
                
                handle->attr->buffer_size = frame_length + 4;
                handle->read_buffer = tmp_ptr;
            }
        }
        handle->read_iovec[1].iov_base =
            &(handle->read_buffer[handle->bytes_read]);
        handle->read_iovec[1].iov_len =
            handle->attr->buffer_size - handle->bytes_read;
        GlobusXIODriverPassRead(result, op, &(handle->read_iovec[1]),
                                1, wait_for,
                                globus_l_xio_gsi_read_cb, handle);
    }
    else
    {
        if(handle->user_iovec_index > 0 ||
           handle->user_iovec_offset > 0)
        { 
            handle->unwrapped_buffer = malloc(wait_for);
            if(!handle->unwrapped_buffer)
            {
                result =
                    GlobusXIOErrorMemory("handle->unwrapped_buffer");
                goto error;            
            }
            handle->unwrapped_buffer_length = wait_for;
            handle->read_iovec[1].iov_base = handle->unwrapped_buffer;
            handle->read_iovec[1].iov_len = wait_for;
            GlobusXIODriverPassRead(result, op, &(handle->read_iovec[1]),
                                    1, wait_for,
                                    globus_l_xio_gsi_read_cb, handle);
        }
        else
        {
            GlobusXIODriverPassRead(result, op, iovec,
                                    iovec_count, wait_for, NULL, handle);
        }
    }

    GlobusXIOGSIDebugExit();
    return result;

 error:
    GlobusXIOGSIDebugExitWithError();
    GlobusXIODriverFinishedRead(op, result, handle->bytes_returned);
    return result;
}

/*
 *  write
 */
void
globus_l_xio_gsi_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    int                                 i;
    globus_l_handle_t *                 handle;
    GlobusXIOName(globus_l_xio_gsi_write_cb);
    GlobusXIOGSIDebugInternalEnter();

    handle = (globus_l_handle_t *) user_arg;

    if(handle->frame_writes == GLOBUS_FALSE)
    { 
        for(i = 0;i < handle->write_iovec_count;i++)
        {
            if(handle->write_iovec[i].iov_base != NULL)
            {
                free(handle->write_iovec[i].iov_base);
            }
        }
    }
    else
    {
        for(i = 1;i < handle->write_iovec_count;i += 2)
        {
            if(handle->write_iovec[i].iov_base != NULL)
            {
                free(handle->write_iovec[i].iov_base);
            }
        }
    }

    GlobusXIODriverFinishedWrite(op, result, handle->bytes_written);
    GlobusXIOGSIDebugInternalExit();
    return;
}

static
globus_result_t
globus_l_xio_gsi_write(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_handle_t *                 handle;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_size_t                       wait_for;
    gss_buffer_desc                     plaintext_buffer;
    gss_buffer_desc                     wrapped_buffer;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    globus_size_t                       frame_length;
    int                                 i;
    int                                 j;
    int                                 conf_state;
    globus_size_t                       iovec_offset;
    size_t                              write_iovec_count = 0;
    
    GlobusXIOName(globus_l_xio_gsi_write);
    GlobusXIOGSIDebugEnter();

    handle = (globus_l_handle_t *) driver_handle;

    /* get wait_for here */
    
    wait_for = GlobusXIOOperationGetWaitFor(op);
        
    if(iovec_count < 1)
    {
        if(wait_for > 0)
        {
            result = GlobusXIOErrorParameter("iovec_count");
        }
        goto error;
    }

    if(handle->attr->prot_level == GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE)
    {
        GlobusXIODriverPassWrite(result, op, iovec, iovec_count, wait_for,
                                 NULL, handle);
        GlobusXIOGSIDebugExit();
        return result;
    }
    
    handle->frame_writes = GLOBUS_FALSE;
    handle->bytes_written = 0;
    plaintext_buffer.value = iovec[0].iov_base;

    if(iovec[0].iov_len > handle->max_wrap_size)
    {
        plaintext_buffer.length = handle->max_wrap_size;
        iovec_offset = handle->max_wrap_size;
    }
    else
    { 
        plaintext_buffer.length = iovec[0].iov_len;
        iovec_offset = 0;
    }
    
    major_status = gss_wrap(&minor_status,
                            handle->context,
                            handle->attr->prot_level
                            == GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY,
                            GSS_C_QOP_DEFAULT,
                            &plaintext_buffer,
                            &conf_state,
                            &wrapped_buffer);

    if(GSS_ERROR(major_status))
    {
        result = GlobusXIOErrorWrapGSSFailed("gss_wrap",
                                             major_status,
                                             minor_status);
        goto error;
    }

    /* figure out how many iovecs I need */

    for(i = 0;i < iovec_count; i++)
    {
        write_iovec_count += iovec[i].iov_len / handle->max_wrap_size;
        if(iovec[i].iov_len % handle->max_wrap_size != 0)
        {
            write_iovec_count++;
        }
        handle->bytes_written += iovec[i].iov_len;
    }

    if(globus_l_xio_gsi_is_ssl_token(wrapped_buffer.value, &frame_length)
       != GLOBUS_TRUE)
    {
        if(write_iovec_count > handle->write_header_count)
        {
            void *                      tmp_ptr;

            tmp_ptr = realloc(handle->write_headers,
                                     4 * write_iovec_count);

            if(tmp_ptr == NULL)
            {
                result = GlobusXIOErrorMemory("handle->write_headers");
                goto error;
            }

            handle->write_headers = tmp_ptr;

            handle->write_header_count = write_iovec_count;
        }   

        handle->frame_writes = GLOBUS_TRUE;
        
        write_iovec_count *= 2;
    }

    if(write_iovec_count > handle->write_iovec_count)
    {
        void *                          tmp_ptr;

        tmp_ptr = realloc(handle->write_iovec,
                          sizeof(globus_xio_iovec_t)*write_iovec_count);
        if(tmp_ptr == NULL)
        {
            result = GlobusXIOErrorMemory("handle->write_iovec");
            goto error;
        }

        handle->write_iovec = tmp_ptr;
        handle->write_iovec_count = write_iovec_count;
    }


    j = 0;
    
    if(handle->frame_writes == GLOBUS_TRUE)
    {
        handle->write_iovec[j].iov_base = handle->write_headers;
        handle->write_iovec[j].iov_len = 4;
        GlobusLXIOGSICreateHeader(handle->write_iovec[j],
                                  wrapped_buffer.length);
        j++;
        wait_for = 4;
    }
    else
    {
        wait_for = 0;    
    }
    
    handle->write_iovec[j].iov_base = wrapped_buffer.value;
    handle->write_iovec[j].iov_len = wrapped_buffer.length;
    wait_for +=  wrapped_buffer.length;
    j++;
    
    if(iovec_offset)
    {
        i = 0;
    }
    else
    {
        i = 1;
    }

    for(;i < iovec_count;i++)
    {
        do
        { 
            plaintext_buffer.value = iovec[i].iov_base + iovec_offset;
            
            if(iovec[i].iov_len - iovec_offset > handle->max_wrap_size)
            {
                plaintext_buffer.length = handle->max_wrap_size;
                iovec_offset += handle->max_wrap_size;
            }
            else
            { 
                plaintext_buffer.length = iovec[0].iov_len - iovec_offset;
                iovec_offset = 0;
            }
            
            major_status = gss_wrap(&minor_status,
                                    handle->context,
                                    handle->attr->prot_level
                                    == GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY,
                                    GSS_C_QOP_DEFAULT,
                                    &plaintext_buffer,
                                    &conf_state,
                                    &wrapped_buffer);
            
            if(GSS_ERROR(major_status))
            {
                result = GlobusXIOErrorWrapGSSFailed("gss_wrap",
                                                     major_status,
                                                     minor_status);
                goto error;
            }

            if(handle->frame_writes == GLOBUS_TRUE)
            { 
                handle->write_iovec[j].iov_base = handle->write_headers + 2*j;
                handle->write_iovec[j].iov_len = 4;
                GlobusLXIOGSICreateHeader(handle->write_iovec[j],
                                          wrapped_buffer.length);
                j++;
                wait_for += 4;
            }

            handle->write_iovec[j].iov_base = wrapped_buffer.value;
            handle->write_iovec[j].iov_len = wrapped_buffer.length;
            j++;
            wait_for += wrapped_buffer.length;
        }
        while(iovec_offset);
    }
    
    GlobusXIODriverPassWrite(result, op, handle->write_iovec,
                             write_iovec_count, wait_for,
                             globus_l_xio_gsi_write_cb, handle);
    GlobusXIOGSIDebugExit();
    return result;
 error:
    GlobusXIOGSIDebugExitWithError();
    GlobusXIODriverFinishedWrite(op, result, 0);
    return result;

}

static
globus_result_t
globus_l_xio_gsi_cntl(
    void *                              driver_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_handle_t *                 handle;
    gss_name_t *                        out_name;
    gss_cred_id_t *                     out_cred;
    gss_ctx_id_t *                      out_ctx;

    globus_result_t                     result;

    GlobusXIOName(globus_l_xio_gsi_cntl);
    GlobusXIOGSIDebugEnter();

    handle = (globus_l_handle_t *) driver_handle;
    
    switch(cmd)
    {
      case GLOBUS_XIO_GSI_GET_CONTEXT:
        out_ctx = va_arg(ap, gss_ctx_id_t *);
        *out_ctx= handle->context;
        break;
      case GLOBUS_XIO_GSI_GET_DELEGATED_CRED:
        out_cred = va_arg(ap, gss_cred_id_t *);
        *out_cred = handle->delegated_cred;
        break;
      case GLOBUS_XIO_GSI_GET_PEER_NAME:
        out_name = va_arg(ap, gss_name_t *);
        *out_name = handle->peer_name;
        break;
      case GLOBUS_XIO_GSI_GET_LOCAL_NAME:
        out_name = va_arg(ap, gss_name_t *);
        *out_name = handle->local_name;
        break;
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto invalid_cmd;
    }
    
    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
    
 invalid_cmd:
    GlobusXIOGSIDebugExitWithError();
    return result;
}

static globus_result_t
globus_l_xio_gsi_load(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;

    GlobusXIOName(globus_l_xio_gsi_load);
    GlobusXIOGSIDebugEnter();

    result = globus_xio_driver_init(&driver, "gsi", NULL);
    if(result != GLOBUS_SUCCESS)
    {
        GlobusXIOGSIDebugExitWithError();
        return result;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_gsi_open,
        globus_l_xio_gsi_close,
        globus_l_xio_gsi_read,
        globus_l_xio_gsi_write,
        globus_l_xio_gsi_cntl);

    globus_xio_driver_set_server(
        driver,
        NULL,
        globus_l_xio_gsi_accept,
        NULL,
        NULL,
        globus_l_xio_gsi_target_destroy);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_gsi_target_init,
        globus_l_xio_gsi_target_cntl,
        globus_l_xio_gsi_target_destroy);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_gsi_attr_init,
        globus_l_xio_gsi_attr_copy,
        globus_l_xio_gsi_attr_cntl,
        globus_l_xio_gsi_attr_destroy);

    
    *out_driver = driver;

    GlobusXIOGSIDebugExit();
    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_gsi_unload(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_gsi_unload);
    GlobusXIOGSIDebugEnter();
    globus_xio_driver_destroy(driver);
    GlobusXIOGSIDebugExit();
    return;
}


static
int
globus_l_xio_gsi_activate(void)
{
    int                                 rc;

    GlobusXIOName(globus_l_xio_gsi_activate);
    GlobusDebugInit(GLOBUS_XIO_GSI, TRACE INTERNAL_TRACE);
    GlobusXIOGSIDebugEnter();
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    GlobusXIOGSIDebugExit();
    return rc;
}

static
int
globus_l_xio_gsi_deactivate(void)
{
    int                                 rc;
    GlobusXIOName(globus_l_xio_gsi_deactivate);
    GlobusXIOGSIDebugEnter();
    rc = globus_module_deactivate(GLOBUS_COMMON_MODULE);
    GlobusXIOGSIDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_GSI);
    return rc;
}

GlobusXIODefineDriver(
    gsi,
    &globus_i_xio_gsi_module,
    globus_l_xio_gsi_load,
    globus_l_xio_gsi_unload);
