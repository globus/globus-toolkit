#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_xio_gsi.h"
#include "version.h"
#include "gssapi.h"
#include "globus_error_gssapi.h"

#define GLOBUS_XIO_GSI_DRIVER_MODULE &globus_i_xio_gsi_module

#define GlobusLXioGsiCreateHeader(__iovec, __length)              \
    {                                                             \
        *(((unsigned char *) (__iovec).iov_base)) =               \
            (unsigned char) (((__length) >> 24) & 0xff);          \
        *(((unsigned char *) (__iovec).iov_base)+1) =             \
            (unsigned char) (((__length) >> 16) & 0xff);          \
        *(((unsigned char *) (__iovec).iov_base)+2) =             \
            (unsigned char) (((__length) >>  8) & 0xff);          \
        *(((unsigned char *) (__iovec).iov_base)+3) =             \
            (unsigned char) (((__length)      ) & 0xff);          \
    }

#define GlobusLXioGsiGetTokenLength(__iovec, __length)            \
    {                                                             \
        globus_byte_t *                 c;                        \
        c = (__iovec).iov_base;                                   \
        (__length)  = ((globus_size_t) (*((c)++))) << 24;         \
        (__length) |= ((globus_size_t) (*((c)++))) << 16;         \
        (__length) |= ((globus_size_t) (*((c)++))) << 8;          \
        (__length) |= ((globus_size_t) (*((c)++)));               \
    }


#define GlobusXIOErrorWrapGSSFailed(failed_func, major_status, minor_status) \
    globus_error_put(                                                        \
        globus_error_wrap_gssapi_error(                                      \
            GLOBUS_XIO_MODULE,                                               \
            major_status,                                                    \
            minor_status,                                                    \
            GLOBUS_XIO_ERROR_WRAPPED,                                        \
            "[%s:%d] %s failed.",                                            \
            _xio_name, __LINE__, (failed_func)))                            


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


/*
 *  attribute structure
 */
typedef struct
{
    gss_cred_id_t                       credential;
    OM_uint32                           req_flags;
    OM_uint32                           time_req;
    gss_OID                             mech_type;
    gss_channel_bindings_t              channel_bindings;
    globus_bool_t                       wrap_tokens;
    globus_size_t                       buffer_size;
    globus_xio_gsi_protection_level_t   prot_level;
} globus_l_attr_t;

static globus_l_attr_t                  globus_l_xio_gsi_attr_default =
{
    GSS_C_NO_CREDENTIAL,
    GSS_C_MUTUAL_FLAG,
    0,
    GSS_C_NO_OID,
    GSS_C_NO_CHANNEL_BINDINGS,
    GLOBUS_FALSE,
    131072, /* 128K default read buffer */
    GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE
};

typedef struct
{
    gss_name_t                          target_name;
    /* init or accept flag */
    globus_bool_t                       init;
} globus_l_target_t;


typedef struct
{
    globus_l_attr_t *                   attr;
    globus_l_target_t *                 target;
    OM_uint32                           ret_flags;
    OM_uint32                           time_rec;
    OM_uint32                           max_wrap_size;
    gss_ctx_id_t                        context;
    gss_cred_id_t                       delegated_cred;
    gss_OID                             mech_used;
    gss_name_t                          source_name;
    size_t                              write_iovec_count;
    globus_xio_iovec_t *                write_iovec;
    globus_bool_t                       frame_writes;
    size_t                              write_header_count;
    unsigned char *                     write_headers;
    globus_xio_iovec_t                  read_iovec[2];
    unsigned char                       header[4];
    unsigned char *                     read_buffer;
    globus_size_t                       bytes_read;
    globus_xio_iovec_t *                user_iovec;
    size_t                              user_iovec_count;
    unsigned char *                     unwrapped_buffer;
    globus_size_t                       unwrapped_buffer_length;
    globus_size_t                       unwrapped_buffer_offset;
    globus_size_t                       bytes_returned;
    globus_bool_t                       done;
    globus_result_t                     result;
} globus_l_handle_t;


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

    return GLOBUS_SUCCESS;

error_attr:
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
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_size_t *                     out_size;
    GlobusXIOName(globus_l_xio_gsi_attr_cntl);

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
        break;
    }

 error_invalid:
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
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_gsi_attr_copy);

    attr = (globus_l_attr_t *) malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    memcpy(attr, src, sizeof(globus_l_attr_t));

    *dst = attr;

 error_attr:
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
    
    attr = (globus_l_attr_t *) driver_attr;

    free(driver_attr);

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
    char *                              contact_string)
{
    globus_l_target_t *                 target;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_gsi_target_init);

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
    
 error_target:

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
    globus_result_t                     result = GLOBUS_SUCCESS;
    gss_name_t *                        out_name;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    GlobusXIOName(globus_l_xio_gsi_target_cntl);

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
    
 error_invalid:
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

    target = (globus_l_target_t *) driver_target;
    
    if(target->target_name != GSS_C_NO_NAME)
    {
        gss_release_name(&minor_status,
                         target->target_name);
    }
    
    free(target);

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

    return;
    
 error:
    GlobusXIODriverFinishedAccept(op, NULL, result);
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
    
    GlobusXIODriverPassAccept(result, accept_op,
                              globus_l_xio_gsi_accept_cb, NULL);
    return result;
}


static
void
globus_l_xio_gsi_handle_destroy(
    globus_l_handle_t *                 handle)
{
    OM_uint32                           minor_status;
    GlobusXIOName(globus_l_xio_gsi_handle_free);

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

    if(handle->source_name != GSS_C_NO_NAME)
    {
        gss_release_name(&minor_status,
                         &handle->source_name);
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
}


static
globus_bool_t
globus_l_xio_gsi_is_ssl_token(
    void *                              token,
    globus_size_t *                     length)
{
    unsigned char * t = (unsigned char *) token;

    GlobusXIOName(globus_l_xio_gsi_is_ssl_token);

    if((t[0] >= 20 &&
        t[0] <= 26 &&
        (t[1] == 3 && (t[2] == 0 || t[2] == 1) ||
         t[1] == 2 && t[2] == 0)) ||
       ((t[0] & 0x80) && t[2] == 1))
    {
        *length = (t[3] << 8) | t[4];
        return GLOBUS_TRUE;
    }
    else
    {
        *length = ((globus_size_t) (*((t)++))) << 24;         
        *length |= ((globus_size_t) (*((t)++))) << 16;
        *length |= ((globus_size_t) (*((t)++))) << 8;
        *length |= ((globus_size_t) (*((t)++)));
        return GLOBUS_FALSE;
    }
}

static globus_result_t
globus_l_xio_gsi_unwrapped_buffer_to_iovec(
    globus_l_handle_t *                 handle,
    globus_size_t *                     bytes_read)
{
    int                                 i;
    globus_result_t                     result = GLOBUS_SUCCESS;

    GlobusXIOName(globus_l_xio_gsi_unwrapped_buffer_to_iovec);
    
    *bytes_read = 0;
    
    for(i = 0;i < handle->user_iovec_count;i++)
    {
        if(handle->user_iovec[i].iov_len >= handle->unwrapped_buffer_length -
           handle->unwrapped_buffer_offset)
        {
            *bytes_read += handle->unwrapped_buffer_length -
                handle->unwrapped_buffer_offset;
            memcpy(handle->user_iovec[i].iov_base,
                   &handle->unwrapped_buffer[handle->unwrapped_buffer_offset],
                   *bytes_read);
            handle->unwrapped_buffer_offset = 0;
            handle->unwrapped_buffer_length = 0;
            free(handle->unwrapped_buffer);
            goto done;
        }
        else
        {
            memcpy(handle->user_iovec[i].iov_base,
                   &handle->unwrapped_buffer[handle->unwrapped_buffer_offset],
                   handle->user_iovec[i].iov_len);
            *bytes_read += handle->user_iovec[i].iov_len;
            handle->unwrapped_buffer_offset += handle->user_iovec[i].iov_len;
        }
    }

 done:
        
    return result;
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
    int                                 conf_state=0;
    gss_qop_t                           qop_state = GSS_C_QOP_DEFAULT;

    GlobusXIOName(globus_l_xio_gsi_wrapped_buffer_to_iovec);
    
    wrapped_buf.value = handle->read_buffer;
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
        return result;
    }

    handle->unwrapped_buffer = unwrapped_buf.value;
    handle->unwrapped_buffer_length = unwrapped_buf.length;
    
    return globus_l_xio_gsi_unwrapped_buffer_to_iovec(handle,
                                                      bytes_read);
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
    globus_size_t                       wait_for;
    
    GlobusXIOName(globus_l_xio_gsi_read_token_cb);

    handle = (globus_l_handle_t *) user_arg;

    context = GlobusXIOOperationGetContext(op);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_pass_close;
    }

    if(handle->bytes_read != 0)
    {
        handle->read_iovec[1].iov_base = handle->read_buffer;
        input_token.length = handle->bytes_read + nbytes;
        input_token.value = &handle->read_buffer[4];
    }
    else if(globus_l_xio_gsi_is_ssl_token(handle->read_iovec[1].iov_base,
                                           &wait_for) ==
            GLOBUS_FALSE)
    {
        handle->bytes_read += (nbytes - 4);
    
        /* grow read buffer so we can read a full token */
        
        if(wait_for + 4 > handle->attr->buffer_size)
        {
            unsigned char *                 tmp_ptr;

            tmp_ptr = realloc(handle->read_buffer,
                                     wait_for + 4);
            if(!tmp_ptr)
            {
                result = GlobusXIOErrorMemory("handle->read_buffer");
                goto error_pass_close;
            }

            handle->attr->buffer_size = wait_for + 4;
            handle->read_buffer = tmp_ptr;
        }

        wait_for -= handle->bytes_read;
        
        if(wait_for)
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
            
            return;
        }
        else
        {
            input_token.length = handle->bytes_read;
            input_token.value = &handle->read_buffer[4];
        }
    }
    else
    {
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
                    goto error_pass_close;
                }
                else
                {
                    handle->result = result;
                }
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
                                              &handle->source_name,
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
                    goto error_pass_close;
                }
                else
                {
                    handle->result = result;
                }
            }
        }
    }

    if(output_token.length != 0)
    {
        if(handle->attr->wrap_tokens == GLOBUS_TRUE)
        {
            iovec = handle->read_iovec;
            iovec_count = 2;
            GlobusLXioGsiCreateHeader(iovec[0], output_token.length);
            
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
        }
        
        if(handle->attr->wrap_tokens == GLOBUS_TRUE)
        {
            iovec = handle->read_iovec;
            iovec_count = 2;
             GlobusLXioGsiCreateHeader(iovec[0], output_token.length);

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
        return;
    }
 error_destroy_handle:
    globus_l_xio_gsi_handle_destroy(handle);
    GlobusXIODriverFinishedOpen(context, NULL, op, result);
    return;
}   

static
globus_result_t
globus_l_xio_gsi_open(
    void *                              driver_target,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_xio_context_t                context;
    globus_l_handle_t *                 handle;
    globus_l_target_t *                 target;
    globus_l_attr_t *                   attr;
    
    GlobusXIOName(globus_l_xio_gsi_open);

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
    handle->source_name = GSS_C_NO_NAME;
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
    }
    
 error:
    
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

    context = GlobusXIOOperationGetContext(op);

    handle = (globus_l_handle_t *) user_arg;

    GlobusXIODriverFinishedOpen(context, NULL, op, handle->result);

    globus_l_xio_gsi_handle_destroy(handle);

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

    globus_l_xio_gsi_handle_destroy((globus_l_handle_t *) driver_handle);
    
    GlobusXIODriverPassClose(result, op, NULL, NULL);
    
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

    handle = (globus_l_handle_t *) user_arg;

    if(handle->attr->prot_level == GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE)
    {        
        GlobusXIODriverFinishedRead(op, result, nbytes);
        return;
    }
    
    context = GlobusXIOOperationGetContext(op);
    
    wait_for = GlobusXIOOperationGetWaitFor(op);

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
            
    while(frame_length + offset + header < handle->bytes_read &&
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
                "globus_l_xio_gsi_wrapped_buffer_to_iovec",result);
            goto done;
        }
        
        wait_for -= bytes_read;
        
        handle->bytes_returned += bytes_read;
        
        offset += frame_length;
        
        if(handle->bytes_read - offset > 4)
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

    if(handle->bytes_read - offset > 0)
    {
        memcpy(handle->read_buffer, &handle->read_buffer[offset],
               handle->bytes_read - offset);
        handle->bytes_read -= offset;                
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
                    result =
                        GlobusXIOErrorMemory("handle->read_buffer");
                    goto done;
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

    return;
    
 done:
    GlobusXIODriverFinishedRead(op, local_result, handle->bytes_returned);
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

    handle = (globus_l_handle_t *) driver_handle;
    
    wait_for = GlobusXIOOperationGetWaitFor(op);

    if(iovec_count < 1)
    {
        if(wait_for > 0)
        { 
            result = GlobusXIOErrorParameter("iovec_count");
        }
        GlobusXIODriverFinishedRead(op, result, 0);
        return result;
    }

    if(handle->attr->prot_level == GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE)
    {
        /*
        GlobusXIODriverPassRead(result, op, iovec, iovec_count, wait_for,
                                NULL, handle);
        */
        GlobusXIODriverPassRead(result, op, iovec, iovec_count, wait_for,
                                globus_l_xio_gsi_read_cb, handle);
        return result;
    }

    handle->bytes_returned = 0;
    handle->user_iovec = iovec;
    handle->user_iovec_count = iovec_count;

    if(handle->unwrapped_buffer_length != 0)
    {
        result = globus_l_xio_gsi_unwrapped_buffer_to_iovec(
            handle,&bytes_read);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_gsi_unwrapped_buffer_to_iovec", result);
            goto done;
        }

        wait_for -= bytes_read;
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
                    goto done;
                }

                wait_for -= bytes_read;

                handle->bytes_returned += bytes_read;

                offset += frame_length;
                
                if(handle->bytes_read - offset > 4)
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

            if(handle->bytes_read - offset > 0)
            {
                memcpy(handle->read_buffer, &handle->read_buffer[offset],
                       handle->bytes_read - offset);
                handle->bytes_read -= offset;                
            }
        }
    }
    
    if(wait_for > 0)
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
                    goto done;
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

    return result;

 done:
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

    handle = (globus_l_handle_t *) user_arg;

    if(handle->attr->prot_level == GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE)
    {
        goto done;  
    }
    
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

 done:
    
    GlobusXIODriverFinishedWrite(op, result, nbytes);
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
        /*
        GlobusXIODriverPassWrite(result, op, iovec, iovec_count, wait_for,
                                 NULL, handle);
        */
        GlobusXIODriverPassWrite(result, op, iovec, iovec_count, wait_for,
                                 globus_l_xio_gsi_write_cb, handle);
        return result;
    }
    
    handle->frame_writes = GLOBUS_FALSE;
    
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
        GlobusLXioGsiCreateHeader(handle->write_iovec[j],
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

    for(i;i < iovec_count;i++)
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
                GlobusLXioGsiCreateHeader(handle->write_iovec[j],
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
    return result;
 error:
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
    GlobusXIOName(globus_l_xio_gsi_cntl);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gsi_load(
    globus_xio_driver_t *               out_driver,
    va_list                             ap)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_gsi_load);

    res = globus_xio_driver_init(&driver, "gsi", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
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

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_gsi_unload(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_gsi_unload);
    globus_xio_driver_destroy(driver);
}


static
int
globus_l_xio_gsi_activate(void)
{
    int                                 rc;

    GlobusXIOName(globus_l_xio_gsi_activate);
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    return rc;
}

static
int
globus_l_xio_gsi_deactivate(void)
{
    GlobusXIOName(globus_l_xio_gsi_deactivate);
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    gsi,
    &globus_i_xio_gsi_module,
    globus_l_xio_gsi_load,
    globus_l_xio_gsi_unload);
