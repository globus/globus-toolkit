#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_xio_gsi.h"
#include "version.h"
#include "gssapi.h"

#define GLOBUS_XIO_GSI_DRIVER_MODULE &globus_i_xio_test_module

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
    globus_bool_t                       wrap;
    globus_size_t                       buffer_size;
}
globus_l_attr_t;

typedef struct
{
    globus_l_attr_t *                   attr;
    globus_l_target_t *                 target;
    OM_uint32                           ret_flags;
    OM_uint32                           time_rec;
    gss_ctx_id_t                        context;
    gss_cred_id_t                       delegated_cred;
    gss_OID                             mech_used;
    gss_name_t                          source_name;
    globus_xio_iovec_t                  iovec[2];
    unsigned char                       header[4];
    unsigned char *                     read_buffer;
    globus_size_t                       bytes_read;
    globus_bool_t                       done;
    globus_result_t                     result;
}
globus_l_handle_t;

typedef struct
{
    gss_name_t                          target_name;
    /* init or accept flag */
    globus_bool_t                       init;
}
globus_l_target_t;


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
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    attr->credential = GSS_C_NO_CREDENTIAL;
    attr->req_flags = GSS_C_MUTUAL;
    attr->time_req = 0;
    attr->mech_type = GSS_C_NO_OID;
    attr->channel_bindings = GSS_C_NO_CHANNEL_BINDINGS;
    attr->wrap = GLOBUS_FALSE;
    attr->buffer_size = 131072; /* 128K default read buffer */
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
    globus_result_t                     result;
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
        *out_cred = *credential;
        break;
        
        /**
         * GSSAPI flags
         */
      case GLOBUS_XIO_GSI_SET_GSSAPI_REQ_FLAGS:
        attr->req_flags = va_arg(ap, OM_uin32);
        break;
      case GLOBUS_XIO_GSI_GET_GSSAPI_REQ_FLAGS:
        out_flags = va_arg(ap, OM_uin32 *);
        *out_flags = attr->req_flags;
        break;
        /* allow setting of flags one by one */
      case GLOBUS_XIO_GSI_SET_ALLOW_LIMITED_PROXY:
        attr->req_flags |= GSS_C_GLOBUS_LIMITED_PROXY_FLAG;
        break;
      case GLOBUS_XIO_GSI_SET_ALLOW_LIMITED_PROXY_MANY:
        attr->req_flags |= GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG;
        break;
      case GLOBUS_XIO_GSI_SET_DELEGATE_LIMITED_PROXY:
        attr->req_flags |= (GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG |
                            GSS_C_DELEG_FLAG);
        attr->req_flags &= ~GSS_C_GLOBUS_SSL_COMPATIBLE;
        attr->wrap = GLOBUS_TRUE;
        break;
      case GLOBUS_XIO_GSI_SET_DELEGATE_FULL_PROXY:
        attr->req_flags |= GSS_C_DELEG_FLAG;
        attr->req_flags &= ~(GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG |
                             GSS_C_GLOBUS_SSL_COMPATIBLE);
        attr->wrap = GLOBUS_TRUE;
        break;
      case GLOBUS_XIO_GSI_SET_SSL_COMPATIBLE:
        attr->req_flags |= GSS_C_GLOBUS_SSL_COMPATIBLE;
        attr->req_flags &= ~(GSS_C_DELEG_FLAG |
                             GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG);
        attr->wrap = GLOBUS_FALSE;
        break;
      case GLOBUS_XIO_GSI_SET_ANON:
        attr->req_flags |= GSS_C_ANON_FLAG;
        attr->req_flags &= ~(GSS_C_DELEG_FLAG |
                             GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG);
        attr->wrap = GLOBUS_FALSE;
        break;

        /**
         * Wrap mode
         */
      case GLOBUS_XIO_GSI_SET_WRAP_MODE:
        attr->wrap = va_arg(ap, globus_bool_t);
        break;
      case GLOBUS_XIO_GSI_GET_WRAP_MODE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->wrap;
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
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

 error_memory:
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
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_gsi_attr_copy);

    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    
    memcpy(attr, src, sizeof(globus_l_attr_t));

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

    globus_free(driver_attr);

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
    target = (globus_l_target_t *) globus_malloc(sizeof(globus_l_target_t));
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
        target->target_name = va_arg(ap, gss_name_t);
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
    GlobusXIOName(globus_l_xio_gsi_target_destroy);

    globus_free(target);

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gsi_server_init(
    void **                             out_server,
    void *                              driver_attr)
{
    GlobusXIOName(globus_l_xio_gsi_server_init);
    return GLOBUS_SUCCESS;
}

void
globus_l_xio_gsi_accept_cb(
    globus_i_xio_op_t *                 op,
    globus_result_t                     result,
    void *                              user_arg)
{
    GlobusXIOName(globus_l_xio_gsi_accept_cb);
    GlobusXIODriverFinishedAccept(op, NULL, result);
}

static globus_result_t
globus_l_xio_gsi_accept(
    void *                              driver_server,
    void *                              driver_attr,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_gsi_accept);
    GlobusXIODriverPassAccept(res, accept_op,      \
        globus_l_xio_gsi_accept_cb, NULL);

    return res;
}

static globus_result_t
globus_l_xio_gsi_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_gsi_server_cntl);
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_gsi_server_destroy(
    void *                              driver_server)
{
    GlobusXIOName(globus_l_xio_gsi_server_destroy);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_gsi_target_destroy(
    void *                              driver_target)
{
    GlobusXIOName(globus_l_xio_gsi_target_destroy);
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_gsi_handle_destroy(
    globus_l_handle_t *                 handle)
{
    OM_uint32                           minor_status;
    GlobusXIOName(globus_l_xio_gsi_handle_free);
    
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

    
    if(handle->iovec[1].io_base != handle->read_buffer)
    {
        free(handle->iovec[1].io_base);
    }
    
    free(handle->read_buffer);
    free(handle);
}


static
globus_bool_t
globus_l_xio_gsi_is_ssl_packet(void * token)
{
    unsigned char * t = (unsigned char *) token;

    GlobusXIOName(globus_l_xio_gsi_is_ssl_packet);

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

    GlobusXIOName(globus_l_xio_gsi_write_token_cb);

    handle = (globus_l_handle_t *) user_arg;
     
    context = GlobusXIOOperationGetContext(op);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_pass_close;
    }
    
    free(handle->iovec[1].io_base);

    handle->iovec[1].iov_base = handle->read_buffer;
    handle->iovec[1].iov_len = handle->attr->buffer_size;
    
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
        iovec = &(handle->iovec[1]);
        iovec_count = 1;
        wait_for = 15;
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
        handle->iovec[1].iov_base = handle->read_buffer;
        input_token.length = handle->bytes_read + nbytes;
        input_token.value = &(handle->read_buffer[4]);
    }
    else if(globus_l_xio_gsi_is_ssl_packet(handle->iovec[1].iov_base) ==
            GLOBUS_FALSE)
    {
        handle->bytes_read += (nbytes - 4);
    
        GlobusLXioGsiGetTokenLength((handle->iovec)[1], wait_for);

        /* grow read buffer so we can read a full token */
        
        if(wait_for + 4 > handle->attr->buffer_size)
        {
            unsigned char *                 tmp_ptr;

            handle->attr->buffer_size = wait_for + 4;
            tmp_ptr = globus_remalloc(handle->read_buffer,
                                      handle->attr->buffer_size);
            if(!tmp_ptr)
            {
                result = GlobusXIOErrorMemory("handle->read_buffer");
                goto error_pass_close;
            }

            handle->read_buffer = tmp_ptr;
        }

        wait_for -= handle->bytes_read;
        
        if(wait_for)
        {
            handle->iovec[1].iov_base = &(handle->read_buffer[nbytes]);
            iovec = &(handle->iovec[1]);
            iovec_count = 1;
            
            GlobusXIODriverPassRead(result, op, iovec, iovec_count, wait_for,
                                    globus_l_xio_gsi_read_token_cb, handle);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_pass_close;
            }
            
            return;
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
                handle->done = GLOBUS_TRUE
            }
        }
        else if(major_status == GSS_S_COMPLETE)
        {
            handle->done = GLOBUS_TRUE;
        }
    }
    else
    {
        major_status = gss_accept_sec_context(&minor_status,
                                              &handle->context,
                                              handle->attr->credential,
                                              &input_token,
                                              handle->attr->channel_bindings,
                                              &handle->source_name;
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
                handle->done = GLOBUS_TRUE
            }
        }
        else if(major_status == GSS_S_COMPLETE)
        {
            handle->done = GLOBUS_TRUE;
        }
    }

    if(output_token.length != 0)
    {
        if(handle->attr->wrap == GLOBUS_TRUE)
        {
            iovec = handle->iovec;
            iovec_count = 2;
            GlobusLXioGsiCreateHeader(iovec[0], output_token.length);
            
            /* needs to be reset */
            
            iovec[1].iov_len = output_token.length;
            iovec[1].iov_base = output_token.value;
            
            wait_for = iovec[0].iov_len + iovec[1].iov_len;
        }
        else
        {
            iovec = &(handle->iovec[1]);
            iovec_count = 1;
            iovec[0].iov_len = output_token.length;
            iovec[0].iov_base = output_token.value;
            wait_for = iovec[0].iov_len;
        }
        
        GlobusXIODriverPassWrite(result, op, iovec, iovec_count, wait_for,
                                 globus_l_xio_gsi_write_token_cb, handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_pass_close;
        }
    }
    else if(handle->done == GLOBUS_TRUE)
    {
        GlobusXIODriverFinishedOpen(context, handle, op, result);
    }
    else
    {
        iovec = &(handle->iovec[1]);
        iovec_count = 1;
        wait_for = 15;
        
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
                handle->done = GLOBUS_TRUE
            }
        }
        else if(major_status == GSS_S_COMPLETE)
        {
            handle->done = GLOBUS_TRUE;
        }
        
        if(handle->attr->wrap == GLOBUS_TRUE)
        {
            iovec = handle->iovec;
            iovec_count = 2;
             GlobusLXioGsiCreateHeader(iovec[0], output_token.length);

            /* needs to be reset once I start reading */
            
            iovec[1].iov_len = output_token.length;
            iovec[1].iov_base = output_token.value;

            wait_for = iovec[0].iov_len + iovec[1].iov_len;
        }
        else
        {
            iovec = &(handle->iovec[1]);
            iovec_count = 1;
            iovec[0].iov_len = output_token.length;
            iovec[0].iov_base = output_token.value;
            wait_for = iovec[0].iov_len;
        }
        
        GlobusXIODriverPassWrite(result, op, iovec, iovec_count, wait_for,
                                 globus_l_xio_gsi_write_token_cb, handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto  error_pass_close;
        }
    }
    else
    {
        iovec = &(handle->iovec[1]);
        iovec_count = 1;
        wait_for = 15;

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

    target = (globus_l_target_t *) driver_target;
    attr = (globus_l_attr_t *) 
        (driver_attr ? driver_attr : &globus_l_xio_gsi_attr_default);
    
    handle = globus_malloc(sizeof(globus_l_handle_t));

    if(!handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error;
    }
    
    handle->target = target;
    handle->attr = attr;
    handle->context = GSS_C_NO_CONTEXT;
    handle->delegated_cred = GSS_C_NO_CREDENTIAL;
    handle->source_name = GSS_C_NO_NAME;
    handle->done = GLOBUS_FALSE;
    handle->result = GLOBUS_SUCCESS;
    handle->bytes_read = 0;
    handle->read_buffer = globus_malloc(handle->attr->buffer_size);

    if(!handle->read_buffer)
    {
        globus_free(handle);
        result = GlobusXIOErrorMemory("handle->read_buffer");
        goto error;
    }

    handle->iovec[0].io_len = 4;
    handle->iovec[0].io_base = handle->header;
    handle->iovec[1].io_len = handle->attr->buffer_size;
    handle->iovec[1].io_base = handle->read_buffer;
    
    if(target->init == GLOBUS_FALSE)
    {
        handle->ret_flags = attr->req_flags;
    }
    else
    {
        handle->ret_flags = 0;
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
    
    GlobusXIOName(globus_l_xio_gsi_close_cb);

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
    GlobusXIOName(globus_l_xio_gsi_read_cb);
    GlobusXIODriverFinishedRead(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_gsi_read(
    void *                              driver_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    GlobusXIOName(globus_l_xio_gsi_read);
    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassRead(res, op, iovec, iovec_count, wait_for, \
        globus_l_xio_gsi_read_cb, NULL);

    return res;
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
    GlobusXIOName(globus_l_xio_gsi_write_cb);
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
    globus_result_t                     res;
    globus_size_t                       wait_for;

    GlobusXIOName(globus_l_xio_gsi_write);
    wait_for = GlobusXIOOperationGetWaitFor(op);

    GlobusXIODriverPassWrite(res, op, iovec, iovec_count, wait_for, \
        globus_l_xio_gsi_write_cb, NULL);

    return res;
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
        globus_l_xio_gsi_server_init,
        globus_l_xio_gsi_accept,
        globus_l_xio_gsi_server_destroy,
        globus_l_xio_gsi_server_cntl,
        globus_l_xio_gsi_target_destroy);

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
