#include "globus_xio_driver.h"
#include "globus_xio_mode_e_driver.h"
#include "version.h"

GlobusDebugDefine(GLOBUS_XIO_MODE_E);
GlobusXIODeclareDriver(mode_e);

#define GlobusXIOModeEDebugPrintf(level, message)                            \
    GlobusDebugPrintf(GLOBUS_XIO_MODE_E, level, message)

#define GlobusXIOModeEDebugEnter()                                           \
    GlobusXIOModeEDebugPrintf(                                               \
        GLOBUS_L_XIO_MODE_E_DEBUG_TRACE,                                     \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOModeEDebugExit()                                            \
    GlobusXIOModeEDebugPrintf(                                               \
        GLOBUS_L_XIO_MODE_E_DEBUG_TRACE,                                     \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOModeEDebugExitWithError()                                   \
    GlobusXIOModeEDebugPrintf(                                               \
        GLOBUS_L_XIO_MODE_E_DEBUG_TRACE,                                     \
        ("[%s] Exiting with error\n", _xio_name))

enum globus_l_xio_error_levels
{
    GLOBUS_L_XIO_MODE_E_DEBUG_TRACE                = 1,
    GLOBUS_L_XIO_MODE_E_DEBUG_INTERNAL_TRACE       = 2
};

#define GLOBUS_XIO_MODE_E_IO_Q_SIZE 8
#define GLOBUS_XIO_MODE_E_HEADER_COUNT 8
#define GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE 8

#define GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_CLOSE 0x04
#define GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_EOD 0x08
#define GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_EOF 0x40


typedef enum globus_i_xio_mode_e_state_s
{

    GLOBUS_XIO_MODE_E_NONE,
    GLOBUS_XIO_MODE_E_OPEN,
    GLOBUS_XIO_MODE_E_ERROR,
    GLOBUS_XIO_MODE_E_EOF_RECEIVED,
    GLOBUS_XIO_MODE_E_EOF_DELIVERED,
    GLOBUS_XIO_MODE_E_CLOSING,

} globus_i_xio_mode_e_state_t;

typedef globus_result_t
(*globus_xio_mode_e_handle_cntl_callback_t)(
    globus_xio_handle_t                 xio_handle);

typedef struct
{
    globus_xio_stack_t                  stack;
    int                                 max_connection_count;
    int                                 total_connection_count;
    globus_xio_attr_t                   xio_attr;       
    globus_xio_mode_e_attr_cntl_callback_t      
                                        attr_cntl_cb;
    globus_bool_t                       eof;
} globus_l_xio_mode_e_attr_t;

static globus_l_xio_mode_e_attr_t       globus_l_xio_mode_e_attr_default =
{
    GLOBUS_NULL,
    1,
    1,  
    GLOBUS_NULL,
    GLOBUS_NULL,
    GLOBUS_TRUE
};

typedef struct
{
    globus_byte_t                       descriptor;
    globus_byte_t                       count[8];
    globus_byte_t                       offset[8];
} globus_l_xio_mode_e_header_t;

typedef struct
{
    globus_xio_server_t                 server;
    globus_xio_handle_t                 accepted_handle;
    globus_l_xio_mode_e_attr_t *        attr;
    globus_i_xio_mode_e_state_t         state;  
    globus_memory_t                     requestor_memory;
    globus_memory_t                     header_memory;
    char *                              cs;     
    globus_fifo_t                       connection_q;
    globus_fifo_t                       eod_q;
    int                                 connection_count;
    int                                 total_conection_count;
    globus_off_t                        eod_count;
    globus_size_t                       eods_received;
    globus_size_t                       eods_sent;
    globus_fifo_t                       io_q;
    globus_mutex_t                      mutex;
    globus_xio_mode_e_handle_cntl_callback_t
                                        handle_cntl_cb;
    globus_off_t                        offset;
    globus_xio_operation_t              outstanding_op;
    int                                 ref_count;
    globus_xio_stack_t                  stack;
    globus_xio_driver_t                 driver;
} globus_l_xio_mode_e_handle_t;

typedef struct
{
    globus_xio_handle_t                 xio_handle;
    globus_l_xio_mode_e_handle_t *      mode_e_handle;
    globus_xio_operation_t              op;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
    int                                 iovec_index;
    globus_size_t                       iovec_index_len;
    globus_off_t                        outstanding_data_len;    
    globus_off_t                        outstanding_data_offset;    
    globus_bool_t                       eod;
    globus_bool_t                       close;
} globus_l_xio_mode_e_connection_handle_t; 

typedef struct
{
    globus_xio_operation_t              op;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
} globus_i_xio_mode_e_requestor_t;


static
int
globus_l_xio_mode_e_activate(void);

static
int
globus_l_xio_mode_e_deactivate(void);

static
globus_result_t
globus_l_xio_mode_e_handle_create(
    globus_l_xio_mode_e_handle_t **     out_handle,
    globus_l_xio_mode_e_attr_t *        attr);

static
globus_result_t
globus_l_xio_mode_e_handle_destroy(
    globus_l_xio_mode_e_handle_t *      handle);

static
void
globus_i_xio_mode_e_server_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg);

static
void
globus_l_xio_mode_e_server_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg);

static
globus_result_t
globus_i_xio_mode_e_register_read_header(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle);

static
globus_result_t
globus_i_xio_mode_e_register_read(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle);

static
globus_result_t
globus_i_xio_mode_e_register_write(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle);

static
void
globus_l_xio_mode_e_close_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg);

static
globus_result_t
globus_l_xio_mode_e_attr_init(
    void **                             out_attr);

static
globus_result_t
globus_l_xio_mode_e_attr_copy(
    void **                             dst,
    void *                              src);

static
globus_result_t
globus_l_xio_mode_e_attr_destroy(
    void *                              driver_attr);


GlobusXIODefineModule(mode_e) =
{
    "globus_xio_mode_e",
    globus_l_xio_mode_e_activate,
    globus_l_xio_mode_e_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


#define GlobusXIOModeEOpenError(reason)                                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(mode_e),                                      \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_MODE_E_OPEN_ERROR,                                   \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Open failed: %s", (reason)))

#define GlobusXIOModeEReadError(reason)                                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(mode_e),                                      \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_MODE_E_READ_ERROR,                                   \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Read failed: %s", (reason)))

#define GlobusXIOModeEWriteError(reason)                                    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(mode_e),                                      \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_MODE_E_WRITE_ERROR,                                  \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Write failed: %s", (reason)))


static
int
globus_l_xio_mode_e_activate(void)
{
    int rc;
    GlobusXIOName(globus_l_xio_mode_e_activate);

    GlobusDebugInit(GLOBUS_XIO_MODE_E, TRACE);

    GlobusXIOModeEDebugEnter();
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error_xio_system_activate;
    }

    GlobusXIORegisterDriver(mode_e);
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_xio_system_activate:
    GlobusXIOModeEDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_MODE_E);
    return rc;
}


static
int
globus_l_xio_mode_e_deactivate(void)
{   
    int rc;
    GlobusXIOName(globus_l_xio_mode_e_deactivate);
    
    GlobusXIOModeEDebugEnter();
    GlobusXIOUnRegisterDriver(mode_e);
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {   
        goto error_deactivate;
    }
    
    GlobusXIOModeEDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_MODE_E);
    return GLOBUS_SUCCESS;

error_deactivate:
    GlobusXIOModeEDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_MODE_E);
    return rc;
}


static
globus_result_t
globus_l_xio_mode_e_handle_destroy(
    globus_l_xio_mode_e_handle_t *      handle)
{
    globus_result_t                     result;
    globus_bool_t			stack = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_mode_e_handle_destroy);

    GlobusXIOModeEDebugEnter();
    if (!handle->attr->stack)
    {
	stack = GLOBUS_TRUE;
    }
    result = globus_l_xio_mode_e_attr_destroy(handle->attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_mode_e_attr_destroy", result);
        goto error;
    }
    globus_fifo_destroy(&handle->connection_q);
    globus_fifo_destroy(&handle->eod_q);
    globus_fifo_destroy(&handle->io_q);
    globus_memory_destroy(&handle->requestor_memory);
    globus_memory_destroy(&handle->header_memory);
    globus_mutex_destroy(&handle->mutex);
    if (handle->server)
    {
        globus_xio_server_close(handle->server);
    }
    if (stack)
    {
        globus_xio_stack_destroy(handle->stack);
    }
    globus_free(handle);
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
void
globus_i_xio_mode_e_header_encode(
    globus_byte_t *                     buf,
    globus_off_t                        in_value)
{
    globus_off_t                        x;
    int                                 i;
    globus_size_t                       offset_size;
    GlobusXIOName(globus_i_xio_mode_e_header_encode);

    GlobusXIOModeEDebugEnter();
    offset_size = sizeof(globus_off_t);
    /*
     * buf[0] contains most significant byte and buf[7] contains the 
     * least significant byte
     */
    globus_assert(GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE >= offset_size);
    for (i = GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE; i > offset_size; i++)
    {
        buf[GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE - i] = 0;
    }
    x = (globus_off_t)in_value;
    for (i = offset_size; i > 0; i--)
    {
        buf[GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE - i] = (x >> (i - 1) * 8) & 0xff;
    }
    GlobusXIOModeEDebugExit();
}


static
globus_result_t
globus_i_xio_mode_e_header_decode(
    globus_byte_t *                     buf,
    globus_off_t *                      out_value)
{
    globus_off_t                        x = 0;
    int                                 i;
    globus_size_t                       offset_size;
    globus_result_t                     result;
    GlobusXIOName(globus_i_xio_mode_e_header_decode);

    GlobusXIOModeEDebugEnter();
    offset_size = sizeof(globus_off_t);
    for (i = GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE; i > offset_size; i--)
    {   
        /* 
         * if offset_size < MAX_OFFSET_SIZE; then the most significant
         * (MAX_OFFSET_SIZE - offset_size) number of bytes should be zero;
         * otherwise there is a overflow
         */ 
        if (buf[GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE - i] != 0)
        {
            result = GlobusXIOModeEReadError("Error decoding header");
            goto overflow;
        }
    }
    if (offset_size > GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE)
    {
        offset_size = GLOBUS_XIO_MODE_E_MAX_OFFSET_SIZE;
    }           
    for (i = 0; i < offset_size; i++)
    {
        x += ((globus_off_t) buf[i]) << (offset_size - i - 1) * 8;
    }
    *out_value = (globus_off_t)x;
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

overflow:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


/*
 *  allocate the memory for and initialize an internal handle
 */
static 
globus_result_t
globus_l_xio_mode_e_handle_create(
    globus_l_xio_mode_e_handle_t **     out_handle,
    globus_l_xio_mode_e_attr_t *        attr)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_result_t                     result;
    int                                 node_size;
    int                                 node_count;
    GlobusXIOName(globus_l_xio_mode_e_handle_create);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *)
                globus_malloc(sizeof(globus_l_xio_mode_e_handle_t));
    if (handle == GLOBUS_NULL)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error_handle;
    }
    if (!attr)
    {
       result = globus_l_xio_mode_e_attr_init((void**)&handle->attr); 
        if (result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_mode_e_attr_init", result);
            goto error_attr;
        }
    }
    else
    {
        result = globus_l_xio_mode_e_attr_copy(
                                (void**)&handle->attr, (void*)attr);
        if (result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_mode_e_attr_copy", result);
            goto error_attr;
        }
    }
    if (!handle->attr->stack)
    {
        result = globus_xio_driver_load("tcp", &handle->driver);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_driver_load;
        }
        result = globus_xio_stack_init(&handle->stack, NULL);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_stack_init;
        }
        result = globus_xio_stack_push_driver(handle->stack, handle->driver);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_push_driver;
        }
    }
    else
    {
        handle->stack = handle->attr->stack;
    }

    result = globus_fifo_init(&handle->connection_q);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_connection_q_init;
    }
    result = globus_fifo_init(&handle->eod_q);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_eod_q_init;
    }           
    result = globus_fifo_init(&handle->io_q);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_io_q_init;
    }
    node_size = sizeof(globus_i_xio_mode_e_requestor_t);  
    node_count = GLOBUS_XIO_MODE_E_IO_Q_SIZE;       
    globus_memory_init(&handle->requestor_memory, node_size, node_count);
    node_size = sizeof(globus_l_xio_mode_e_header_t);
    node_count = GLOBUS_XIO_MODE_E_HEADER_COUNT;       
    globus_memory_init(&handle->header_memory, node_size, node_count);
    globus_mutex_init(&handle->mutex, NULL);     
    handle->state = GLOBUS_XIO_MODE_E_NONE;
    handle->connection_count = 0;
    handle->eods_received = 0;
    handle->eods_sent = 0;
    handle->eod_count = -1;    
    handle->server = GLOBUS_NULL;
    handle->accepted_handle = GLOBUS_NULL;
    handle->offset = 0;
    handle->ref_count = 1;
    *out_handle = handle;
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_io_q_init:
    globus_fifo_destroy(&handle->eod_q);
error_eod_q_init:
    globus_fifo_destroy(&handle->connection_q);
error_connection_q_init:
error_push_driver:
    if (!handle->attr->stack)
    {
        globus_xio_stack_destroy(handle->stack); 
    }
error_stack_init:
    if (!handle->attr->stack)
    {
        globus_xio_driver_unload(handle->driver);
    }
error_driver_load:
    globus_l_xio_mode_e_attr_destroy(handle->attr);
error_attr:
    globus_free(handle);
error_handle:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_mode_e_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_l_xio_mode_e_attr_t *        attr;
    globus_xio_contact_t                my_contact_info;
    char *                              cs;     
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_server_init);

    GlobusXIOModeEDebugEnter();
    attr = (globus_l_xio_mode_e_attr_t *) driver_attr;
    result = globus_l_xio_mode_e_handle_create(&handle, attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_handle_create;
    }   
    if (!attr)
    {
        attr = handle->attr;
    }    
    result = globus_xio_attr_init(&attr->xio_attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_attr_init;
    }  
    if (attr->attr_cntl_cb)
    { 
        result = attr->attr_cntl_cb(attr->xio_attr);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_attr_cntl;
        }
    }   
    result = globus_xio_server_create(
            &handle->server, attr->xio_attr, handle->stack);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_server_create;
    }   
    result = globus_xio_server_get_contact_string(handle->server, &cs);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_get_cs;
    }
    result = globus_xio_contact_parse(&my_contact_info, cs);    
    if (result != GLOBUS_SUCCESS)
    {
        goto error_parse_cs;
    }
    result = globus_xio_driver_pass_server_init(op, &my_contact_info, handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_pass_server_init;
    }
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_pass_server_init:
error_parse_cs:
error_get_cs:
    globus_xio_server_close(handle->server);
error_server_create:
error_attr_cntl:
    globus_xio_attr_destroy(attr->xio_attr);
error_attr_init:
    globus_l_xio_mode_e_handle_destroy(handle);
error_handle_create:
    GlobusXIOModeEDebugExitWithError();
    return result;    
}


static
void
globus_l_xio_mode_e_server_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_mode_e_handle_t *      handle;  
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_mode_e_server_accept_cb);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *)user_arg;
    globus_mutex_lock(&handle->mutex);   
    op = handle->outstanding_op;
    if (result == GLOBUS_SUCCESS)
    {
        ++handle->ref_count;
        handle->accepted_handle = xio_handle;
    }
    else
    {
        goto error_accept;
    }
    globus_mutex_unlock(&handle->mutex);   
    globus_xio_driver_finished_accept(op, handle, result);
    GlobusXIOModeEDebugExit();
    return;

error_accept:
    globus_mutex_unlock(&handle->mutex);   
    globus_xio_driver_finished_accept(op, handle, result);
    GlobusXIOModeEDebugExitWithError();
    return;
}


static
void
globus_i_xio_mode_e_server_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_mode_e_handle_t *      handle;  
    GlobusXIOName(globus_i_xio_mode_e_server_accept_cb);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *)user_arg;
    globus_mutex_lock(&handle->mutex);   
    if (result != GLOBUS_SUCCESS)
    {    
        goto error_accept;
    }    
    switch (handle->state)
    {
        case GLOBUS_XIO_MODE_E_OPEN:
        {
            globus_result_t     res;    
            res = globus_xio_register_open(
                        xio_handle, 
                        NULL, 
                        handle->attr->xio_attr,
                        globus_i_xio_mode_e_server_open_cb,
                        handle);
            if (res != GLOBUS_SUCCESS)
            {
                globus_xio_register_close(
                    xio_handle, 
                    NULL, 
                    NULL,
                    NULL);
                goto error_register_open;
            }
            res = globus_xio_server_register_accept(
                server, 
                globus_i_xio_mode_e_server_accept_cb,
                handle);
            if (res != GLOBUS_SUCCESS)
            {
                goto error_register_accept;
            }
            break;
        }
        default:
            goto error_invalid_state;
    }   
    globus_mutex_unlock(&handle->mutex);   
    GlobusXIOModeEDebugExit();
    return;

error_register_accept:
error_register_open:
error_invalid_state:
error_accept:
    handle->state = GLOBUS_XIO_MODE_E_ERROR;
    globus_mutex_unlock(&handle->mutex); 
    GlobusXIOModeEDebugExitWithError();
    return;
}


static
globus_result_t
globus_l_xio_mode_e_server_accept(
    void *                              driver_server,
    globus_xio_operation_t              op)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_server_accept);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t*)driver_server;
    handle->outstanding_op = op;
    result = globus_xio_server_register_accept(
        handle->server, 
        globus_l_xio_mode_e_server_accept_cb,
        handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_register_accept;
    }   
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_register_accept:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


globus_result_t
globus_l_xio_mode_e_server_destroy(
    void *                              driver_server)
{
    globus_l_xio_mode_e_handle_t *      handle;
    GlobusXIOName(globus_l_xio_mode_e_server_destroy);
                            
    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *)driver_server;
    globus_mutex_lock(&handle->mutex);    
    --handle->ref_count;
    if (handle->ref_count == 0)
    {
        globus_l_xio_mode_e_handle_destroy(handle);
    }
    else
    {
        globus_mutex_unlock(&handle->mutex);    
    }
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;
}


globus_result_t
globus_l_xio_mode_e_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_mode_e_server_cntl);

    GlobusXIOModeEDebugEnter();
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;
}


globus_result_t
globus_l_xio_mode_e_link_cntl(
    void *                              driver_link,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_mode_e_link_cntl);

    GlobusXIOModeEDebugEnter();
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;
}


globus_result_t
globus_l_xio_mode_e_link_destroy(
    void *                              driver_link)
{
    globus_l_xio_mode_e_handle_t *      handle;
    GlobusXIOName(globus_l_xio_mode_e_link_destroy);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *) driver_link;
    globus_mutex_lock(&handle->mutex);
    --handle->ref_count;
    if (handle->ref_count == 0)
    {
        globus_l_xio_mode_e_handle_destroy(handle);
    }
    else
    {
        globus_mutex_unlock(&handle->mutex);
    }
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;
}


static
void
globus_l_xio_mode_e_server_connection_handle_init(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle)
{
    GlobusXIOName(globus_l_xio_mode_e_server_connection_handle_init);
    GlobusXIOModeEDebugEnter();
    connection_handle->op = GLOBUS_NULL;
    connection_handle->eod = GLOBUS_FALSE;
    connection_handle->close = GLOBUS_FALSE;
    connection_handle->outstanding_data_len = 0;
    connection_handle->iovec_index = -1;
    GlobusXIOModeEDebugExit();
}


static
globus_result_t
globus_l_xio_mode_e_process_header(
    globus_l_xio_mode_e_header_t *      header,
    globus_l_xio_mode_e_connection_handle_t *      
                                        connection_handle)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_process_header);

    GlobusXIOModeEDebugEnter();
    if (header->descriptor & GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_EOD)
    {
        connection_handle->eod = GLOBUS_TRUE;
    }
    if (header->descriptor & GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_CLOSE)
    {
        /* sending CLOSE before EOD is a protocol violation */    
        globus_assert(connection_handle->eod);
        connection_handle->close = GLOBUS_TRUE;
    }
    if (header->descriptor & GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_EOF)
    {
        connection_handle->outstanding_data_len = 0;
        connection_handle->outstanding_data_offset = 0;
        result = globus_i_xio_mode_e_header_decode(
            header->offset, &connection_handle->mode_e_handle->eod_count);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        result = globus_i_xio_mode_e_header_decode(
            header->count, &connection_handle->outstanding_data_len);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        result = globus_i_xio_mode_e_header_decode(
            header->offset, &connection_handle->outstanding_data_offset);
        if (result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
void
globus_l_xio_mode_e_process_outstanding_data(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_i_xio_mode_e_requestor_t *   requestor;
    GlobusXIOName(globus_l_xio_mode_e_process_outstanding_data);

    GlobusXIOModeEDebugEnter();
    handle = connection_handle->mode_e_handle;
    if (!globus_fifo_empty(&handle->io_q))
    {
        requestor = (globus_i_xio_mode_e_requestor_t *)
                        globus_fifo_dequeue(&handle->io_q); 
        connection_handle->op = requestor->op;
        connection_handle->iovec = requestor->iovec;
        connection_handle->iovec_count = requestor->iovec_count;
        globus_memory_push_node(
                    &handle->requestor_memory, (void*)requestor);
        globus_i_xio_mode_e_register_read(connection_handle);
    }
    else
    {
        globus_fifo_enqueue(&handle->connection_q, connection_handle);
    }
    GlobusXIOModeEDebugExit();
}


static
globus_bool_t
globus_l_xio_mode_e_process_eod(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle,
    globus_fifo_t                       op_q)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_i_xio_mode_e_requestor_t *   requestor;
    globus_bool_t                       eof = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_mode_e_check_eof);

    GlobusXIOModeEDebugEnter();
    handle = connection_handle->mode_e_handle;
    ++handle->eods_received;
    /* 
     * I decrement connection if get eod irrespective of whether i get close
     * or not, If i dont get close, i reset the connection objects put in
     * the eod_q (globus_l_xio_mode_e_reset_connections). There i increment
     * the connection count again
     */ 
    if (connection_handle->close)
    {
        globus_xio_register_close(
                connection_handle->xio_handle,
                NULL,
                globus_l_xio_mode_e_close_cb,
                handle);
        globus_free(connection_handle);
    }
    else
    {
        globus_fifo_enqueue(&handle->eod_q, connection_handle);
    }
    if (handle->eod_count == handle->eods_received)
    {
        eof = GLOBUS_TRUE;
        while (!globus_fifo_empty(&handle->io_q))
        {
            requestor = (globus_i_xio_mode_e_requestor_t*)
                            globus_fifo_dequeue(&handle->io_q);
            globus_fifo_enqueue(&op_q, requestor->op);
            globus_memory_push_node(&handle->requestor_memory,
                                                    requestor);
        }
    }
    GlobusXIOModeEDebugExit();
    return eof;
}



static
void
globus_l_xio_mode_e_read_header_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_l_xio_mode_e_header_t *      header;
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    globus_xio_operation_t              op;
    globus_fifo_t                       op_q;
    globus_bool_t                       eof;
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_result_t                     res;
    globus_off_t                        offset;
    GlobusXIOName(globus_l_xio_mode_e_read_header_cb);

    GlobusXIOModeEDebugEnter();
    globus_fifo_init(&op_q);
    connection_handle = (globus_l_xio_mode_e_connection_handle_t *) user_arg;
    handle = connection_handle->mode_e_handle;
    offset = connection_handle->outstanding_data_offset;
    globus_mutex_lock(&handle->mutex);
    if (result == GLOBUS_SUCCESS)
    {   
        header = (globus_l_xio_mode_e_header_t *) buffer;
        result = globus_l_xio_mode_e_process_header(header, connection_handle);
        if (result != GLOBUS_SUCCESS)
        {
            /* next read would fail */
            handle->state = GLOBUS_XIO_MODE_E_ERROR;
            goto error;
        }
        globus_memory_push_node(&handle->header_memory, (void*)buffer);
        if (connection_handle->outstanding_data_len > 0)
        {
            globus_l_xio_mode_e_process_outstanding_data(connection_handle);
        }
        else if (connection_handle->eod)
        {
            eof = globus_l_xio_mode_e_process_eod(connection_handle, op_q);
            if (eof) 
            {
                if (globus_fifo_empty(&op_q))
                {
                    if (handle->state == GLOBUS_XIO_MODE_E_OPEN)
                    {
                        handle->state = GLOBUS_XIO_MODE_E_EOF_RECEIVED;
                    }
                }
                else
                {
                    op = (globus_xio_operation_t) globus_fifo_peek(&op_q);
                    globus_xio_driver_set_eof_received(op);
                    res = GlobusXIOErrorEOF();
                    finish = GLOBUS_TRUE;
                    if (handle->state == GLOBUS_XIO_MODE_E_OPEN)
                    {
                        handle->state = GLOBUS_XIO_MODE_E_EOF_DELIVERED;
                    }
                }
            }
        }
        else
        {
            result = globus_i_xio_mode_e_register_read_header(
                                                        connection_handle);
            if (result != GLOBUS_SUCCESS)
            {
                /* next read would fail */
                handle->state = GLOBUS_XIO_MODE_E_ERROR;
                goto error;
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);
    if (finish)
    {
        while (!globus_fifo_empty(&op_q))
        {
            op = (globus_xio_operation_t) globus_fifo_dequeue(&op_q);
            globus_xio_driver_data_descriptor_cntl(
                        op,
                        NULL,
                        GLOBUS_XIO_DD_SET_OFFSET,
                        offset);
            globus_xio_driver_finished_read(op, res, 0);
        }
    }
    globus_fifo_destroy(&op_q);
    GlobusXIOModeEDebugExit();
    return;

error:
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExitWithError();
    return;
}


static
void
globus_l_xio_mode_e_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    globus_l_xio_mode_e_handle_t *      handle;
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_mode_e_open_cb);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *)user_arg;
    globus_mutex_lock(&handle->mutex);
    op = handle->outstanding_op;
    if (result == GLOBUS_SUCCESS)
    {    
        connection_handle = (globus_l_xio_mode_e_connection_handle_t *)
                                globus_malloc(sizeof(
                                    globus_l_xio_mode_e_connection_handle_t));
        if (!connection_handle)
        {
            result = GlobusXIOModeEOpenError("Memory error");
            goto error_connection_handle;
        }
        handle->state = GLOBUS_XIO_MODE_E_OPEN;
        connection_handle->xio_handle = xio_handle;
        connection_handle->mode_e_handle = handle;
        globus_fifo_enqueue(&handle->connection_q, connection_handle);
    }
    globus_mutex_unlock(&handle->mutex);
    globus_xio_driver_finished_open(handle, op, result);
    GlobusXIOModeEDebugExit();
    return;    

error_connection_handle:
    globus_xio_register_close(xio_handle, NULL, NULL, NULL);
    /* attr_init is done before register_open in open_new_stream */
    globus_xio_attr_destroy(handle->attr->xio_attr);
    handle->state = GLOBUS_XIO_MODE_E_ERROR;
    if (--handle->ref_count == 0)
    {
        globus_l_xio_mode_e_handle_destroy(handle);
    }
    else
    {
        globus_mutex_unlock(&handle->mutex);
    }
    globus_xio_driver_finished_open(handle, op, result);
    GlobusXIOModeEDebugExitWithError();
    return;    
}


static
void
globus_i_xio_mode_e_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    globus_l_xio_mode_e_handle_t *      handle;
    globus_xio_operation_t              write_op;
    globus_result_t                     res;
    globus_bool_t                       finish_write = GLOBUS_FALSE;
    GlobusXIOName(globus_i_xio_mode_e_open_cb);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *)user_arg;
    globus_mutex_lock(&handle->mutex);
    if (result == GLOBUS_SUCCESS)
    {    
        connection_handle = (globus_l_xio_mode_e_connection_handle_t *)
                                globus_malloc(sizeof(
                                    globus_l_xio_mode_e_connection_handle_t));
        if (!connection_handle)
        {
            goto error_connection_handle;
        }
        connection_handle->xio_handle = xio_handle;
        connection_handle->mode_e_handle = handle;
        if (!globus_fifo_empty(&handle->io_q))
        {
            globus_i_xio_mode_e_requestor_t * requestor;
            requestor = (globus_i_xio_mode_e_requestor_t *)
                            globus_fifo_dequeue(&handle->io_q);
            connection_handle->op = requestor->op;
            connection_handle->iovec = requestor->iovec;
            connection_handle->iovec_count = requestor->iovec_count;
            globus_memory_push_node(
                &handle->requestor_memory, (void*)requestor);
            res = globus_i_xio_mode_e_register_write(connection_handle);
            if (res != GLOBUS_SUCCESS)
            {
                write_op = connection_handle->op;
                finish_write = GLOBUS_TRUE;
                goto error_register_write;
            }
        }
        else
        {
            globus_fifo_enqueue(&handle->connection_q, connection_handle);
        }
    }
    else
    {
        goto error_open;
    }
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExit();
    return;    

error_register_write:
error_connection_handle:
    globus_xio_register_close(xio_handle, NULL, NULL, NULL);
    /* attr_init is done before register_open in open_new_stream */
    globus_xio_attr_destroy(handle->attr->xio_attr);
error_open:
    handle->state = GLOBUS_XIO_MODE_E_ERROR;
    globus_mutex_unlock(&handle->mutex);
    if (finish_write)
    {
        globus_xio_driver_data_descriptor_cntl(
                write_op,
                NULL,
                GLOBUS_XIO_DD_SET_OFFSET,
                connection_handle->outstanding_data_offset);
        globus_xio_driver_finished_write(write_op, res, 0);
    }
    GlobusXIOModeEDebugExitWithError();
    return;    
}


static
void
globus_i_xio_mode_e_server_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_mode_e_handle_t *      handle;
    GlobusXIOName(globus_i_xio_mode_e_server_open_cb);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *) user_arg;
    globus_mutex_lock(&handle->mutex);
    if (result == GLOBUS_SUCCESS)
    {
        globus_l_xio_mode_e_connection_handle_t *
                                            connection_handle;
        globus_result_t                     res;
        connection_handle = (globus_l_xio_mode_e_connection_handle_t *)
                                globus_malloc(sizeof(
                                    globus_l_xio_mode_e_connection_handle_t));
        connection_handle->mode_e_handle = handle;
        connection_handle->xio_handle = xio_handle;
        res = globus_i_xio_mode_e_register_read_header(connection_handle);
        if (res != GLOBUS_SUCCESS)
        {
            handle->state = GLOBUS_XIO_MODE_E_ERROR;
            goto error;
        }
        ++handle->connection_count;
    }
    else
    {
        handle->state = GLOBUS_XIO_MODE_E_ERROR;
        goto error;
    }
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExit();
    return;

error:
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExitWithError();
    return;
}


static
void
globus_l_xio_mode_e_server_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_mode_e_server_open_cb);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *) user_arg;
    globus_mutex_lock(&handle->mutex);
    op = handle->outstanding_op;
    if (result == GLOBUS_SUCCESS)
    {
        if (handle->state == GLOBUS_XIO_MODE_E_ERROR)
        {
            result = GlobusXIOModeEOpenError("Invalid state");
            goto error;
        }
        else
        {
            handle->state = GLOBUS_XIO_MODE_E_OPEN;
        }
    }
    else
    {
        goto error;
    }
    globus_mutex_unlock(&handle->mutex);
    globus_i_xio_mode_e_server_open_cb(xio_handle, result, user_arg);
    globus_xio_driver_finished_open(handle, op, result);
    GlobusXIOModeEDebugExit();
    return;

error:
    if (--handle->ref_count == 0)
    {
        globus_l_xio_mode_e_handle_destroy(handle);
    }
    else
    {
        globus_mutex_unlock(&handle->mutex);
    }
    globus_xio_driver_finished_open(NULL, op, result);
    GlobusXIOModeEDebugExitWithError();
    return;
    
}


/* called locked (if handle->state == GLOBUS_XIO_MODE_E_OPEN) */
static
globus_result_t 
globus_l_xio_mode_e_open_new_stream(
    globus_l_xio_mode_e_handle_t *      handle,
    globus_xio_callback_t               open_cb)
{
    globus_xio_handle_t                 xio_handle;     
    globus_l_xio_mode_e_attr_t *        attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_open_new_stream);

    GlobusXIOModeEDebugEnter();
    attr = handle->attr;
    result = globus_xio_attr_init(&attr->xio_attr);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_attr_init;
    }
    if (attr->attr_cntl_cb)
    {
        result = attr->attr_cntl_cb(attr->xio_attr);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_attr_cntl;
        }
    }
    result = globus_xio_handle_create(&xio_handle, handle->stack);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_handle_create;
    }
    result = globus_xio_register_open(
                xio_handle, 
                handle->cs, 
                handle->attr->xio_attr,
                open_cb,
                handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
    ++handle->connection_count;
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_open:
error_handle_create:
    globus_xio_register_close(xio_handle, NULL, NULL, NULL);
error_attr_cntl:
    globus_xio_attr_destroy(handle->attr->xio_attr);
error_attr_init:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_mode_e_server_open(
    globus_l_xio_mode_e_handle_t *      handle,
    globus_xio_operation_t              op)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_server_open);

    GlobusXIOModeEDebugEnter();
    globus_mutex_lock(&handle->mutex);
    handle->outstanding_op = op;
    result = globus_xio_register_open(
                handle->accepted_handle,
                NULL,
                handle->attr->xio_attr,
                globus_l_xio_mode_e_server_open_cb,
                handle);
    if (result != GLOBUS_SUCCESS)
    {
        handle->state = GLOBUS_XIO_MODE_E_ERROR;
        if (handle->ref_count == 0)
        {
            globus_l_xio_mode_e_handle_destroy(handle);    
        }
        else
        {
            globus_mutex_unlock(&handle->mutex);
        }
        goto error_register_open;
    }
    ++handle->ref_count;
    result = globus_xio_server_register_accept(
            handle->server,
            globus_i_xio_mode_e_server_accept_cb,
            handle);
    if (result != GLOBUS_SUCCESS)
    {
        handle->state = GLOBUS_XIO_MODE_E_ERROR;
    }
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_register_open:
    GlobusXIOModeEDebugExitWithError();
    return result;

}


static
globus_result_t
globus_l_xio_mode_e_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_l_xio_mode_e_attr_t *        attr;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_mode_e_open);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *) driver_link;
    attr = (globus_l_xio_mode_e_attr_t *) driver_attr;
    if (!handle) /* Client */
    {
        result = globus_l_xio_mode_e_handle_create(&handle, attr);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_handle_create;
        }
        result = globus_xio_contact_info_to_string(
                        contact_info, &handle->cs);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_contact_info_to_string;
        }
        handle->outstanding_op = op;
        result = globus_l_xio_mode_e_open_new_stream(
                        handle, globus_l_xio_mode_e_open_cb);
        if (result != GLOBUS_SUCCESS)
        {
            result = GlobusXIOModeEOpenError("Error opening a stream");
            goto error_open_new_stream;
        }
    }
    else                /* Server */
    {
        result = globus_l_xio_mode_e_server_open(handle, op);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_server_open; 
        }
    }
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_open_new_stream:
error_contact_info_to_string:
    globus_l_xio_mode_e_handle_destroy(handle);    
error_handle_create:
error_server_open:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
globus_result_t
globus_i_xio_mode_e_register_read_header(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle)
{
    globus_l_xio_mode_e_header_t *      header;
    globus_size_t                       header_size;
    globus_result_t                     result;
    GlobusXIOName(globus_i_xio_mode_e_register_read_header);

    GlobusXIOModeEDebugEnter();
    globus_l_xio_mode_e_server_connection_handle_init(connection_handle);
    header = (globus_l_xio_mode_e_header_t *)
                    globus_memory_pop_node(
                        &connection_handle->mode_e_handle->header_memory);
    header_size = sizeof(globus_l_xio_mode_e_header_t);
    result = globus_xio_register_read(
        connection_handle->xio_handle,
        (globus_byte_t*)header,
        header_size,
        header_size,
        NULL,               /* data_desc */
        globus_l_xio_mode_e_read_header_cb,
        connection_handle);
    GlobusXIOModeEDebugExit();
    return result;
}


static
void
globus_l_xio_mode_e_read_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_result_t                     res = result;
    globus_l_xio_mode_e_connection_handle_t *      
                                        connection_handle;
    globus_l_xio_mode_e_handle_t *      handle;
    globus_bool_t                       eof;
    globus_xio_operation_t              op;
    globus_off_t                        offset;
    globus_fifo_t                       op_q;
    GlobusXIOName(globus_l_xio_mode_e_read_cb);

    GlobusXIOModeEDebugEnter();
    globus_fifo_init(&op_q);
    connection_handle = (globus_l_xio_mode_e_connection_handle_t *) user_arg;
    handle = connection_handle->mode_e_handle; 
    /* 
     * register_read function called below resets connection_handle->op. 
     * I'm making a copy here to finish the operation 
     */
    op = connection_handle->op; 
    offset = connection_handle->outstanding_data_offset;
    if (connection_handle->iovec_index != -1)
    {
        iovec[connection_handle->iovec_index].iov_len = 
                                        connection_handle->iovec_index_len;
        connection_handle->iovec_index = -1;
    }
    globus_mutex_lock(&handle->mutex); 
    if (result == GLOBUS_SUCCESS)
    {    
        connection_handle->outstanding_data_len -= nbytes;
        if (connection_handle->outstanding_data_len > 0)
        {
            globus_l_xio_mode_e_process_outstanding_data(connection_handle);
        }
        else if (connection_handle->eod) 
        {
            eof = globus_l_xio_mode_e_process_eod(connection_handle, op_q);
            if (eof)
            {
                globus_xio_driver_set_eof_received(connection_handle->op);
                res = GlobusXIOErrorEOF();
                if (handle->state == GLOBUS_XIO_MODE_E_OPEN)
                {
                    handle->state = GLOBUS_XIO_MODE_E_EOF_DELIVERED;
                }
            }
        }
        else
        {
            result = globus_i_xio_mode_e_register_read_header(
                                                        connection_handle);
            if (result != GLOBUS_SUCCESS)
            {
                /* next read would fail */
                handle->state = GLOBUS_XIO_MODE_E_ERROR;
            }
        }
    }
    globus_mutex_unlock(&handle->mutex); 
    globus_xio_driver_data_descriptor_cntl(
                        op,
                        NULL,
                        GLOBUS_XIO_DD_SET_OFFSET,
                        offset);
    globus_xio_driver_finished_read(op, res, nbytes);
    while (!globus_fifo_empty(&op_q))
    {
        op = (globus_xio_operation_t)globus_fifo_dequeue(&op_q);
        globus_xio_driver_finished_read(op, res, 0);
    }
    globus_fifo_destroy(&op_q);
    GlobusXIOModeEDebugExit();
    return;
}


static
globus_result_t
globus_i_xio_mode_e_register_read(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle)
{
    globus_size_t                       iovec_len;    
    globus_result_t                     result;
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
    GlobusXIOName(globus_i_xio_mode_e_register_read);

    GlobusXIOModeEDebugEnter();
    iovec = connection_handle->iovec;
    iovec_count = connection_handle->iovec_count;
    GlobusXIOUtilIovTotalLength(iovec_len, iovec, iovec_count);
    if (connection_handle->outstanding_data_len < iovec_len) 
    {
        globus_size_t                   size = 0;
        int                             i;
        iovec_len = connection_handle->outstanding_data_len;
        for (i = 0; i < iovec_count; i++)
        {
            size += iovec[i].iov_len;
            if (size > iovec_len)
            {
                connection_handle->iovec_index = i;
                iovec_count = i + 1;
                connection_handle->iovec_index_len = iovec[i].iov_len;
                iovec[i].iov_len -= (size - iovec_len);
                break;
            }
        }
    }
    result = globus_xio_register_readv(
                connection_handle->xio_handle,
                (globus_xio_iovec_t*)iovec, 
                iovec_count,
                iovec_len,
                NULL,
                globus_l_xio_mode_e_read_cb,
                connection_handle);

    GlobusXIOModeEDebugExit();
    return result;
}                        


static
void
globus_l_xio_mode_e_reset_connections(
    globus_l_xio_mode_e_handle_t *      handle)
{
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    globus_result_t                     result; 
    GlobusXIOName(globus_l_xio_mode_e_reset_connections);
    GlobusXIOModeEDebugEnter();
    handle->eod_count = -1;
    handle->eods_received = 0;
    while (!globus_fifo_empty(&handle->eod_q))
    {
        connection_handle = (globus_l_xio_mode_e_connection_handle_t *)
                        globus_fifo_dequeue(&handle->eod_q);
        result = globus_i_xio_mode_e_register_read_header(connection_handle);
        if (result != GLOBUS_SUCCESS)
        {
            handle->state = GLOBUS_XIO_MODE_E_ERROR;
            goto error;
        }
    }
    handle->state = GLOBUS_XIO_MODE_E_OPEN;
    GlobusXIOModeEDebugExit();
    return;

error:
    GlobusXIOModeEDebugExitWithError();
    return;
}


static
globus_result_t
globus_l_xio_mode_e_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t*           iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_result_t                     result;
    globus_size_t                       wait_for;
    GlobusXIOName(globus_l_xio_mode_e_read);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *) driver_specific_handle;

    wait_for = globus_xio_operation_get_wait_for(op);
    if (wait_for != 1)
    {
        result = GlobusXIOModeEReadError(
                        "Waitforbytes parameter is not equal to one");
        goto error_wait_for;
    }
    globus_mutex_lock(&handle->mutex);
    switch (handle->state)
    {
        case GLOBUS_XIO_MODE_E_EOF_RECEIVED:
            globus_xio_driver_set_eof_received(op);
            handle->state = GLOBUS_XIO_MODE_E_EOF_DELIVERED;
            result = GlobusXIOErrorEOF();
            goto error_eof;
        case GLOBUS_XIO_MODE_E_EOF_DELIVERED:
            if (globus_xio_driver_eof_received(op) || 
                                        handle->connection_count == 0)
            {
                result = GlobusXIOErrorEOF();
                goto error_eof;
            }
            else
            {
                globus_l_xio_mode_e_reset_connections(handle);
                /* 
                 * connection_q will be empty at this point. I let this
                 * fall through to enqueue the request in the io_q
                 */
            }
            /* fall through */
        case GLOBUS_XIO_MODE_E_OPEN:
            if (globus_fifo_empty(&handle->connection_q))
            {
                globus_i_xio_mode_e_requestor_t *   requestor;
                requestor = (globus_i_xio_mode_e_requestor_t *)
                            globus_memory_pop_node(&handle->requestor_memory);
                requestor->op = op;
                requestor->iovec = (globus_xio_iovec_t*)iovec;
                requestor->iovec_count = iovec_count;
                globus_fifo_enqueue(&handle->io_q, requestor);
            }
            else
            {
                globus_l_xio_mode_e_connection_handle_t * connection_handle;
                connection_handle = (globus_l_xio_mode_e_connection_handle_t*) 
                    globus_fifo_dequeue(&handle->connection_q);
                connection_handle->op = op;
                connection_handle->iovec = (globus_xio_iovec_t*)iovec;
                connection_handle->iovec_count = iovec_count;
                globus_i_xio_mode_e_register_read(connection_handle);
            }
            break;
        default:
            result = GlobusXIOModeEReadError("Invalid state");
            goto error_invalid_state;
    }
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_invalid_state:
error_eof:
    globus_mutex_unlock(&handle->mutex);
error_wait_for:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
void
globus_l_xio_mode_e_write_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    globus_l_xio_mode_e_handle_t *      handle;
    globus_xio_operation_t              op;
    globus_xio_operation_t              requestor_op;
    globus_off_t                        offset;
    globus_off_t                        requestor_offset;
    globus_bool_t                       finish = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_mode_e_write_cb);

    GlobusXIOModeEDebugEnter();
    connection_handle = (globus_l_xio_mode_e_connection_handle_t *) user_arg;
    handle = connection_handle->mode_e_handle;
    op = connection_handle->op;
    offset = connection_handle->outstanding_data_offset;
    globus_mutex_lock(&handle->mutex);
    if (!globus_fifo_empty(&handle->io_q))
    {
        globus_i_xio_mode_e_requestor_t * requestor;
        requestor = (globus_i_xio_mode_e_requestor_t *)
                        globus_fifo_dequeue(&handle->io_q);
        connection_handle->op = requestor->op;
        connection_handle->iovec = requestor->iovec;
        connection_handle->iovec_count = requestor->iovec_count;
        globus_memory_push_node(&handle->requestor_memory, (void*)requestor);
        res = globus_i_xio_mode_e_register_write(connection_handle);
        if (res != GLOBUS_SUCCESS)
        {   
            requestor_op = requestor->op;    
            requestor_offset = connection_handle->outstanding_data_offset;
            finish = GLOBUS_TRUE;
            handle->state = GLOBUS_XIO_MODE_E_ERROR;
        }
    }
    else
    {
        globus_fifo_enqueue(&handle->connection_q, connection_handle);
    }
    globus_mutex_unlock(&handle->mutex);
    globus_xio_driver_data_descriptor_cntl(
                        op,
                        NULL,
                        GLOBUS_XIO_DD_SET_OFFSET,
                        offset);
    globus_xio_driver_finished_write(op, result, nbytes);
    if (finish)
    {
        globus_xio_driver_data_descriptor_cntl(
                    requestor_op,
                    NULL,
                    GLOBUS_XIO_DD_SET_OFFSET,
                    requestor_offset);
        globus_xio_driver_finished_write(requestor_op, res, 0);
    }
    GlobusXIOModeEDebugExit();
    return;
}


static
void
globus_l_xio_mode_e_write_header_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_result_t                     res;
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    globus_l_xio_mode_e_handle_t *      handle;
    const globus_xio_iovec_t *          iovec;
    int                                 iovec_count;
    globus_size_t                       iovec_len;
    globus_xio_operation_t              op;
    globus_off_t                        offset;
    GlobusXIOName(globus_l_xio_mode_e_write_header_cb);

    GlobusXIOModeEDebugEnter();
    connection_handle = (globus_l_xio_mode_e_connection_handle_t *) user_arg;
    handle = connection_handle->mode_e_handle;
    globus_mutex_lock(&handle->mutex);
    globus_memory_push_node(&handle->header_memory, (void*)buffer);
    if (result == GLOBUS_SUCCESS)
    {
        iovec = connection_handle->iovec;
        iovec_count = connection_handle->iovec_count;
        GlobusXIOUtilIovTotalLength(iovec_len, iovec, iovec_count);
        res = globus_xio_register_writev(
            connection_handle->xio_handle,
            (globus_xio_iovec_t*)iovec,
            iovec_count,
            iovec_len,
            GLOBUS_NULL,
            globus_l_xio_mode_e_write_cb,
            connection_handle);
        if (res != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        res = result;
        goto error;
    }
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExit();
    return;

error:
    handle->state = GLOBUS_XIO_MODE_E_ERROR;
    op = connection_handle->op;
    offset = connection_handle->outstanding_data_offset;
    globus_fifo_enqueue(&handle->connection_q, connection_handle);
    globus_mutex_unlock(&handle->mutex);
    globus_xio_driver_data_descriptor_cntl(
                    op,
                    NULL,
                    GLOBUS_XIO_DD_SET_OFFSET,
                    offset);
    globus_xio_driver_finished_write(op, res, 0);
    GlobusXIOModeEDebugExitWithError();
    return;
}


/* called locked */
static
globus_result_t
globus_i_xio_mode_e_register_write(
    globus_l_xio_mode_e_connection_handle_t *      
                                        connection_handle)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_off_t                        size;
    globus_off_t                        offset;
    globus_l_xio_mode_e_header_t *      header;
    globus_size_t                       header_size;
    globus_result_t                     result;
    GlobusXIOName(globus_i_xio_mode_e_register_write);

    GlobusXIOModeEDebugEnter();
    handle = connection_handle->mode_e_handle;
    header = (globus_l_xio_mode_e_header_t *) globus_memory_pop_node(
                                                    &handle->header_memory);
    header_size = sizeof(globus_l_xio_mode_e_header_t);
    memset(header, 0, header_size);
    GlobusXIOUtilIovTotalLength(
            size, connection_handle->iovec, connection_handle->iovec_count);
    globus_i_xio_mode_e_header_encode(header->count, size);
    result = globus_xio_driver_data_descriptor_cntl(
                connection_handle->op,
                NULL,
                GLOBUS_XIO_DD_GET_OFFSET,
                &offset);
    if (result != GLOBUS_SUCCESS || offset == -1)
    {
        offset = handle->offset;
    }
    globus_i_xio_mode_e_header_encode(header->offset, offset);
    connection_handle->outstanding_data_offset = offset;
    handle->offset += size;
    result = globus_xio_register_write(
        connection_handle->xio_handle, 
        (globus_byte_t*)header, 
        header_size,
        header_size,
        GLOBUS_NULL,
        globus_l_xio_mode_e_write_header_cb,
        connection_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }               
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_mode_e_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;    
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_write);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *) driver_specific_handle;
    /* 
     * Mode E is unidirectional. Server can only read and client can only write
     */
    globus_assert(handle->server == GLOBUS_NULL); 
    globus_mutex_lock(&handle->mutex);
    if (!globus_fifo_empty(&handle->connection_q))
    {
        connection_handle = (globus_l_xio_mode_e_connection_handle_t *)
                                globus_fifo_dequeue(&handle->connection_q);
        connection_handle->op = op;
        connection_handle->iovec = (globus_xio_iovec_t*)iovec;
        connection_handle->iovec_count = iovec_count;
        result = globus_i_xio_mode_e_register_write(connection_handle);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_register_write;
        }
    }
    else
    {
        globus_i_xio_mode_e_requestor_t * requestor;
        if (handle->connection_count < handle->attr->max_connection_count)
        {
            result = globus_l_xio_mode_e_open_new_stream(
                        handle, globus_i_xio_mode_e_open_cb);
            if (result != GLOBUS_SUCCESS)
            {
                result = GlobusXIOModeEWriteError(
                                "Error opening a new stream");
                goto error_open_new_stream;
            }
        }
        requestor = (globus_i_xio_mode_e_requestor_t *)
                    globus_memory_pop_node(&handle->requestor_memory);
        requestor->op = op;
        requestor->iovec = (globus_xio_iovec_t*)iovec;
        requestor->iovec_count = iovec_count;
        globus_fifo_enqueue(&handle->io_q, requestor);
    }
    globus_mutex_unlock(&handle->mutex);

    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_open_new_stream:
error_register_write:
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
void
globus_l_xio_mode_e_close_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_bool_t                       destroy = GLOBUS_FALSE;
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_mode_e_close_cb);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *)user_arg;
/* check result */
    globus_mutex_lock(&handle->mutex);
    if (--handle->connection_count == 0)
    {
        switch (handle->state)
        {
            case GLOBUS_XIO_MODE_E_CLOSING:
                finish = GLOBUS_TRUE;
                op = handle->outstanding_op;
                if (--handle->ref_count == 0)
                {
                    destroy = GLOBUS_TRUE;
                }
                break;
            case GLOBUS_XIO_MODE_E_EOF_RECEIVED:
            case GLOBUS_XIO_MODE_E_EOF_DELIVERED:
                break;
            default:
                globus_assert(0 && "Unexpected state in mode_e_close_cb");
        }
    }
    globus_mutex_unlock(&handle->mutex);
    if (finish)
    {
        if (destroy)
        {
            globus_l_xio_mode_e_handle_destroy(handle);
        }
        globus_xio_driver_finished_close(op, result);
    }
    GlobusXIOModeEDebugExit();
}


static
void
globus_l_xio_mode_e_write_eod_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    globus_l_xio_mode_e_handle_t *      handle;
    globus_l_xio_mode_e_header_t *      header; 
    globus_xio_operation_t              op;
    globus_bool_t                       finish = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_mode_e_write_eod_cb);

    GlobusXIOModeEDebugEnter();
    connection_handle = (globus_l_xio_mode_e_connection_handle_t *) user_arg;
    header = (globus_l_xio_mode_e_header_t *) buffer;
    handle = connection_handle->mode_e_handle;
/* check result */
    ++handle->eods_sent; 
    globus_mutex_lock(&handle->mutex);
    if (header->descriptor & GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_CLOSE)
    {
        globus_xio_register_close(
                xio_handle,
                handle->attr->xio_attr,
                globus_l_xio_mode_e_close_cb,
                handle);
        globus_free(connection_handle);
    }
    else
    {
        globus_fifo_enqueue(&handle->eod_q, connection_handle);
        if (handle->eods_sent == handle->connection_count)
        {
            globus_fifo_move(&handle->connection_q, &handle->eod_q);
            op = connection_handle->op;
            finish = GLOBUS_TRUE;
        }
        
    }           
    globus_memory_push_node(&handle->header_memory, (void*)buffer);
    globus_mutex_unlock(&handle->mutex);
    if (finish)
    {
        globus_xio_driver_finished_close(op, GLOBUS_SUCCESS);
    }
    GlobusXIOModeEDebugExit();
}


static
globus_result_t
globus_l_xio_mode_e_register_eod(
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle,
    globus_bool_t                       close,
    globus_bool_t                       eof)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_l_xio_mode_e_header_t *      header;
    globus_size_t                       header_size;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_register_eod);

    GlobusXIOModeEDebugEnter();
    handle = connection_handle->mode_e_handle;
    globus_mutex_lock(&handle->mutex);
    header = (globus_l_xio_mode_e_header_t *)
                    globus_memory_pop_node(&handle->header_memory);
    header_size = sizeof(globus_l_xio_mode_e_header_t);
    memset(header, 0, header_size);
    header->descriptor = GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_EOD;
    if (close)
    {
        header->descriptor |= GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_CLOSE;
    }
    if (eof)
    {
        header->descriptor |= GLOBUS_XIO_MODE_E_DATA_DESCRIPTOR_EOF;
        globus_i_xio_mode_e_header_encode(header->offset, 
                            handle->attr->total_connection_count);
    }
    result = globus_xio_register_write(
        connection_handle->xio_handle,
        (globus_byte_t*)header,
        header_size,
        header_size,
        GLOBUS_NULL,
        globus_l_xio_mode_e_write_eod_cb,
        connection_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error:
    globus_memory_push_node(&handle->header_memory, (void*)header);         
    globus_mutex_unlock(&handle->mutex);
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
void
globus_l_xio_mode_e_close_connections(
    globus_fifo_t *                     connection_q)
{
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    GlobusXIOName(globus_l_xio_mode_e_close_connections);

    GlobusXIOModeEDebugEnter();
    while (!globus_fifo_empty(connection_q))
    {
        connection_handle = (globus_l_xio_mode_e_connection_handle_t *)
                            globus_fifo_dequeue(connection_q);
        globus_xio_register_close(
            connection_handle->xio_handle, 
            NULL, 
            globus_l_xio_mode_e_close_cb,
            connection_handle->mode_e_handle);
        globus_free(connection_handle);
    }
    GlobusXIOModeEDebugExit();
}


static
globus_result_t
globus_l_xio_mode_e_close(
    void *                              driver_specific_handle,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_l_xio_mode_e_connection_handle_t *
                                        connection_handle;
    globus_l_xio_mode_e_attr_t *        attr;
    globus_result_t                     result;
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_bool_t                       destroy = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_mode_e_close);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *) driver_specific_handle;
    attr = (globus_l_xio_mode_e_attr_t *) 
                driver_attr ? driver_attr : handle->attr;
    globus_mutex_lock(&handle->mutex);
    handle->attr->total_connection_count = attr->total_connection_count;
    /* 
     * If at all eof is sent, it should be sent on only one connection. 
     * I send it on the connection on the top of the q (I assume there
     * would be atleast one connection alive. thats why i dont check if
     * fifo is empty before dequeuing the first connection). The duplication
     * of the while loop body below is to avoid checking a boolean in each
     * iteration inside the while loop. Note the third parameter for 
     * register_eod function is always GLOBUS_FALSE for the calls inside
     * the while loop
     */
    handle->outstanding_op = op;
    if (!handle->server)
    {
        connection_handle = (globus_l_xio_mode_e_connection_handle_t *)
                                globus_fifo_dequeue(&handle->connection_q);
        handle->state = GLOBUS_XIO_MODE_E_CLOSING;
        globus_l_xio_mode_e_register_eod(
                        connection_handle, GLOBUS_TRUE, attr->eof);
        while (!globus_fifo_empty(&handle->connection_q))
        {
            connection_handle = (globus_l_xio_mode_e_connection_handle_t *)
                                    globus_fifo_dequeue(&handle->connection_q);
            result = globus_l_xio_mode_e_register_eod(
                            connection_handle, GLOBUS_TRUE, GLOBUS_FALSE);
        }
    }
    else
    {
        if (handle->connection_count == 0)
        {
            finish = GLOBUS_TRUE;
            if (--handle->ref_count == 0)
            {
                destroy = GLOBUS_TRUE;
            }
        }
        else
        {
            globus_l_xio_mode_e_close_connections(&handle->connection_q);
            globus_l_xio_mode_e_close_connections(&handle->eod_q);
            handle->state = GLOBUS_XIO_MODE_E_CLOSING;
        }
    }
    globus_mutex_unlock(&handle->mutex);
    if (finish)
    {
        if (destroy)
        {
            globus_l_xio_mode_e_handle_destroy(handle);
        }
        globus_xio_driver_finished_close(op, GLOBUS_SUCCESS);
    }
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;      
}


static
globus_result_t
globus_l_xio_mode_e_cntl(
    void  *                             driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_xio_mode_e_handle_t *      handle;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_cntl);

    GlobusXIOModeEDebugEnter();
    handle = (globus_l_xio_mode_e_handle_t *) driver_specific_handle;
    switch(cmd)
    {
        default:
            result = GlobusXIOErrorInvalidCommand(cmd);
            goto error;     
    }   
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_mode_e_attr_init(
    void **                             out_attr)
{
    globus_l_xio_mode_e_attr_t *        attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_attr_init);

    GlobusXIOModeEDebugEnter();
    /*
     *  create a mode_e attr structure and intialize its values
     */
    attr = (globus_l_xio_mode_e_attr_t *) 
                globus_malloc(sizeof(globus_l_xio_mode_e_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }
    memcpy(attr, &globus_l_xio_mode_e_attr_default, 
                        sizeof(globus_l_xio_mode_e_attr_t));
    *out_attr = attr;
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_mode_e_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_result_t                     result;
    globus_l_xio_mode_e_attr_t *       attr;
    GlobusXIOName(globus_l_xio_mode_e_attr_cntl);

    GlobusXIOModeEDebugEnter();
    attr = (globus_l_xio_mode_e_attr_t *) driver_attr;
    switch(cmd)
    {
        case GLOBUS_XIO_MODE_E_SET_STACK:
            /* globus_xio_stack_t is a pointer to a struct */
            attr->stack = va_arg(ap, globus_xio_stack_t);
            break;
        case GLOBUS_XIO_MODE_E_GET_STACK:
        {
            globus_xio_stack_t * stack = va_arg(ap, globus_xio_stack_t *);
            *stack = attr->stack;
            break;
        }
        case GLOBUS_XIO_MODE_E_SET_NUM_STREAMS:
            attr->max_connection_count = va_arg(ap, int);
            break;
        case GLOBUS_XIO_MODE_E_GET_NUM_STREAMS:
        {
            int * max_connection_count = va_arg(ap, int*);
            *max_connection_count = attr->max_connection_count;
            break;
        }
        case GLOBUS_XIO_MODE_E_APPLY_ATTR_CNTLS:
        {
            globus_xio_mode_e_attr_cntl_callback_t attr_cntl_cb;
            attr_cntl_cb = va_arg(ap, globus_xio_mode_e_attr_cntl_callback_t);
            attr->attr_cntl_cb = attr_cntl_cb;
            break;
        }
        case GLOBUS_XIO_MODE_E_SET_EOF:
        {
            globus_bool_t eof = va_arg(ap, globus_bool_t);
            int total_connection_count = va_arg(ap, int);
            attr->eof = eof;
            attr->total_connection_count = total_connection_count;
            break;
        }
        case GLOBUS_XIO_MODE_E_GET_EOF:
        {
            globus_bool_t * eof = va_arg(ap, globus_bool_t*);
            *eof = attr->eof;
            break;
        }
        default:
           result = GlobusXIOErrorInvalidCommand(cmd);
           goto error;
    }   
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error:  
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_mode_e_attr_copy(
    void **                             dst,
    void *                              src)
{
    globus_l_xio_mode_e_attr_t *        src_attr;
    globus_l_xio_mode_e_attr_t *        dst_attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_attr_copy);

    GlobusXIOModeEDebugEnter();
    dst_attr = (globus_l_xio_mode_e_attr_t *) 
                globus_malloc(sizeof(globus_l_xio_mode_e_attr_t));
    if(!dst_attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_dst_attr;
    }
    src_attr = (globus_l_xio_mode_e_attr_t *) src;
    memcpy(dst_attr, src_attr, sizeof(globus_l_xio_mode_e_attr_t)); 
    /*
     * if there is any ptr in the attr structure do attr->xptr =
     * globus_libc_strdup(attr->xptr) and do if (!attr->xptr) { result =
     * GlobusXIOErrorMemory("xptr"); goto error_xptr; }
     */
    *dst = dst_attr;
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_dst_attr:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_mode_e_attr_destroy(
    void *                              driver_attr)
{
    globus_l_xio_mode_e_attr_t *        attr;
    GlobusXIOName(globus_l_xio_mode_e_attr_destroy);

    GlobusXIOModeEDebugEnter();
    attr = (globus_l_xio_mode_e_attr_t *) driver_attr;
    globus_free(attr);
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_xio_mode_e_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_mode_e_init);

    GlobusXIOModeEDebugEnter();
    result = globus_xio_driver_init(&driver, "mode_e", GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_driver_init", result);
        goto error_init;
    }
    globus_xio_driver_set_transport(
        driver,
        globus_l_xio_mode_e_open,
        globus_l_xio_mode_e_close,
        globus_l_xio_mode_e_read,
        globus_l_xio_mode_e_write,
        globus_l_xio_mode_e_cntl);
    globus_xio_driver_set_server(
        driver,
        globus_l_xio_mode_e_server_init,
        globus_l_xio_mode_e_server_accept,
        globus_l_xio_mode_e_server_destroy,
        globus_l_xio_mode_e_server_cntl,
        globus_l_xio_mode_e_link_cntl,
        globus_l_xio_mode_e_link_destroy);
    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_mode_e_attr_init,
        globus_l_xio_mode_e_attr_copy,
        globus_l_xio_mode_e_attr_cntl,
        globus_l_xio_mode_e_attr_destroy);
    *out_driver = driver;
    GlobusXIOModeEDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    GlobusXIOModeEDebugExitWithError();
    return result;
}


static
void
globus_l_xio_mode_e_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}


GlobusXIODefineDriver(
    mode_e,
    globus_l_xio_mode_e_init,
    globus_l_xio_mode_e_destroy);

