#if !defined(GLOBUS_I_XIO_H)
#define GLOBUS_I_XIO_H

/***************************************************************************
 *                    Error construction macros
 **************************************************************************/
#define GlobusXIOErrorBadParameter(func)                                    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            NULL,                                                           \
            GLOBUS_XIO_ERROR_BAD_PARAMETER_ERROR,                           \
            "[%s] Bad parameter",                                           \
            (func)))

#define GlobusXIOErrorMemoryAlloc(func)                                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            NULL,                                                           \
            GLOBUS_XIO_ERROR_BAD_PARAMETER_ERROR,                           \
            "[%s] malloc failure",                                          \
            (func)))

#define GlobusXIOErrorInvalidStack(func)                                    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            NULL,                                                           \
            GLOBUS_XIO_ERROR_INVALID_STACK,                                 \
            "[%s] stack is not valid",                                      \
            (func)))

#define GlobusXIOErrorDriverNotFound(func)                                  \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            NULL,                                                           \
            GLOBUS_XIO_ERROR_DRIVER_NOT_FOUND,                              \
            "[%s] given driver not found",                                  \
            (func)))

#define GlobusXIOErrorOperationCanceled(func)                               \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            NULL,                                                           \
            GLOBUS_XIO_ERROR_DRIVER_NOT_FOUND,                              \
            "[%s] operation was canceled",                                  \
            (func)))

#define GlobusXIOErrorPassToFar(func)                                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            NULL,                                                           \
            GLOBUS_XIO_ERROR_DRIVER_NOT_FOUND,                              \
            "[%s] at bottom of stack.",                                     \
            (func)))

#define GlobusXIOErrorHandleNotOpen(func)                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            NULL,                                                           \
            GLOBUS_XIO_ERROR_DRIVER_NOT_FOUND,                              \
            "[%s] The handle is not in the open state.",                    \
            (func)))
/***************************************************************************
 *                    Internally exposed data structures
 **************************************************************************/

struct globus_l_xio_dd_s
{

    /* matching length arrays */
    void **                                     drivers;
    void **                                     drivers_data;

    /* contains the length of the above 2 arrays */
    int                                         stack_size;
};

struct globus_l_xio_attr_ds_s
{
    void *                                      driver;
    void *                                      driver_attr;
}

struct globus_l_xio_attr_s
{
    struct globus_l_xio_attr_ds_s *             ds_array;
    int                                         max;
    int                                         ndx;
};

struct globus_i_xio_stack_s
{
    globus_list_t *                             driver_stack;
} globus_i_xio_stack_t;

/* 
 *  
 */
typedef struct globus_xio_server_s
{
    globus_xio_server_state_t                   state;

    globus_xio_timeout_callback_t               accept_timeout;

    int                                         ref;

    int                                         stack_size;
    globus_i_xio_server_entry_t                 entry[1];

} globus_i_xio_server_t;


typedef struct globus_i_xio_handle_s
{
    globus_mutex_t                              mutex;
    globus_memory_t                             op_memory;
    int                                         ref;
    int                                         stack_size;
    globus_i_xio_context_t *                    context_array;

    globus_i_xio_handle_state_t                 state;

    /* since only 1 open or close can be outstanding at a time we don't
       need a list */
    globus_i_xio_op_t *                         open_op;
    globus_i_xio_op_t *                         close_op;
    globus_list_t *                             write_op_list;
    globus_list_t *                             read_op_list;

    /* counts outstanding read and write operations */
    int                                         outstanding_operations;

    globus_xio_timeout_callback_t               open_timeout;
    globus_reltime_t                            open_timeout_period;
    globus_xio_timeout_callback_t               read_timeout;
    globus_reltime_t                            read_timeout_period;
    globus_xio_timeout_callback_t               write_timeout;
    globus_reltime_t                            write_timeout_period;
    globus_xio_timeout_callback_t               close_timeout;
    globus_reltime_t                            close_timeout_period;
} globus_i_xio_handle_t;

/*
 *  represents an entry in the array of open handles.
 *
 *  each entry is maped to a driver in the stack
 */
typedef struct globus_i_xio_context_entry_s
{
    globus_xio_driver_t *                       driver;
    void *                                      driver_handle;
    void *                                      driver_attr;
} globus_i_xio_context_entry_t;

/* 
 *  a stretchy array
 */
typedef struct globus_i_xio_context_s
{
    globus_mutex_t                              mutex;
    int                                         ref;
    int                                         size;
    globus_i_xio_context_entry_t                entry_array[1];
} globus_i_xio_context_t;

/* MACROS for accessing the op_entry structure unin elements */
#define _op_ent_data_cb             type_u.handle_s.data_cb
#define _op_ent_waitforbytes        type_u.handle_s.wait_for_bytes
#define _op_ent_nbytes              type_u.handle_s.nbytes
#define _op_ent_iovec               type_u.handle_s.iovec
#define _op_ent_iovec_count         type_u.handle_s.iove_count

#define _op_ent_target              type_u.target_s.target
#define _op_ent_accept_attr         type_u.target_s.accept_attr
/*
 *  represents a entry in an array of operations.  each entry
 *  is mapped to a driver at the same index.
 */
typedef struct globus_i_xio_op_entry_s
{
    /* callback info arrays */
    globus_xio_driver_callback_t                cb;
    void *                                      user_arg;
    globus_xio_driver_t                         driver;

    union
    {
        /* handle op entries */
        struct
        {
            globus_xio_driver_data_callback_t   data_cb;
            globus_size_t                       wait_for_bytes;
            globus_size_t                       nbytes;
            globus_iovec_t                      iovec;
            int                                 iovec_count;
        } handle_s;
        /* target op entries */
        struct
        {
            void *                              target;
            void *                              accept_attr;
        } target_s;
    } type_u;
    globus_bool_t                               in_register;
    globus_bool_t                               is_limited;

    void *                                      target;
} globus_i_xio_op_entry_t;


#define _op_data_cb                             callback_u.data_cb
#define _op_iovec_cb                            callback_u.iovec_cb
#define _op_cb                                  callback_u.cb
#define _accept_cb                              callback_u.accept_cb

#define _op_handle                              type_u.handle_s.handle
#define _op_iovec                               type_u.handle_s.iovec
#define _op_iovec_count                         type_u.handle_s.iovec_count
#define _op_mem_iovec                           type_u.handle_s.mem_iovec
#define _op_context                             type_u.handle_s.context

#define _op_server                              type_u.target_s.server
#define _op_target                              type_u.target_s.target

/*
 *  represents a requested io operation (open close read or write).
 */
typedef struct globus_i_xio_op_s
{
    /* operation type */
    globus_i_xio_op_type_t                      op_type;
    globus_i_xio_op_state_t                     state;

    /*
     * user callbacks.  only 1 will be used per operation
     */
    union
    {
        globus_xio_data_callback_t              data_cb;
        globus_xio_iovec_callback_t             iovec_cb;
        globus_xio_callback_t                   cb;
        globus_xio_accept_callback_t            accept_cb;
    }callback_u;
    void *                                      user_arg;
   
    /*
     *  Union target and operation members that will not overlap together
     */
    union
    { 
        /* handle op stuff */
        struct
        {
            globus_i_xio_handle_t *             handle;

            globus_iovec_t *                    iovec;
            int                                 iovec_count;
            globus_iovec_t                      mem_iovec;

            /* convience pointer, really owned by handle */
            globus_i_xio_context_t *            context;
            /* data descriptor */
            globus_i_xio_data_descriptor_t *    data_desc;
        } handle_s;
        /* target stuff */
        struct
        {
            globus_i_xio_server_t *             server;
            void *                              target;
        } target_s;
    } type_u;

    /* flag to determine if cancel should happen */
    globus_bool_t                               progress;
    globus_xio_timeout_callback_t               timeout_cb;

    /* reference count for destruction */
    int                                         ref;

    /* members for cancelation */
    globus_xio_driver_cancel_callback_t         cancel_cb;
    void *                                      cancel_arg;
    globus_bool_t                               canceled;

    /* user callback variables */
    globus_xio_callback_space_t                 space;

    /* result code saved in op for kickouts */
    globus_result_t                             cached_res;

    /* size of the arrays */
    int                                         stack_size;
    /* current index in the driver stack */
    int                                         ndx;
    /* entry for each thing driver in the stack */
    globus_i_xio_op_entry_t                     entry[1];
} globus_i_xio_op_t;

typedef struct globus_i_xio_target_entry_s
{
    globus_xio_driver_t                         driver;
    void *                                      target;
} globus_i_xio_op_entry_t;

typedef struct globus_i_xio_target_s
{
    int                                         stack_size;
    globus_i_xio_target_entry_t                 entry[1];
} globus_i_xio_target_t; 


typedef enum globus_i_xio_handle_state_e
{
    GLOBUS_XIO_HANDLE_STATE_OPENING,
    GLOBUS_XIO_HANDLE_STATE_OPEN,
    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED,
    GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED,
    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING,
    GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING,
    GLOBUS_XIO_HANDLE_STATE_CLOSING,
    GLOBUS_XIO_HANDLE_STATE_CLOSED,
} globus_i_xio_handle_state_t;

typedef enum globus_i_xio_op_type_e
{
    GLOBUS_XIO_OPERATION_TYPE_FINISHED,
    GLOBUS_XIO_OPERATION_TYPE_OPEN,
    GLOBUS_XIO_OPERATION_TYPE_CLOSE,
    GLOBUS_XIO_OPERATION_TYPE_READ,
    GLOBUS_XIO_OPERATION_TYPE_WRITE,
    GLOBUS_XIO_OPERATION_TYPE_ACCEPT,
    GLOBUS_XIO_OPERATION_TYPE_EOF,
} globus_i_xio_op_type_t;

typedef enum globus_i_xio_op_state_e
{
    GLOBUS_XIO_TARGET_OP_ACCEPTING,
    GLOBUS_XIO_TARGET_OP_SERVER,
    GLOBUS_XIO_TARGET_OP_CLIENT,
    GLOBUS_XIO_TARGET_OP_TIMEOUT_PENDING,
    GLOBUS_XIO_TARGET_OP_ACCEPT_WAITING,
    GLOBUS_XIO_TARGET_OP_CLOSED,
} globus_i_xio_op_state_t;

typedef enum globus_xio_server_state_e
{
    GLOBUS_XIO_SERVER_STATE_OPEN,
    GLOBUS_XIO_SERVER_STATE_ACCEPTING,
    GLOBUS_XIO_SERVER_STATE_CLOSED,
} globus_xio_server_state_t;

#endif
