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
 *  used by: handle, and target, operation
 *
 *  lifecycle
 *  ---------
 *  When created by target it lives as long as the target does.  Essentially
 *  The user stack is converted into this structure and maintained by the 
 *  target.  Ass soon and the target is destroyed the driver stack is
 *  destroyed.
 *
 *  When used by the handle it is "created" on open from a target (the one in
 *  target is simply reused).  When the handle is destroyed this adt is 
 *  destroyed with it.
 *
 *  Operations simply reference the driver stack maintained by the handle. 
 *  Operations are only allowed to live as long as the handle from which they 
 *  came, so there is no reference counting needed here.
 *
 *  Not all members are used by target.
 */
struct globus_i_xio_driver_target_stack_s
{
    struct globus_xio_driver_s *                driver;
    void *                                      target;
}

struct globus_i_xio_target_s
{
    int                                         stack_size;
    globus_i_xio_driver_target_stack_t          target_stack[1];
};


typedef struct globus_i_xio_handle_s
{
    globus_mutex_t                              mutex;
    globus_memory_t                             op_memory;
    int                                         ref;
    int                                         stack_size;
    globus_i_xio_context_t *                    context_array;

    globus_bool_t                               op_list;

    globus_xio_timeout_callback                 open_timeout;
    globus_reltime_t                            open_timeout_period;
    globus_xio_timeout_callback                 read_timeout;
    globus_reltime_t                            read_timeout_period;
    globus_xio_timeout_callback                 write_timeout;
    globus_reltime_t                            write_timeout_period;
    globus_xio_timeout_callback                 close_timeout;
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

/*
 *  represents a entry in an array of operations.  each entry
 *  is mapped to a driver at the same index.
 */
typedef struct globus_i_xio_op_entry_s
{
    /* callback info arrays */
    globus_xio_driver_callback_t                cb;
    globus_xio_driver_data_callback_t           data_cb;
    void *                                      user_arg;
    globus_size_t                               wait_for_bytes;
    globus_size_t                               nbytes;
    globus_iovec_t                              iovec;
    int                                         iovec_count;

    globus_bool_t                               in_register;
    globus_bool_t                               is_limited;
} globus_i_xio_op_entry_t;

/*
 *  represents a requested io operation (open close read or write).
 */
typedef struct globus_i_xio_operation_s
{
    /* operation type */
    globus_i_xio_operation_type_t               op_type;

    /* flag to determine if cancel should happen */
    globus_bool_t                               progress;
    globus_xio_timeout_callback                 timeout_cb;

    /* reference count for destruction */
    int                                         ref;
    globus_bool_t                               destroy_me;


    globus_i_xio_handle_t *                     xio_handle;

    int                                         close_how;

    /* user callback variables */
    globus_xio_callback_space_t                 space;

    /* result code saved in op for kickouts */
    globus_result_t                             cached_res;

    /* size of the arrays */
    int                                         stack_size;
    /* convience pointer, really owned by handle */
    globus_i_xio_context_t *                    context;
    /* data descriptor */
    globus_i_xio_data_descriptor_t *            data_desc;
    /* current index in the driver stack */
    int                                         ndx;
    /* entry for each thing driver in the stack */
    globus_i_xio_op_entry_s                     entry_array[1];
} globus_i_xio_operation_t;



/***************************************************************************
 *                    Driver accessor macros
 **************************************************************************/
#define GlobusXIODriverAttrInit(__res, __driver, __out_ptr)             \
{                                                                       \
    __res = __driver->attr_init_func(&__out_ptr);                       \
}

#define GlobusXIODriverAttrCntl(__res, __driver, __dsa, __cmd, __ap)    \
{                                                                       \
    __res = __driver->attr_cntl_func(__dsa, __cmd, __ap);               \
}

#define GlobusXIODriverAttrDestroy(__res, __driver, __dsa)              \
{                                                                       \
    __res = __driver->attr_destroy_func(__dsa);                         \
}

#define GlobusXIODriverAttrCopy(__res, __driver, __dst, __src)          \
{                                                                       \
    __res = __driver->attr_copy_func(__dst, __src);                     \
}


#endif
