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


struct globus_i_xio_driver_op_stack_s
{
    /* the aray of drivers and driver specific data */
    struct globus_xio_driver_s *                driver;
    void *                                      driver_handle;
    void *                                      driver_attr;

    /* callback information */
    globus_xio_callback_t                       open_close_cb;  
    globus_xio_data_callback_t                  data_cb;
    void *                                      user_ptr;
};


struct globus_i_xio_target_s
{
    struct globus_i_xio_driver_target_stack_s * target_stack;
    int                                         stack_size;
};

struct globus_i_xio_handle_s
{
    struct globus_i_xio_driver_target_stack_s * target_stack;
    int                                         stack_size;
    globus_mutex_t                              mutex;

};

/*
 *  represents a requested io operation (open close read or write).
 */
struct globus_i_xio_operation_s
{   
    globus_i_xio_operation_type_t               op_type;

    struct globus_i_xio_handle_s *              xio_handle;
    /* this is simply a convenience pointer, can be accessedd from handle */
    struct globus_i_xio_driver_op_stack_s *     driver_stack;
    /* tracks the position into the driver stack */
    int                                         current_driver_ndx;

    /* data operation members */
    globus_iovec_t                              iovec;
    int                                         iovec_count;
    struct globus_i_xio_data_descriptor_s *     data_desc;

    int                                         close_how;

    /* callback pointer info */
    globus_xio_callback_t                       open_close_cb;  
    globus_xio_data_callback_t                  data_cb;
    void *                                      user_ptr;
};



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
