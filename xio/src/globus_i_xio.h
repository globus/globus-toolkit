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


/***************************************************************************
 *                    DD accessor macros
 **************************************************************************/


#endif
