

enum
{
    GLOBUS_XIO_FILE_SET_MODE = 1,
    GLOBUS_XIO_FILE_GET_MODE,
    GLOBUS_XIO_FILE_MAX_CMD = GLOBUS_XIO_FILE_GET_MODE
}

struct globus_l_xio_file_attr_s
{
    int                                         mode;
}

struct globus_l_xio_file_target_s
{
    char                                        cs[256];
}

globus_result_t
globus_xio_driver_file(
    globus_xio_driver_t *                       out_driver)
{
    *out_driver = &globus_xio_driver_file_info;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_attr_init(
    void **                                     out_attr)
{
    struct globus_l_xio_file_attr_s *           file_attr;

    file_attr = (struct globus_l_xio_file_attr_s *)
        globus_malloc(sizeof(struct globus_l_xio_file_attr_s));

    memset(file_attr, '\0', sizeof(struct globus_l_xio_file_attr_s));

    *out_attr = file_attr;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_attr_cntl(
    void *                                      attr,
    int                                         cmd,
    va_list                                     ap)
{
    switch(cmd)
    {
        case GLOBUS_XIO_FILE_SET_MODE:
            break;

        case GLOBUS_XIO_FILE_GET_MODE:
            break;
    }
}

globus_result_t
globus_xio_driver_file_attr_copy(
    void **                                     dst,
    void *                                      src)
{
    struct globus_l_xio_file_attr_s *           file_attr;

    file_attr = (struct globus_l_xio_file_attr_s *)
        globus_malloc(sizeof(struct globus_l_xio_file_attr_s));

    memcpy(file_attr, src, sizeof(struct globus_l_xio_file_attr_s));

    *dst = file_attr;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_attr_destroy(
    void *                                      attr)
{
    globus_free(attr);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_target_init(
    void **                                     out_target,
    void *                                      target_attr,
    const char *                                contact_string,
    globus_xio_driver_stack_t                   stack)
{
    struct globus_l_xio_file_target_s *         target;

    target = (struct globus_l_xio_file_target_s *)
                globus_malloc(sizeof(struct globus_l_xio_file_target_s));
    sprintf(target->cs, "%s", contact_string);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_target_destroy(
    void *                                      target)
{
    struct globus_l_xio_file_target_s *         file_target;

    file_target = (struct globus_l_xio_file_target_s *) target;

    globus_free(file_target);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_cntl(
     void *                                      driver_handle,
     int                                         cmd,
     ...)
{

    /* get eof */
    return GLOBUS_SUCCESS;
}


globus_result_t
globus_xio_driver_file_open(
    void **                                     driver_handle,
    void *                                      driver_handle_attr,
    void *                                      target,
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               op);
{
    struct globus_l_xio_file_target_s *         file_target;
    struct globus_l_xio_file_handle_s *         file_handle;
    FILE *                                      fptr;

    file_target = (struct globus_l_xio_file_target_s *) target;

    fptr = fopen(file_target->cs, file_ttr->mode);
    if(fptr == NULL)
    {
        return GLOBUS_FAILURE;
    }

    file_handle = (struct globus_l_xio_file_handle_s *)
        globus_malloc(sizeof(struct globus_l_xio_file_handle_s));
    file_handle->fptr = fptr;

    *driver_handle = file_handle;

    globus_xio_driver_finished_open(context, op);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_close(
    void *                                      driver_handle,
    globus_xio_driver_context_t                 context,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_file_handle_s *         file_handle;

    file_handle = (struct globus_l_xio_file_handle_s *) driver_handle;

    fclose(file_handle->fptr);
    globus_free(file_handle);

    globus_xio_driver_finished_close(op);
    globus_xio_driver_close_context(op);
    
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_read(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_file_handle_s *         file_handle;

    file_handle = (struct globus_l_xio_file_handle_s *) driver_handle;

    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        nbytes = fread(iovec[ctr].iov_base, 
                        iovec[ctr].iov_len, 1, file_handle->ptr); 
        if(nbytes != iovec[ctr].iov_len)
        {
            return GLOBUS_FAILURE;
        }
        iovec[ctr].nbytes = nbytes;
    }

    globus_xio_driver_finished_write(op);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_driver_file_write(
    void *                                      driver_handle,
    globus_xio_iovec_t                          iovec,
    int                                         iovec_count,
    globus_xio_driver_operation_t               op)
{
    struct globus_l_xio_file_handle_s *         file_handle;

    file_handle = (struct globus_l_xio_file_handle_s *) driver_handle;

    for(ctr = 0; ctr < iovec_count; ctr++)
    {
        nbytes = fwrite(iovec[ctr].iov_base, 
                        iovec[ctr].iov_len, 1, file_handle->ptr); 
        if(nbytes != iovec[ctr].iov_len)
        {
            return GLOBUS_FAILURE;
        }
        iovec[ctr].nbytes = nbytes;
    }

    globus_xio_driver_finished_write(op);

    return GLOBUS_SUCCESS;
}

typedef struct globus_xio_driver_s 
{
    /*
     *  main io interface functions
     */
    globus_xio_driver_file_open,
    globus_xio_driver_file_close,
    globus_xio_driver_file_read,
    globus_xio_driver_file_write,     
    globus_xio_driver_handle_cntl_t                     handle_cntl_func;
    int                                                 max_handle_cntl_cmd;

    globus_xio_driver_file_target_init,
    globus_xio_driver_file_target_destory,

    /*
     *  No server functions.
     */
    NULL,
    NULL,
    NULL,
    NULL,
    0,

    /*
     *  driver attr functions.  All or none may be NULL
     */
    globus_xio_driver_file_attr_init,
    globus_xio_driver_file_attr_copy,
    globus_xio_driver_file_attr_cntl,
    globus_xio_driver_file_attr_destroy,
    GLOBUS_XIO_FILE_MAX_CMD,
    
    /*
     *  No need for data descriptors.
     */
    NULL,
    NULL,
    NULL,
    NULL,
    0,
};
