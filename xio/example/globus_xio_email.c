
int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_driver_t                     tcp;
    globus_xio_driver_t                     smtp;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     smtp_handle;
    globus_xio_handle_t                     stdin_handle;

    if(argc < 2)
    {
        fprintf(stdout, "%s <to address>.\n", argv[0]);
        return 1;
    }

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    res = globus_xio_driver_load("smtp", &smtp_driver);

    globus_xio_stack_init(&stack, NULL);
    globus_xio_stack_push(stack, tcp_driver);
    globus_xio_stack_push(stack, smtp_driver);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}
