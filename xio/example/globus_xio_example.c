#include <globus_xio.h>

int
main(
    int                             argc,
    char *                          argv[])
{
    globus_result_t                 res;
    char *                          driver_name;
    globus_xio_driver_t             driver;
    globus_xio_server_t             server;
    globus_xio_stack_t              stack;
    globus_xio_handle_t             handle;
    globus_size_t                   nbytes;
    globus_xio_target_t             target;
    int                             ctr;
    char *                          contact_string = NULL;
    char                            buf[256];

    for(ctr = 1; ctr < argc - 1; ctr++)
    {
        if(strcmp(argv[ctr], "-c") == 0 && ctr < argc - 2)
        {
            ctr++;
            contact_string = argv[ctr];
        }
    }

    driver_name = argv[ctr];

    globus_module_activate(GLOBUS_XIO_MODULE);
    res = globus_xio_driver_load(
            driver_name,
            &driver);
    assert(res != GLOBUS_SUCCESS);
    
    globus_xio_stack_init(&stack, NULL);
    globus_xio_stack_push_driver(stack, driver);

    if(contact_string == NULL)
    {
        globus_xio_server_create(&server, NULL, stack);
/*        globus_xio_server_cntl(
            server, 
            NULL, 
            GLOBUS_XIO_CNTL_GET_CONTACT_STRING,
            &buf, 
            sizeof(buf));
        globus_libc_fprintf(stdout, "serving at: %s.\n", buf);
*/
        res = globus_xio_server_accept(
                &target,
                server,
                NULL);
        assert(res != GLOBUS_SUCCESS);
        globus_xio_server_close(server);
    }
    else
    {
        globus_xio_target_init(
            &target, 
            NULL,
            contact_string, 
            stack);
    }

    res = globus_xio_open(
            &handle,
            NULL,
            target);
    assert(res != GLOBUS_SUCCESS);

    do
    {
        res = globus_xio_read(handle, buf, sizeof(buf), 1, &nbytes, NULL);
        if(nbytes > 0)
        {
            buf[nbytes] = '\0';
            fprintf(stderr, "%s", buf);
        }
    } while(res == GLOBUS_SUCCESS);
    
    if(!globus_xio_error_is_eof(res))
    {
        /* bad error occurred */   
    }
    globus_xio_close(handle, NULL);

    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}
