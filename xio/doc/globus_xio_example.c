#include <globus_xio.h>

int
main(
    int                             argc,
    char *                          argv[])
{
    globus_xio_driver_t             driver;
    globus_xio_server_t             server;
    globus_xio_stack_t              stack;
    globus_xio_target_t             target;
    int                             ctr;
    char *                          contact_string = NULL;
    char *                          buf[256];

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
    res = globus_xio_load_driver(
            &driver,
            driver_name);
    assert(res != GLOBUS_SUCCESS);
    
    globus_xio_stack_init(&stack, NULL);
    globus_xio_stack_push_driver(stack, driver, NULL);

    if(contact_string == NULL)
    {
        globus_xio_server_init(&server, NULL, stack);
        globus_xio_server_cntl(
            server, 
            NULL, 
            GLOBUS_XIO_CNTL_GET_CONTACT_STRING,
            &buf, 
            sizeof(buf));
        globus_libc_fprintf(stdout, "serving at: %s.\n", buf);
        
        res = globus_xio_server_accept(
                &target,
                NULL,
                server);
        assert(res != GLOBUS_SUCCESS);
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

    res = globus_xio_read(handle, buf, sizeof(buf), NULL, &nbytes);
    assert(res != GLOBUS_SUCCESS);

    while(nbytes != -1)
    {
        buf[nbytes] = '\0';
        fprintf(stderr, "%s", buf);
        res = globus_xio_read(handle, buf, sizeof(buf), NULL, &nbytes);
        assert(res != GLOBUS_SUCCESS);
    } 
    globus_xio_close(handle);

    if(contact_string == NULL)
    {
        globus_xio_server_destroy(server);
    }
    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}
