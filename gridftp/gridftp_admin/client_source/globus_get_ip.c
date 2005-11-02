#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"

#define LINE_LEN 1024

void
test_res(
    globus_result_t                         res)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }

    fprintf(stderr, "ERROR: %s\n", globus_object_printable_to_string(
        globus_error_get(res)));

    globus_assert(0);
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     arg_i = 0;
    int                                     done = GLOBUS_FALSE;
    globus_xio_driver_t                     tcp_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    globus_result_t                         res;
    char *                                  local_contact;
    char *                                  tmp_ptr;
    char *                                  cs;

    if(argc < 2)
    {
        printf("provide a contact string\n");
        return 1;
    }

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_xio_stack_init(&stack, NULL);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res);

    arg_i = 1;
    while(!done)
    {
        cs = argv[arg_i];
        res = globus_xio_handle_create(&xio_handle, stack);
        test_res(res);
        res = globus_xio_open(xio_handle, cs, NULL);
        if(res == GLOBUS_SUCCESS)
        {
            done = GLOBUS_TRUE;
        }
        arg_i++;
        if(arg_i >= argc)
        {
            exit(1);
        }
    }
    res = globus_xio_handle_cntl(
        xio_handle,
        tcp_driver,
        GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT,
        &local_contact);
    test_res(res);
    tmp_ptr = strchr(local_contact, ':');
    assert(tmp_ptr != NULL);
    *tmp_ptr = '\0';
    printf("%s\n", local_contact);
    globus_xio_close(xio_handle, NULL);

    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}
