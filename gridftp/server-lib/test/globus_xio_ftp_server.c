#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"

#define LINE_LEN 1024

void
test_res(
    globus_result_t                         res,
    int                                     line)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }

    fprintf(stderr, "ERROR @ %d: %s\n", line, globus_error_print_chain(
        globus_error_get(res)));

    globus_assert(0);
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_driver_t                     tcp_driver;
    globus_xio_driver_t                     ftp_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    char *                                  cs;
    globus_result_t                         res;
    char                                    line[LINE_LEN];
    globus_bool_t                           done = GLOBUS_FALSE;
    globus_size_t                           nbytes;
    globus_xio_server_t                     server_handle;

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_xio_stack_init(&stack, NULL);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res, __LINE__);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res, __LINE__);
    res = globus_xio_driver_load("gssapi_ftp", &ftp_driver);
    test_res(res, __LINE__);
    res = globus_xio_stack_push_driver(stack, ftp_driver);
    test_res(res, __LINE__);

    globus_xio_server_create(&server_handle, NULL, stack);

    globus_xio_server_get_contact_string(server_handle, &cs);
    fprintf(stdout, "Contact: %s\n", cs);

    globus_xio_server_accept(&xio_handle, server_handle);

    res = globus_xio_open(xio_handle, NULL, NULL);
    test_res(res, __LINE__);
    res = globus_xio_write(xio_handle, "220 hello\r\n", strlen("220 hello\r\n"),
        strlen("220 hello\r\n"), &nbytes, NULL);
    test_res(res, __LINE__);

    while(!done)
    {
        res = globus_xio_read(
            xio_handle, line, LINE_LEN, 1, &nbytes, NULL);
        test_res(res, __LINE__);
        line[nbytes] = '\0';

        fprintf(stdout, "%s", line);
    }

    globus_xio_close(xio_handle, NULL);

    globus_module_activate(GLOBUS_XIO_MODULE);

    return 0;
}
