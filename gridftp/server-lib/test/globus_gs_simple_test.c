#include "globus_xio.h"
#include "globus_gridftp_server.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_ftp_cmd.h"

#define REPLY_220 "220 Hello there\r\n"
#define FTP_USER_ARG (void*)0x15

static globus_mutex_t                       globus_l_mutex;
static globus_cond_t                        globus_l_cond;
static globus_bool_t                        globus_l_done = GLOBUS_FALSE;

void
test_res(
    globus_result_t                         res,
    int                                     line)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }
                                                                                
    fprintf(stderr, "ERROR at line:%d: %s\n", 
        line,
        globus_object_printable_to_string(
            globus_error_get(res)));
                                                                                
    globus_assert(0);
}

static void
globus_l_done_cb(
    globus_gridftp_server_t                 server,
    globus_result_t                         res,
    void *                                  user_arg)
{
    fprintf(stdout, "Done callback received\n");
    test_res(res, __LINE__);

    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_done = GLOBUS_TRUE;
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
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
    globus_xio_target_t                     target;
    globus_xio_server_t                     server;
    globus_result_t                         res;
    char *                                  cs;
    globus_size_t                           nbytes;
    globus_gridftp_server_attr_t            ftp_attr;
    globus_gridftp_server_t                 ftp_server;

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_module_activate(GLOBUS_GRIDFTP_SERVER_MODULE);

    /*
     *  set up the xio handle
     */
    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res, __LINE__);
    res = globus_xio_driver_load("ftp_cmd", &ftp_driver);
    test_res(res, __LINE__);
    res = globus_xio_stack_init(&stack, NULL);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res, __LINE__);
    res = globus_xio_stack_push_driver(stack, ftp_driver);
    test_res(res, __LINE__);

    res = globus_xio_server_create(&server, NULL, stack);
    test_res(res, __LINE__);

    res = globus_xio_server_cntl(
            server,
            tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_CONTACT,
            &cs);
    test_res(res, __LINE__);

    fprintf(stdout, "%s\n", cs);

    res = globus_xio_server_accept(&target, server, NULL);
    test_res(res, __LINE__);

    res = globus_xio_target_cntl(
        target, ftp_driver, GLOBUS_XIO_DRIVER_FTP_CMD_BUFFER, GLOBUS_TRUE);
    test_res(res, __LINE__);

    fprintf(stdout, "opening handle\n");
    res = globus_xio_open(&xio_handle, NULL, target);
    test_res(res, __LINE__);

    /* send the banner */
    res = globus_xio_write(
        xio_handle, 
        REPLY_220, 
        strlen(REPLY_220),
        strlen(REPLY_220),
        &nbytes,
        NULL);

    /*
     *  server connection is all set up, hand it to server_lib
     */
    res = globus_gridftp_server_init(&ftp_server);
    test_res(res, __LINE__);

    res = globus_gridftp_server_attr_init(&ftp_attr);
    test_res(res, __LINE__);

    res = globus_gridftp_server_attr_set_done(ftp_attr, globus_l_done_cb);

    globus_mutex_lock(&globus_l_mutex);
    {
        res = globus_gridftp_server_start(
            ftp_server, ftp_attr, xio_handle, FTP_USER_ARG);

        while(!globus_l_done)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    fprintf(stdout, "closing handle\n");
    res = globus_xio_close(xio_handle, NULL);
    test_res(res, __LINE__);

    globus_module_deactivate(GLOBUS_GRIDFTP_SERVER_MODULE);
    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}
