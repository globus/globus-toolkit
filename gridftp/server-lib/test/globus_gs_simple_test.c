#include "globus_xio.h"
#include "globus_gridftp_server_control.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_ftp_cmd.h"

#define REPLY_220 "220 Hello there\r\n"
#define FTP_USER_ARG (void*)0x15

#define USER_DATA_HANDLE    ((void *) 0xFF)

char *  CONTACT_STRINGS[]     = {"127.0.0.1:2", "192.168.0.1:5566", NULL};

#define CONTACT_STRINGS_COUNT   2


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
    globus_gridftp_server_control_t         server,
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

static void
globus_l_resource_cb(
    globus_gridftp_server_control_op_t      op,
    const char *                            path,
    globus_gridftp_server_control_resource_mask_t mask)
{
    globus_result_t                         res;
    globus_gridftp_server_control_stat_t    stat_info;
    struct stat                             st;

    if(stat(path, &st) < 0)
    {
        globus_gridftp_server_control_finished_resource(
            op,
            globus_error_put(GLOBUS_ERROR_NO_INFO),
            NULL,
            0);
        return;
    }

    stat_info.mode = st.st_mode;
    stat_info.nlink = st.st_nlink;
    stat_info.uid = st.st_uid;
    stat_info.gid = st.st_gid;
    stat_info.size = st.st_size;
    stat_info.atime = st.st_atime;
    stat_info.ctime = st.st_ctime;
    stat_info.mtime = st.st_mtime;
    strcpy(stat_info.name, path);

    res = globus_gridftp_server_control_finished_resource(
        op,
        GLOBUS_SUCCESS,
        &stat_info,
        1);
    globus_assert(res == GLOBUS_SUCCESS);
}

static void
passive_connect(
    globus_gridftp_server_control_op_t      op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    int                                     max)
{
    globus_gridftp_server_control_finished_passive_connect(
        op,
        USER_DATA_HANDLE,
        GLOBUS_SUCCESS,
        GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI,
        (const char **)CONTACT_STRINGS,
        CONTACT_STRINGS_COUNT);
}

static void
active_connect(
    globus_gridftp_server_control_op_t      op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    const char **                           cs,
    int                                     cs_count)
{
    globus_gridftp_server_control_finished_active_connect(
        op,
        USER_DATA_HANDLE,
        GLOBUS_SUCCESS,
        GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI);
}

static void
data_destroy_cb(
    void *                                  user_data_handle)
{
    globus_assert(user_data_handle == USER_DATA_HANDLE);
}


static void
transfer(
    globus_gridftp_server_control_op_t      op,
    void *                                  data_handle,
    const char *                            local_target,
    const char *                            mod_name,
    const char *                            mod_parms)
{
    globus_gridftp_server_control_begin_transfer(op);
    globus_gridftp_server_control_finished_transfer(op, GLOBUS_SUCCESS);
}



void
auth_func(
    globus_gridftp_server_control_op_t      op,
    const char *                            user_name,
    const char *                            pw,
    gss_cred_id_t                           cred,
    gss_cred_id_t                           del_cred)
{
    fprintf(stderr, "User: %s Pass: %s\n", user_name, pw);

    if(strcmp(user_name, "failme") == 0)
    {
        globus_gridftp_server_control_finished_auth(op, (globus_result_t)1, 0);
    }
    else
    {
        globus_gridftp_server_control_finished_auth(
            op, GLOBUS_SUCCESS, getuid());
    }
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_driver_t                     tcp_driver;
    globus_xio_driver_t                     ftp_driver;
    globus_xio_stack_t                      stack;
    globus_xio_attr_t                       xio_attr;
    globus_xio_handle_t                     xio_handle;
    globus_xio_server_t                     xio_server;
    globus_result_t                         res;
    char *                                  cs;
    globus_gridftp_server_control_attr_t    ftp_attr;
    globus_gridftp_server_control_t         ftp_server;

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_module_activate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);

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

    res = globus_xio_server_create(&xio_server, NULL, stack);
    test_res(res, __LINE__);

    res = globus_xio_server_get_contact_string(xio_server, &cs);
    test_res(res, __LINE__);
    fprintf(stdout, "%s\n", cs);

    res = globus_xio_server_accept(&xio_handle, xio_server);
    test_res(res, __LINE__);

    fprintf(stdout, "opening handle\n");
    res = globus_xio_attr_init(&xio_attr);
    test_res(res, __LINE__);
    res = globus_xio_attr_cntl(
        xio_attr, ftp_driver, GLOBUS_XIO_DRIVER_FTP_CMD_BUFFER, GLOBUS_TRUE);
    test_res(res, __LINE__);
    res = globus_xio_open(xio_handle, NULL, xio_attr);
    test_res(res, __LINE__);

    /*
     *  server connection is all set up, hand it to server_lib
     */
    res = globus_gridftp_server_control_init(&ftp_server);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_init(&ftp_attr);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_set_auth(ftp_attr, auth_func);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_set_resource(
        ftp_attr, globus_l_resource_cb);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_data_functions(
        ftp_attr, active_connect, passive_connect, data_destroy_cb);

    res = globus_gridftp_server_control_attr_add_send(
        ftp_attr, NULL, transfer);

    globus_mutex_lock(&globus_l_mutex);
    {
        res = globus_gridftp_server_control_start(
            ftp_server, ftp_attr, xio_handle, globus_l_done_cb, FTP_USER_ARG);
        test_res(res, __LINE__);

        while(!globus_l_done)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    globus_module_deactivate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);
    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}
