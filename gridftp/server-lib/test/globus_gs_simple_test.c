#include "globus_xio.h"
#include "globus_gridftp_server_control.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_ftp_cmd.h"
#include "globus_xio_gssapi_ftp.h"

/*
#define FTP_DRIVER_NAME "ftp_cmd"
#define MODE GLOBUS_XIO_DRIVER_FTP_CMD_BUFFER
*/

#define FTP_DRIVER_NAME "gssapi_ftp"
#define MODE GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUPER_MODE

#define REPLY_220 "220 Hello there from simple ftp.\r\n"
#define FTP_USER_ARG (void*)0x15

#define USER_DATA_HANDLE    ((void *) 0xFF)

char *  CONTACT_STRINGS[]     = {"127.0.0.1:2", NULL};

#define CONTACT_STRINGS_COUNT   1

static void
globus_gs_cmd_site(
    globus_gridftp_server_control_op_t      op,
    const char *                            full_command,
    char **                                 cmd_a,
    int                                     argc,
    void *                                  user_arg)
{
    if(strcmp(cmd_a[1], "MINE") == 0)
    {
        globus_gsc_959_finished_command(
            op, "200 successful sire interception\r\n");
    }
    else
    {
        globus_gsc_959_finished_command(op, NULL);
    }
}


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
                                                                                
    fprintf(stderr, "ERROR at line: %d: %s\n", 
        line,
        globus_error_print_chain(
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
list_cb(
    globus_gridftp_server_control_op_t      op,
    void *                                  data_handle,
    const char *                            path)
{
    globus_gridftp_server_control_begin_transfer(op, 0);
    globus_gridftp_server_control_finished_transfer(op, GLOBUS_SUCCESS);
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
    fprintf(stdout, "data_destroy_cb()\n");
    globus_assert(user_data_handle == USER_DATA_HANDLE);
}


static void
transfer(
    globus_gridftp_server_control_op_t      op,
    void *                                  data_handle,
    const char *                            local_target,
    const char *                            mod_name,
    const char *                            mod_parms,
    globus_gridftp_server_control_restart_t restart)
{
    int                                     ctr;
    globus_size_t                           off = 0;
    globus_size_t                           len = 256;

    globus_gridftp_server_control_begin_transfer(op, 255);

    for(ctr = 0; ctr < 500; ctr++)
    {
        globus_poll();
        usleep(50000);
        globus_gridftp_server_control_update_bytes(op, 0, off, len);
        off += len;
    }
    globus_gridftp_server_control_finished_transfer(op, GLOBUS_SUCCESS);
}

void
auth_func(
    globus_gridftp_server_control_op_t      op,
    int                                     type,
    const char *                            subject,
    const char *                            user_name,
    const char *                            pw)
{
    fprintf(stderr, "User: %s Pass: %s: type = %d\n", user_name, pw, type);

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
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    globus_xio_server_t                     xio_server;
    globus_result_t                         res;
    char *                                  cs;
    globus_gridftp_server_control_attr_t    ftp_attr;
    globus_gridftp_server_control_t         ftp_server;
    globus_xio_system_handle_t              system_handle;

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_module_activate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);

    /*
     *  set up the xio handle
     */
    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res, __LINE__);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(res, __LINE__);

    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res, __LINE__);

    res = globus_xio_server_create(&xio_server, NULL, stack);
    test_res(res, __LINE__);

    globus_xio_stack_destroy(stack);

    res = globus_xio_server_get_contact_string(xio_server, &cs);
    test_res(res, __LINE__);
    fprintf(stdout, "%s\n", cs);
    globus_free(cs);

    res = globus_xio_server_accept(&xio_handle, xio_server);
    test_res(res, __LINE__);

    fprintf(stdout, "xio connection esstablished.\n");
    /*
     *  server connection is all set up, hand it to server_lib
     */
    res = globus_gridftp_server_control_init(&ftp_server);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_init(&ftp_attr);
    test_res(res, __LINE__);

    globus_xio_server_close(xio_server);

    if(argc > 1)
    {
        globus_gridftp_server_control_attr_set_security(
            ftp_attr, GLOBUS_GRIDFTP_SERVER_LIBRARY_GSSAPI | 
                GLOBUS_GRIDFTP_SERVER_LIBRARY_NONE);
    }
    else
    {
        globus_gridftp_server_control_attr_set_security(
            ftp_attr, GLOBUS_GRIDFTP_SERVER_LIBRARY_NONE);
    }

    res = globus_gridftp_server_control_attr_set_auth(ftp_attr, auth_func);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_set_resource(
        ftp_attr, globus_l_resource_cb);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_set_list(
        ftp_attr, list_cb);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_set_idle_time(
        ftp_attr, 15);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_data_functions(
        ftp_attr, active_connect, passive_connect, data_destroy_cb);

    res = globus_gridftp_server_control_attr_add_send(
        ftp_attr, NULL, transfer);
    test_res(res, __LINE__);

    res = globus_gridftp_server_control_attr_add_recv(
        ftp_attr, NULL, transfer);
    test_res(res, __LINE__);

    res = globus_xio_handle_cntl(xio_handle, tcp_driver,
            GLOBUS_XIO_TCP_GET_HANDLE, &system_handle);
    test_res(res, __LINE__);

    globus_gsc_959_command_add(
        ftp_server,
        "SITE",
        globus_gs_cmd_site,
        GLOBUS_GSC_COMMAND_POST_AUTH,
        2,
        2,
        "214 Syntax: SITE <sp> pathname\r\n",
        NULL);

    globus_mutex_lock(&globus_l_mutex);
    {
        res = globus_gridftp_server_control_start(
            ftp_server, ftp_attr, system_handle, 
            globus_l_done_cb, FTP_USER_ARG);
        test_res(res, __LINE__);

        while(!globus_l_done)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    globus_xio_close(xio_handle, NULL);
    fprintf(stdout, "Ending...\n");
    res = globus_gridftp_server_control_attr_destroy(ftp_attr);
    test_res(res, __LINE__);
    res = globus_gridftp_server_control_destroy(ftp_server);
    test_res(res, __LINE__);

    globus_module_deactivate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);
    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}
