#include "globus_i_gwtftp.h"

/* 
 *  This file contains the main routine, the arugment parsing and 
 *  list code that listens for connections and accepts.  Once accepted
 *  it hands the new connection to connect.c for the FTP handlshake processing
 */

static globus_xio_stack_t               gwtftp_l_server_stack;
static globus_xio_stack_t               gwtftp_l_client_stack;
static globus_xio_driver_t              gwtftp_l_tcp_driver;
static globus_xio_driver_t              gwtftp_l_telnet_driver;
static globus_xio_driver_t              gwtftp_l_gssapi_driver;
static globus_xio_server_t              gwtftp_l_server;

static globus_mutex_t                   gwtftp_l_mutex;
static globus_cond_t                    gwtftp_l_cond;
static globus_bool_t                    gwtftp_l_done = GLOBUS_FALSE;
static globus_bool_t                    gwtftp_l_daemon = GLOBUS_FALSE;
static int                              gwtftp_l_log_level = 255;
static FILE *                           gwtftp_l_log_fptr;
static const char *                     gwtftp_l_pw_file = NULL;
static int                              gwtftp_l_listen_port = 0;

static globus_list_t *                  gwtftp_l_connection_list = NULL;

extern globus_options_entry_t           globus_i_gwtftp_opts_table[];

void
gwtftp_i_log(
    int                                 level,
    char *                              fmt,
    ...)
{
    va_list                             ap;

    if(level > gwtftp_l_log_level)
    {
        return;
    }

    va_start(ap, fmt);
    vfprintf(gwtftp_l_log_fptr, fmt, ap);
    va_end(ap);
}

static
void
gwtftp_l_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{

    globus_mutex_lock(&gwtftp_l_mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error_callback;
        }
        result = globus_xio_server_register_accept(
            gwtftp_l_server,
            gwtftp_l_accept_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_register;
        }

        /* valid connection list is tracked here. Even if we are shutting
            down we add all valid handles to the list.  They will be
            closed in the cleanup section */

        globus_list_insert(&gwtftp_l_connection_list, handle);
        if(gwtftp_l_done)
        {
            goto error_over;
        }

        /* only pass it on to the next level after we know we are not
            immediately about to kill it off */
        gwtftp_i_new_connection(handle);

    }
    globus_mutex_unlock(&gwtftp_l_mutex);

    return;

error_register:
error_callback:
    gwtftp_l_done = GLOBUS_TRUE;
    globus_cond_signal(&gwtftp_l_cond);
error_over:
    globus_mutex_unlock(&gwtftp_l_mutex);
}

static
globus_result_t
gwtftp_l_opts_unknown(
    globus_options_handle_t             opts_handle,
    void *                              unknown_arg,
    int                                 argc,
    char **                             argv)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "gwtftp_l_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        unknown_arg));
}


static
globus_result_t
gwtftp_l_setup_xio_stack()
{
    globus_result_t                     result;
    globus_xio_attr_t                   xio_attr;
    char *                              cs;

    globus_xio_stack_init(&gwtftp_l_server_stack, NULL);
    globus_xio_stack_init(&gwtftp_l_client_stack, NULL);

    result = globus_xio_driver_load("tcp", &gwtftp_l_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_tcp_load;
    }
    result = globus_xio_driver_load("telnet", &gwtftp_l_telnet_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_telnet_load;
    }
    result = globus_xio_driver_load("gssapi_ftp", &gwtftp_l_gssapi_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_gss_load;
    }

    result = globus_xio_stack_push_driver(
        gwtftp_l_client_stack, gwtftp_l_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_client_tcp_push;
    }
    result = globus_xio_stack_push_driver(
        gwtftp_l_client_stack, gwtftp_l_telnet_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_client_telnet_push;
    }
/*
    result = globus_xio_stack_push_driver(
        gwtftp_l_client_stack, gwtftp_l_gssapi_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_client_telnet_push;
    }
*/

    result = globus_xio_stack_push_driver(
        gwtftp_l_server_stack, gwtftp_l_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server_tcp_push;
    }
    result = globus_xio_stack_push_driver(
        gwtftp_l_server_stack, gwtftp_l_gssapi_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server_gss_push;
    }

    globus_xio_attr_init(&xio_attr);
    result = globus_xio_attr_cntl(xio_attr, gwtftp_l_telnet_driver,
            GLOBUS_XIO_TELNET_BUFFER, GLOBUS_TRUE);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server_create;
    }
/*
    result = globus_xio_attr_cntl(
            xio_attr, gwtftp_l_gssapi_driver,
            GLOBUS_XIO_GSSAPI_ATTR_TYPE_ALLOW_CLEAR, GLOBUS_TRUE);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server_create;
    }
*/

    if(gwtftp_l_listen_port != 0)
    {
        result = globus_xio_attr_cntl(
            xio_attr,
            gwtftp_l_tcp_driver,
            GLOBUS_XIO_TCP_SET_PORT,
            gwtftp_l_listen_port);
        if(result != GLOBUS_SUCCESS)
        {
            /* log message */
            gwtftp_i_log(FTP2GRID_LOG_MUST,
                "Requested listener port %d not set\n", gwtftp_l_listen_port);
        }
    }

    result = globus_xio_server_create(
        &gwtftp_l_server, xio_attr, gwtftp_l_client_stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server_create;
    }

    result = globus_xio_server_cntl(
        gwtftp_l_server,
        gwtftp_l_tcp_driver,
        GLOBUS_XIO_TCP_GET_LOCAL_CONTACT,
        &cs);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    
   gwtftp_i_log(
       FTP2GRID_LOG_WARN,
       "server listening on %s\n", cs);
    free(cs);
    globus_xio_attr_destroy(xio_attr);

    return GLOBUS_SUCCESS;
error_attr:
    /* close the server */
    globus_xio_server_close(gwtftp_l_server);
error_server_create:
    globus_xio_attr_destroy(xio_attr);
error_server_gss_push:
error_server_tcp_push:
error_client_telnet_push:
error_client_tcp_push:
    globus_xio_driver_unload(gwtftp_l_gssapi_driver);
error_gss_load:
    globus_xio_driver_unload(gwtftp_l_telnet_driver);
error_telnet_load:
    globus_xio_driver_unload(gwtftp_l_tcp_driver);
error_tcp_load:
    globus_xio_stack_destroy(gwtftp_l_server_stack);
    globus_xio_stack_destroy(gwtftp_l_client_stack);

    return result;
}

static
void
gwtftp_l_interrupt_cb(
    void *                              user_arg)
{
    /* attempt a nice shutdown */

    globus_mutex_lock(&gwtftp_l_mutex);
    {
        gwtftp_l_done = GLOBUS_TRUE;
        globus_cond_signal(&gwtftp_l_cond);
    }
    globus_mutex_unlock(&gwtftp_l_mutex);
}

void
gwtftp_i_close(
    globus_xio_handle_t                 handle)
{
    globus_list_t *                     list;

    globus_mutex_lock(&gwtftp_l_mutex);
    {
        list = globus_list_search(gwtftp_l_connection_list, handle);
        if(list == NULL)
        {
        }
        else
        {
            globus_list_remove(&gwtftp_l_connection_list, list);

            globus_xio_register_close(handle, NULL, NULL, NULL);
        }
    }
    globus_mutex_unlock(&gwtftp_l_mutex);
}

static
globus_result_t
gwtftp_i_options(
    int                                 argc,
    char **                             argv)
{
    globus_i_gwtftp_cmd_opts_t        cmd_opts;
    globus_options_handle_t             opt_h;
    globus_result_t                     result;

    gwtftp_l_log_fptr = stderr;

    memset(&cmd_opts, '\0', sizeof(globus_i_gwtftp_cmd_opts_t));
    cmd_opts.log_mask = FTP2GRID_LOG_WARN;
    globus_options_init(
        &opt_h, gwtftp_l_opts_unknown, &cmd_opts);
    globus_options_add_table(opt_h, globus_i_gwtftp_opts_table, &cmd_opts);
    result = globus_options_command_line_process(opt_h, argc, argv);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    gwtftp_l_log_level = cmd_opts.log_mask;
    if(cmd_opts.quiet)
    {
        gwtftp_l_log_level = 0;
    }
    if(cmd_opts.log_file != NULL)
    {
        gwtftp_l_log_fptr = fopen(cmd_opts.log_file, "w");

        if(gwtftp_l_log_fptr == NULL)
        {
            gwtftp_l_log_fptr = stderr;

            gwtftp_i_log(
                FTP2GRID_LOG_WARN,
                "logging file %s failed to open\n",
                cmd_opts.log_file);
        }
    }

    gwtftp_l_pw_file = cmd_opts.pw_file;
    if(gwtftp_l_pw_file == NULL)
    {
        /* WARN */
        gwtftp_i_log(FTP2GRID_LOG_MUST,
            "No password file specified.  *EVERYONE* can connect and use you credentials.\n  Please don't run it like this\n");
    }

    gwtftp_l_listen_port = cmd_opts.port;

    return GLOBUS_SUCCESS;
error:
    return result;
}

int
main(
    int                                 argc,
    char **                             argv)
{
    globus_result_t                     result;

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_module_activate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);

    globus_mutex_init(&gwtftp_l_mutex, NULL);
    globus_cond_init(&gwtftp_l_cond, NULL);

    result = gwtftp_i_options(argc, argv);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = gwtftp_l_setup_xio_stack();
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    gwtftp_i_server_init();


    globus_mutex_lock(&gwtftp_l_mutex);
    {
        result = globus_xio_server_register_accept(
            gwtftp_l_server,
            gwtftp_l_accept_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        /* register signal handler */
        globus_callback_register_signal_handler(
            GLOBUS_SIGNAL_INTERRUPT,
            GLOBUS_TRUE,
            gwtftp_l_interrupt_cb,
            NULL);
        while(!gwtftp_l_done)
        {
            globus_cond_wait(&gwtftp_l_cond, &gwtftp_l_mutex);
        }
        /* close the server socket */
        globus_xio_server_close(gwtftp_l_server);

        /* walk through all created handles and close them all */
        while(!globus_list_empty(gwtftp_l_connection_list))
        {
            globus_xio_handle_t         close_handle;

            close_handle = (globus_xio_handle_t) globus_list_remove(
                &gwtftp_l_connection_list, gwtftp_l_connection_list);

            globus_xio_close(close_handle, NULL);
        }
    }    
    globus_mutex_unlock(&gwtftp_l_mutex);

    globus_module_deactivate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 0;

error:
    globus_module_deactivate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 1;
}


/* 
 *  this function is called to form the connection from this prgram 
 *  to the end server.  it is implemented here but called else where so
 *  that this file can fully manage the handle list
 */
globus_result_t
gwtftp_i_server_connect(
    const char *                        cs,
    const char *                        subject,
    globus_xio_callback_t               open_cb, 
    void *                              user_arg)
{
    globus_xio_handle_t                 xio_handle;
    globus_result_t                     result;

    globus_mutex_lock(&gwtftp_l_mutex);
    {
        result = globus_xio_handle_create(
            &xio_handle, gwtftp_l_server_stack);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        result = globus_xio_register_open(
            xio_handle,
            cs,
            NULL,
            open_cb,
            user_arg);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_open;
        }
        globus_list_insert(&gwtftp_l_connection_list, xio_handle);
    }
    globus_mutex_unlock(&gwtftp_l_mutex);

    return GLOBUS_SUCCESS;
error_open:
error:
    return result;
}


globus_result_t
gwtftp_i_ip_ok(
    globus_xio_handle_t                 handle)
{
    globus_result_t                     result;
    char *                              remote_contact;

    result = globus_xio_handle_cntl(
        handle,
        gwtftp_l_tcp_driver,
        GLOBUS_XIO_TCP_GET_REMOTE_NUMERIC_CONTACT,
        &remote_contact);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    /* by default we just check localhost */
    if(strcmp(remote_contact, "127.0.0.1") == 0)
    {
        return GLOBUS_SUCCESS;
    }

    /* fall through on error */
error:
    return result;
}

static
void
gwtftp_i_exec__unix(
    uid_t                               uid,
    globus_xio_handle_t                 client_xio,
    globus_url_t *                      url)
{
    globus_xio_system_socket_t          socket_handle;
    pid_t                               pid;
    int                                 rc;
    globus_result_t                     result;

    pid = fork();
    if(pid == 0)
    {
        /* do i set the uid or do i let a sudo thing do it */
        rc = setuid(uid);
        if(rc != 0)
        {
        }
        /* extract the FD */
        result = globus_xio_handle_cntl(
            client_xio,
            gwtftp_l_tcp_driver,
            GLOBUS_XIO_TCP_GET_HANDLE,
            &socket_handle);
        if(result != GLOBUS_SUCCESS)
        {
        }
        rc = dup2(socket_handle, STDIN_FILENO);
        if(rc < 0)
        {
        }
        /* all xio sockets will close on exec */

    }
    else if(pid < 0)
    {
        gwtftp_i_log(FTP2GRID_LOG_INFO, "Failed to fork\n");
    }
}

uid_t
gwtftp_i_pass_ok__unix(
    const char *                        username,
    const char *                        pw)
{
    char *                              pw_hash;
    struct passwd *                     pw_ent;
    FILE *                              pw_fptr;
    uid_t                               uid = -1;
    globus_bool_t                       done = GLOBUS_FALSE;

    if(gwtftp_l_pw_file == NULL)
    {
        return getpid();
    }
    pw_fptr = fopen(gwtftp_l_pw_file, "r");
    if(pw_fptr == NULL)
    {
        return -1;
    }

    while(!done)
    {
        pw_ent = fgetpwent(pw_fptr);
        if(pw_ent == NULL)
        {
            done = GLOBUS_TRUE;
        }
        else
        {
            if(strcmp(pw_ent->pw_name, username) == 0)
            {
                pw_hash = DES_crypt(pw, pw_ent->pw_passwd);
                if(strcmp(pw_hash, pw_ent->pw_passwd) == 0)
                {
                    uid = pw_ent->pw_uid;
                }
                done = GLOBUS_TRUE;
            }
        }
    }
    fclose(pw_fptr);

    return uid;
}

void
gwtftp_i_authorized_user(
    globus_xio_handle_t                 client_xio,
    const char *                        full_username,
    const char *                        pass)
{
    int                                 rc;
    uid_t                               uid;
    globus_list_t *                     list;
    globus_xio_handle_t                 server_xio;
    globus_result_t                     result;
    globus_url_t                        g_url;

    gwtftp_i_log(FTP2GRID_LOG_INFO,
        "Authorizing: %s\n", full_username);
    globus_mutex_lock(&gwtftp_l_mutex);
    {
        list = globus_list_search(gwtftp_l_connection_list, client_xio);
        globus_assert(list != NULL);

        rc = globus_url_parse(full_username, &g_url);
        if(rc != 0)
        {
            goto error;
        }
        if(g_url.scheme_type != GLOBUS_URL_SCHEME_GSIFTP)
        {
            goto error_scheme;
        }

        uid = gwtftp_i_pass_ok__unix(g_url.user, pass);
        if(uid < 0)
        {
            /* if it is bad. 
                XXX: we can send a nice little message, but just close for now
             */
            goto error;
        }
        else
        {
            if(gwtftp_l_daemon)
            {
                gwtftp_i_exec__unix(uid, client_xio, &g_url);
                globus_list_remove(&gwtftp_l_connection_list, list);
                globus_xio_register_close(client_xio, NULL, NULL, NULL);
            }
            else
            {
                char *                  cs;

                result = globus_xio_handle_create(
                    &server_xio, gwtftp_l_server_stack);
                if(result != GLOBUS_SUCCESS)
                {
                    goto error_scheme;
                }

                cs = globus_common_create_string(
                    "%s:%d", g_url.host, g_url.port);

                result = gwtftp_i_server_conn_open(
                    server_xio, cs, client_xio);
                globus_free(cs);
                if(result != GLOBUS_SUCCESS)
                {
                    goto error_open;
                }
                globus_list_insert(&gwtftp_l_connection_list, server_xio);
            }
        }
    }
    globus_mutex_unlock(&gwtftp_l_mutex);
    globus_url_destroy(&g_url);

    return;

error_open:
    globus_xio_register_close(server_xio, NULL, NULL, NULL);
error_scheme:
    globus_url_destroy(&g_url);
error:
    globus_list_remove(&gwtftp_l_connection_list, list);
    globus_xio_register_close(client_xio, NULL, NULL, NULL);

    globus_mutex_unlock(&gwtftp_l_mutex);
    return;
}
