#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "globus_i_gridftp_server.h"
#include "globus_gsi_authz.h"
#include "version.h"

#include <sys/wait.h>

static globus_cond_t                    globus_l_gfs_cond;
static globus_mutex_t                   globus_l_gfs_mutex;
static globus_bool_t                    globus_l_gfs_terminated = GLOBUS_FALSE;
static unsigned int                     globus_l_gfs_open_count = 0;
static unsigned int                     globus_l_gfs_max_open_count = 0;
static globus_xio_driver_t              globus_l_gfs_tcp_driver = GLOBUS_NULL;
static globus_xio_server_t              globus_l_gfs_xio_server = GLOBUS_NULL;
static globus_bool_t                    globus_l_gfs_xio_server_accepting;
static globus_xio_attr_t                globus_l_gfs_xio_attr;
static globus_bool_t                    globus_l_gfs_exit = GLOBUS_FALSE;
static globus_bool_t                    globus_l_gfs_sigint_caught = GLOBUS_FALSE;

static
globus_result_t
globus_l_gfs_open_new_server(
    globus_xio_handle_t                 handle);

static
void
globus_l_gfs_server_closed(
    void *                              user_arg);

static
void
globus_l_gfs_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg);
    
static
void
globus_l_gfs_server_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg);

static
void
globus_l_gfs_bad_signal_handler(
    int                                 signum)
{
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_ERR, 
        _GSSL("an unexpected signal occured: %d\n"), 
        signum);
    if(!globus_l_gfs_exit)
    {
        signal(signum, SIG_DFL);
        raise(signum);
    }
    else
    {
        exit(signum);
    }
}


static
void 
globus_l_gfs_sigint(
    void *                              user_arg)
{
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_ERR, 
        "Server is shutting down...\n");

    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        if(globus_l_gfs_sigint_caught)
        {
            globus_l_gfs_open_count = 0;
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_ERR, 
                "Forcing unclean shutdown.\n");
        }

        globus_l_gfs_sigint_caught = GLOBUS_TRUE;
        globus_l_gfs_terminated = GLOBUS_TRUE;

        if(globus_l_gfs_open_count == 0)
        {
            globus_cond_signal(&globus_l_gfs_cond);
        }
        else
        {
            globus_i_gfs_control_stop();
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
}

static
void 
globus_l_gfs_sighup(
    void *                              user_arg)
{
    int                                 argc;
    char **                             argv;

    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO, 
        "Reloading config...\n");         

    argv = (char **) globus_i_gfs_config_get("argv");
    argc = globus_i_gfs_config_int("argc");

    globus_i_gfs_config_init(argc, argv);
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO, 
        "Done reloading config.\n");           
}

static
void 
globus_l_gfs_sigchld(
    void *                              user_arg)
{
    int                                 child_pid;
    int                                 child_status;
    int                                 child_rc;

    while((child_pid = waitpid(-1, &child_status, WNOHANG)) > 0)
    {
        if(WIFEXITED(child_status))
        {
            child_rc = WEXITSTATUS(child_status);
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_INFO, 
                "Child process %d ended with rc = %d\n", 
                child_pid, 
                child_rc);
        }
        else if(WIFSIGNALED(child_status))
        {
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_INFO, 
                "Child process %d killed by signal %d\n",
                child_pid, 
                WTERMSIG(child_rc));
        }
    
        globus_mutex_lock(&globus_l_gfs_mutex);
        {
            globus_l_gfs_open_count--;
            if(globus_l_gfs_open_count == 0)
            {
                globus_cond_signal(&globus_l_gfs_cond);
            }
        }
        globus_mutex_unlock(&globus_l_gfs_mutex);   
    }
}

static
void
globus_l_gfs_signal_init()
{
    
#   ifdef SIGINT
    globus_callback_register_signal_handler(
        SIGINT,
        GLOBUS_TRUE,
        globus_l_gfs_sigint,
        NULL);
#   endif

#   ifdef SIGHUP
    globus_callback_register_signal_handler(
        SIGHUP,
        GLOBUS_TRUE,
        globus_l_gfs_sighup,
        NULL);
#   endif

#   ifdef SIGKILL
    {
    /* XXX    //signal(SIGKILL, globus_l_gfs_bad_signal_handler); */
    }
#   endif
#   ifdef SIGSEGV
    {
        signal(SIGSEGV, globus_l_gfs_bad_signal_handler);
    }
#   endif
#   ifdef SIGABRT
    {
        signal(SIGABRT, globus_l_gfs_bad_signal_handler);
    }
#   endif
#   ifdef SIGBUS
    {
        signal(SIGBUS, globus_l_gfs_bad_signal_handler);
    }
#   endif
#   ifdef SIGFPE
    {
        signal(SIGFPE, globus_l_gfs_bad_signal_handler);
    }
#   endif
#   ifdef SIGILL
    {
        signal(SIGILL, globus_l_gfs_bad_signal_handler);
    }
#   endif
#   ifdef SIGIOT
    {
        signal(SIGIOT, globus_l_gfs_bad_signal_handler);
    }
#   endif
#   ifdef SIGPIPE
    {
 /* XXX       //signal(SIGPIPE, globus_l_gfs_bad_signal_handler); */
    }
#   endif
#   ifdef SIGEMT
    {
        signal(SIGEMT, globus_l_gfs_bad_signal_handler);
    }

#   endif
#   ifdef SIGSYS
    {
        signal(SIGSYS, globus_l_gfs_bad_signal_handler);
    }

#   endif
#   ifdef SIGTRAP
    {
        signal(SIGTRAP, globus_l_gfs_bad_signal_handler);
    }

#   endif
#   ifdef SIGSTOP
    {
 /* XXX       //signal(SIGSTOP, globus_l_gfs_bad_signal_handler); */
    }

#   endif
}

/* called locked */
static
globus_result_t
globus_l_gfs_spawn_child(
    globus_xio_handle_t                 handle)
{
    char **                             new_argv;
    char **                             prog_argv;
    globus_result_t                     result;
    pid_t                               child_pid;
    globus_xio_system_handle_t          socket_handle;
    int                                 i;
    int                                 j;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_spawn_child);

    result = globus_xio_handle_cntl(
        handle,
        globus_l_gfs_tcp_driver,
        GLOBUS_XIO_TCP_GET_HANDLE,
        &socket_handle);
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result(
            _GSSL("Could not get handle from daemon process"), result);
        goto error;
    }

    child_pid = fork();
    if(child_pid == 0)
    { 
        if(globus_l_gfs_xio_server)
        {
            globus_xio_server_close(globus_l_gfs_xio_server);
            globus_l_gfs_xio_server = GLOBUS_NULL;
        }

        rc = dup2(socket_handle, STDIN_FILENO);
        if(rc == -1)
        {
            result = GlobusGFSErrorSystemError("dup2", errno);
            globus_i_gfs_log_result(
                _GSSL("Could not open new handle for child process"), result);
            goto child_error;
        }
        close(socket_handle);

        /* exec the process */
        prog_argv = (char **) globus_i_gfs_config_get("argv");
        for(i = 0; prog_argv[i] != NULL; i++)
        {
        }
        new_argv = (char **) globus_calloc(1, sizeof(char *) * (i + 2));
        if(new_argv == NULL)
        {
            goto child_close_error;
        }
        if((new_argv[0] = globus_i_gfs_config_string("exec")) == NULL)
        {
            new_argv[0] = globus_i_gfs_config_string("exec_name");
        }
        for(i = 1, j = 1; prog_argv[i] != NULL; i++)
        {
            if(strcmp(prog_argv[i], "-S") != 0 &&
                strcmp(prog_argv[i], "-s") != 0)
            {
                if(strcmp(prog_argv[i], "-p") == 0)
                {
                    i++;
                }
                else
                {   
                    new_argv[j++] = prog_argv[i];
                }
            }
        }
        new_argv[j++] = "-i";
        new_argv[j] = NULL;

        rc = execv(new_argv[0], new_argv);
        if(rc == -1)
        {
            result = GlobusGFSErrorSystemError("execv", errno);
            globus_i_gfs_log_result(
                _GSSL("Could not exec child process"), result);
            goto child_error;
        }
    } 
    else if(child_pid == -1)
    {
    }
    else
    { 
        /* inc the connection count 2 here since we will dec it on this close
        and on the death of the child process */
        globus_l_gfs_open_count += 2;
        globus_mutex_unlock(&globus_l_gfs_mutex);
        result = globus_xio_register_close(
            handle,
            NULL,
            globus_l_gfs_close_cb,
            NULL);    
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gfs_close_cb(handle, result, NULL);
        }        
    }    

    return GLOBUS_SUCCESS;

child_close_error:
    close(STDIN_FILENO);
    close(socket_handle);
child_error:
    exit(1);
error:
    return result;
}

static
void
globus_i_gfs_connection_closed()
{
    globus_result_t                     result;

    globus_l_gfs_open_count--;
    if(globus_l_gfs_terminated || globus_i_gfs_config_bool("inetd"))
    {
        if(globus_l_gfs_open_count == 0)
        {
            globus_l_gfs_terminated = GLOBUS_TRUE;
            globus_cond_signal(&globus_l_gfs_cond);
        }
    }
    /* if we are a server */
    else if(globus_l_gfs_xio_server)
    {
        /* if not waiting on an accept, and are below the max
            register another accept.
            this happens when we hit the max connection count, the
            death of this connection leaves room for the next */
        if(!globus_l_gfs_xio_server_accepting &&
            globus_l_gfs_open_count < globus_l_gfs_max_open_count)
        {
            result = globus_xio_server_register_accept(
                globus_l_gfs_xio_server,
                globus_l_gfs_server_accept_cb,
                NULL);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_accept;
            }
            globus_l_gfs_xio_server_accepting = GLOBUS_TRUE;
        }
    }
 
    return;

/* if an accept fails, set terminated to true because we can no longer 
    take connects so once all hte current ones end we should let the
    process die */
error_accept:
    globus_l_gfs_terminated = GLOBUS_TRUE;
    if(globus_l_gfs_open_count == 0)
    {
        globus_cond_signal(&globus_l_gfs_cond);
    }
    globus_i_gfs_log_result("Unable to accept connections", result);
}

static
void
globus_l_gfs_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        globus_i_gfs_connection_closed();
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
}

static
void
globus_l_gfs_new_server_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_system_handle_t          system_handle;
    char *                              remote_contact;
    char *                              local_contact;
    
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        if(result != GLOBUS_SUCCESS || globus_l_gfs_terminated)
        {
            goto error;
        }
    
        result = globus_xio_handle_cntl(
            handle,
            globus_l_gfs_tcp_driver,
            GLOBUS_XIO_TCP_GET_REMOTE_NUMERIC_CONTACT,
            &remote_contact);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        if(!globus_i_gfs_config_allow_addr(remote_contact))
        {
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_WARN,
                "Connection disallowed by configuration from: %s\n", 
                remote_contact);
            goto error;
        }
        globus_free(remote_contact);       
        result = globus_xio_handle_cntl(
            handle,
            globus_l_gfs_tcp_driver,
            GLOBUS_XIO_TCP_GET_REMOTE_CONTACT,
            &remote_contact);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
        
        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_INFO,
            "New connection from: %s\n", remote_contact);

        result = globus_xio_handle_cntl(
            handle,
            globus_l_gfs_tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT,
            &local_contact);
        if(result != GLOBUS_SUCCESS)
        {
            goto error2;
        }

        result = globus_xio_handle_cntl(
            handle,
            globus_l_gfs_tcp_driver,
            GLOBUS_XIO_TCP_GET_HANDLE,
            &system_handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_start;
        }

        if(globus_i_gfs_config_bool("data_node"))
        {
            result = globus_i_gfs_data_node_start(
                handle, 
                system_handle, 
                remote_contact, 
                local_contact, 
                globus_l_gfs_server_closed, 
                NULL);
        }
        else
        {        
            result = globus_i_gfs_control_start(
                handle, 
                system_handle, 
                remote_contact,
                local_contact, 
                globus_l_gfs_server_closed,
                NULL);
        }
        if(result != GLOBUS_SUCCESS)
        {
            globus_i_gfs_log_result("Connection failed", result);
            goto error_start;
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    globus_free(local_contact);
    globus_free(remote_contact);
    return;

error_start:
    globus_free(remote_contact);   
error2:
    globus_free(local_contact);
error:
    result = globus_xio_register_close(
        handle,
        NULL,
        globus_l_gfs_close_cb,
        NULL);
    globus_mutex_unlock(&globus_l_gfs_mutex);

    if(result != GLOBUS_SUCCESS)
    {
        globus_l_gfs_close_cb(handle, result, NULL);
    }
}

/* begin new server, this is called locked and it is assumed that
   the application is not in the termintated state */
static
globus_result_t
globus_l_gfs_open_new_server(
    globus_xio_handle_t                 handle)
{
    globus_result_t                     result;
    
    /* dont need the handle here, will get it in callback too */
    result = globus_xio_register_open(
        handle,
        NULL,
        globus_l_gfs_xio_attr,
        globus_l_gfs_new_server_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_open;
    }
    globus_l_gfs_open_count++;
    
    return GLOBUS_SUCCESS;

error_open:
    
    return result;
}

static
globus_result_t
globus_l_gfs_prepare_stack(
    globus_xio_stack_t *                stack)
{
    globus_result_t                     result;
    
    result = globus_xio_stack_init(stack, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }

    result = globus_xio_stack_push_driver(*stack, globus_l_gfs_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }

    return GLOBUS_SUCCESS;
}

/* begin a server instance from the channel already connected on stdin,
    this IS called locked, it is assume that the server has not been
    terminated */
static
globus_result_t
globus_l_gfs_convert_inetd_handle(void)
{
    globus_result_t                     result;
    globus_xio_stack_t                  stack;
    globus_xio_handle_t                 handle;
    
    result = globus_l_gfs_prepare_stack(&stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    result = globus_xio_attr_cntl(
        globus_l_gfs_xio_attr,
        globus_l_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_HANDLE,
        STDIN_FILENO);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_stack;
    }

    result = globus_xio_handle_create(&handle, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_stack;
    }
    
    result = globus_l_gfs_open_new_server(handle);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_stack;
    }
    
    return GLOBUS_SUCCESS;

error_stack:
    globus_xio_stack_destroy(stack);
error:
    return result;
}




/* a new client has connected */
static
void
globus_l_gfs_server_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        globus_l_gfs_xio_server_accepting = GLOBUS_FALSE;
        if(result != GLOBUS_SUCCESS)
        {
            goto error_accept;
        }

        /* if we fail to actually open a connection with either method we
            do not fail, just lof that the connection failed */
        if(globus_i_gfs_config_bool("daemon"))
        {
            result = globus_l_gfs_spawn_child(handle);
            if(result != GLOBUS_SUCCESS)
            {
                globus_i_gfs_log_result("Could not spawn a child", result);
                result = GLOBUS_SUCCESS;
            }
        }
        else
        {
            result = globus_l_gfs_open_new_server(handle);
            if(result != GLOBUS_SUCCESS)
            {
                globus_i_gfs_log_result(_GSSL("Could not open new handle"),
			       	result);
                result = GLOBUS_SUCCESS;
            }
        }
        /* be sure to close handle on server proc and close server on 
         * client proc (close on exec)
         *
         * need to handle proc exits and decrement the open server count
         * to keep the limit in effect.
         * 
         * win32 will have to simulate fork/exec... should i just do that
         * for unix too?
         */
        if(!globus_l_gfs_terminated &&
            (globus_l_gfs_max_open_count == 0 || 
                globus_l_gfs_open_count < globus_l_gfs_max_open_count) &&
            !globus_i_gfs_config_bool("connections_disabled"))
        {
            result = globus_xio_server_register_accept(
                server,
                globus_l_gfs_server_accept_cb,
                GLOBUS_NULL);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_register_accept;
            }
            globus_l_gfs_xio_server_accepting = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
    
    return;

error_register_accept:
    
error_accept:
    globus_l_gfs_terminated = GLOBUS_TRUE;
    if(globus_l_gfs_open_count == 0)
    {
        globus_cond_signal(&globus_l_gfs_cond);
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
}

/* start up a daemon which will spawn server instances */
static
globus_result_t
globus_l_gfs_be_daemon(void)
{
    char *                              contact_string;
    char *                              interface;
    globus_result_t                     result;
    globus_xio_stack_t                  stack;
    globus_xio_attr_t                   attr;

    result = globus_callback_register_signal_handler(
        SIGCHLD,
        GLOBUS_TRUE,
        globus_l_gfs_sigchld,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_l_gfs_prepare_stack(&stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_xio_attr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        goto stack_error;
    }
    if((interface = globus_i_gfs_config_string("control_interface")) != NULL)
    {
        result = globus_xio_attr_cntl(
            attr,
            globus_l_gfs_tcp_driver,
            GLOBUS_XIO_TCP_SET_INTERFACE,
            interface);
        if(result != GLOBUS_SUCCESS)
        {
            goto attr_error;
        }
    }
    result = globus_xio_attr_cntl(
        attr,
        globus_l_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_PORT,
        globus_i_gfs_config_int("port"));
    if(result != GLOBUS_SUCCESS)
    {
        goto attr_error;
    }
    
    result = globus_xio_attr_cntl(
        attr,
        globus_l_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_REUSEADDR,
        GLOBUS_TRUE);
    if(result != GLOBUS_SUCCESS)
    {
        goto attr_error;
    }
    
    result = globus_xio_server_create(&globus_l_gfs_xio_server, attr, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto attr_error;
    }

    if(globus_i_gfs_config_bool("chdir"))
    {
        char *                          chdir_to;
        chdir_to = globus_i_gfs_config_string("chdir_to");
        if(chdir_to != NULL)
        {
            chdir(chdir_to);
        }
        else
        {
            chdir("/");
        }
    }

    if(globus_i_gfs_config_int("port") == 0 ||
        globus_i_gfs_config_bool("contact_string"))
    {
        result = globus_xio_server_get_contact_string(
            globus_l_gfs_xio_server,
            &contact_string);
        if(result != GLOBUS_SUCCESS)
        {
            goto server_error;
        }
        globus_libc_printf(_GSSL("Server listening at %s\n"), contact_string);
        fflush(stdout);
        globus_free(contact_string);
    }
    
    result = globus_xio_server_register_accept(
        globus_l_gfs_xio_server,
        globus_l_gfs_server_accept_cb,
        GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto contact_error;
    }
    globus_l_gfs_xio_server_accepting = GLOBUS_TRUE;
    globus_xio_stack_destroy(stack);
    globus_xio_attr_destroy(attr);

    return GLOBUS_SUCCESS;

contact_error:
    globus_free(contact_string);
server_error:
    globus_xio_server_close(globus_l_gfs_xio_server);
attr_error:
    globus_xio_attr_destroy(attr);
stack_error:
    globus_xio_stack_destroy(stack);
error:

    return result;
}

static
void
globus_l_gfs_be_clean_up()
{
    if(globus_l_gfs_xio_server)
    {
        globus_xio_server_close(globus_l_gfs_xio_server);
    }

    globus_xio_attr_destroy(globus_l_gfs_xio_attr);
    globus_xio_driver_unload(globus_l_gfs_tcp_driver);
    globus_i_gfs_log_close();

    globus_module_deactivate_all();
}

int
main(
    int                                 argc,
    char **                             argv)
{
    pid_t                               pid;
    int                                 rc = 0;
    char *                              config;
    globus_result_t                     result;

    /* activte globus stuff */    
    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);
    globus_module_activate(GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE);
    globus_module_activate(GLOBUS_GSI_AUTHZ_MODULE);


    /* activate all the server modules */
    globus_i_gfs_config_init(argc, argv);
    globus_i_gfs_log_open();
    globus_l_gfs_signal_init();
    globus_i_gfs_data_init();
    globus_gfs_ipc_init(!globus_i_gfs_config_bool("data_node"), NULL);
    globus_i_gfs_control_init();

    /* initialize global variables */
    globus_mutex_init(&globus_l_gfs_mutex, GLOBUS_NULL);
    globus_cond_init(&globus_l_gfs_cond, GLOBUS_NULL);
    
    globus_l_gfs_open_count = 0;
    globus_l_gfs_max_open_count = globus_i_gfs_config_int("connections_max");
    globus_l_gfs_exit = globus_i_gfs_config_int("bad_signal_exit");
    globus_l_gfs_xio_server = NULL;

    /* if all the want is version info print and exit */
    if(globus_i_gfs_config_bool("help"))
    {
        globus_i_gfs_config_display_usage();
        rc = 0;
        goto error_ver;
    }
    else if(globus_i_gfs_config_bool("version"))
    {
        globus_version_print(
            local_package_name,
            &local_version,
            stderr,
            GLOBUS_TRUE);
        rc = 0;
        goto error_ver;
    }
    else if(globus_i_gfs_config_bool("versions"))
    {
        globus_version_print(
            local_package_name,
            &local_version,
            stderr,
            GLOBUS_TRUE);

        globus_module_print_activated_versions(
            stderr,
            GLOBUS_TRUE);
        rc = 0;
        goto error_ver;
    }

    if(globus_i_gfs_config_bool("detach"))
    {
        /* this is where i detach the server into the background
         * not sure how this will work for win32.  if it involves starting a
         * new process, need to set server handle to not close on exec
         */
        pid = fork();
        if(pid < 0)
        {
        }
        else if(pid != 0)
        {
            exit(0);
        }
        else
        {
            setsid();
            freopen("/dev/null", "w+", stdin);
            freopen("/dev/null", "w+", stdout);
            freopen("/dev/null", "w+", stderr);
            if(globus_i_gfs_config_bool("chdir"))
            {
                char *                  chdir_to;
                chdir_to = globus_i_gfs_config_string("chdir_to");
                if(chdir_to != NULL)
                {
                    chdir(chdir_to);
                }
                else
                {
                    chdir("/");
                }
            }
        }
    }
    if(globus_i_gfs_config_bool("cas"))
    {
        globus_gfs_acl_add_module(&globus_gfs_acl_cas_module);
    }
    if(globus_i_gfs_config_string("test_acl"))
    {
        globus_gfs_acl_add_module(&globus_gfs_acl_test_module);
    }
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        result = globus_xio_driver_load("tcp", &globus_l_gfs_tcp_driver);
        if(result != GLOBUS_SUCCESS)
        {
            rc = 1;
            goto error_lock;
        }

        result = globus_xio_attr_init(&globus_l_gfs_xio_attr);
        if(result != GLOBUS_SUCCESS)
        {
            rc = 1;
            goto error_lock;
        }

        /* in theory we could have gotten a terminated already */
        if(globus_l_gfs_terminated)
        {
            rc = 0;
            goto error_lock;
        }
        config = globus_i_gfs_config_string("loaded_config");
        if(globus_i_gfs_config_bool("inetd"))
        {
            freopen("/dev/null", "w+", stdout);
            freopen("/dev/null", "w+", stderr);
            if(config)
            {
                globus_i_gfs_log_message(
                    GLOBUS_I_GFS_LOG_INFO, 
                    "Configuration read from %s\n", config);
            }
            result = globus_l_gfs_convert_inetd_handle();
        }
        else
        {
            if(config)
            {
                globus_i_gfs_log_message(
                    GLOBUS_I_GFS_LOG_INFO,
                    "Configuration read from %s\n", config);
            }            
            result = globus_l_gfs_be_daemon();
        }
        if(result != GLOBUS_SUCCESS)
        {
            rc = 1;
            goto error_lock;
        }

        /* run until we are done */ 
        while((!globus_l_gfs_terminated || globus_l_gfs_open_count > 0))
        {
            globus_cond_wait(&globus_l_gfs_cond, &globus_l_gfs_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    globus_l_gfs_be_clean_up();

    return 0;
error_lock:
    globus_i_gfs_log_result(_GSSL("Could not start server"), result);
    globus_mutex_unlock(&globus_l_gfs_mutex);
error_ver:
    globus_l_gfs_be_clean_up();

    return rc;
}

static
void
globus_l_gfs_server_closed(
    void *                              user_arg)
{
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        globus_i_gfs_connection_closed();
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
}
