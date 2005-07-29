/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "globus_i_gridftp_server.h"
#include "version.h"
#include "globus_i_gfs_ipc.h"

#include <sys/wait.h>
#include <signal.h>

static globus_cond_t                    globus_l_gfs_cond;
static globus_mutex_t                   globus_l_gfs_mutex;
static globus_bool_t                    globus_l_gfs_terminated = GLOBUS_FALSE;
static unsigned int                     globus_l_gfs_outstanding = 0;
static unsigned int                     globus_l_gfs_open_count = 0;
static unsigned int                     globus_l_gfs_max_open_count = 0;
static globus_xio_driver_t              globus_l_gfs_tcp_driver = GLOBUS_NULL;
static globus_xio_server_t              globus_l_gfs_xio_server = GLOBUS_NULL;
static globus_bool_t                    globus_l_gfs_xio_server_accepting;
static globus_xio_attr_t                globus_l_gfs_xio_attr;
static globus_bool_t                    globus_l_gfs_exit = GLOBUS_FALSE;
static globus_bool_t                    globus_l_gfs_sigint_caught = GLOBUS_FALSE;

static char **                          globus_l_gfs_child_argv = NULL;
static int                              globus_l_gfs_child_argc = 0;

#ifndef BUILD_LITE
#define GLOBUS_L_GFS_SIGCHLD_DELAY 10
static globus_callback_handle_t         globus_l_gfs_sigchld_periodic_handle = 
                                            GLOBUS_NULL_HANDLE;
#endif

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
globus_i_gfs_connection_closed();

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
globus_l_gfs_sigchld(
    void *                              user_arg);

static
void
globus_l_gfs_bad_signal_handler(
    int                                 signum)
{
    GlobusGFSName(globus_l_gfs_bad_signal_handler);
    GlobusGFSDebugEnter();

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
    
    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_server_close_cb(
    globus_xio_server_t                 server,
    void *                              user_arg)
{
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        globus_l_gfs_outstanding--;
        globus_l_gfs_xio_server = GLOBUS_NULL;
        globus_cond_signal(&globus_l_gfs_cond);
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
}



static
void 
globus_l_gfs_sigint(
    void *                              user_arg)
{
    globus_result_t                     res;
    GlobusGFSName(globus_l_gfs_sigint);
    GlobusGFSDebugEnter();

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
        if(globus_l_gfs_xio_server)
        {
            res = globus_xio_server_register_close(
                globus_l_gfs_xio_server, globus_l_gfs_server_close_cb, NULL);
            if(res == GLOBUS_SUCCESS)
            {
                globus_l_gfs_outstanding++;
            }
            else
            {
                globus_l_gfs_xio_server = GLOBUS_NULL;
            }
        }

        globus_l_gfs_sigint_caught = GLOBUS_TRUE;
        globus_l_gfs_terminated = GLOBUS_TRUE;

        if(globus_l_gfs_open_count == 0)
        {
            globus_cond_signal(&globus_l_gfs_cond);
        }
        else
        {
            if(globus_i_gfs_config_bool("data_node"))
            {
                globus_i_gfs_ipc_stop();
            }
            else
            {
                globus_i_gfs_control_stop();
            }
            if(globus_i_gfs_config_bool("daemon"))
            {
                globus_l_gfs_sigchld(user_arg);
            }
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    GlobusGFSDebugExit();
}

static
void 
globus_l_gfs_sighup(
    void *                              user_arg)
{
    int                                 argc;
    char **                             argv;
    GlobusGFSName(globus_l_gfs_sighup);
    GlobusGFSDebugEnter();

    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO, 
        "Reloading config...\n");         

    argv = (char **) globus_i_gfs_config_get("argv");
    argc = globus_i_gfs_config_int("argc");

    globus_i_gfs_config_init(argc, argv);
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO, 
        "Done reloading config.\n");           

    GlobusGFSDebugExit();
}

static
void 
globus_l_gfs_sigchld(
    void *                              user_arg)
{
    int                                 child_pid;
    int                                 child_status;
    int                                 child_rc;
    GlobusGFSName(globus_l_gfs_sigchld);
    GlobusGFSDebugEnter();

    while(globus_l_gfs_open_count > 0 &&
        (child_pid = waitpid(-1, &child_status, WNOHANG)) > 0)
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
            globus_i_gfs_connection_closed();
        }
        globus_mutex_unlock(&globus_l_gfs_mutex);   
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_signal_init()
{
    GlobusGFSName(globus_l_gfs_signal_init);
    GlobusGFSDebugEnter();
    
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

    GlobusGFSDebugExit();
}

/* called locked */
static
globus_result_t
globus_l_gfs_spawn_child(
    globus_xio_handle_t                 handle)
{
    globus_result_t                     result;
    pid_t                               child_pid;
    globus_xio_system_native_handle_t   socket_handle;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_spawn_child);

    GlobusGFSDebugEnter();

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
            result = globus_xio_server_register_close(
                globus_l_gfs_xio_server, globus_l_gfs_server_close_cb, NULL);
            if(result == GLOBUS_SUCCESS)
            {
                globus_l_gfs_outstanding++;
            }
            else
            {
                globus_l_gfs_xio_server = GLOBUS_NULL;
            }
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
        if(*globus_l_gfs_child_argv[0] == '/')
        {
            rc = execv(globus_l_gfs_child_argv[0], globus_l_gfs_child_argv);
        }
        else
        {
            rc = execvp(globus_l_gfs_child_argv[0], globus_l_gfs_child_argv);
        }
        if(rc == -1)
        {
            char *                      error_msg;

            error_msg = globus_common_create_string("%s\n%s\n%s\n%s",
                _GSSL("Could not exec child process."),
                _GSSL("Please verify that a gridftp server is located at: "),
                globus_l_gfs_child_argv[0],
                _GSSL("Or try the -exec flag."));
            result = GlobusGFSErrorSystemError("execv", errno);
            globus_i_gfs_log_result(error_msg, result);

            goto child_close_error;
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

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

child_close_error:
    close(STDIN_FILENO);
    close(socket_handle);
child_error:
    exit(1);
error:
    GlobusGFSDebugExitWithError();
    return result;
}

static
void
globus_i_gfs_connection_closed()
{
    GlobusGFSName(globus_i_gfs_connection_closed);
    GlobusGFSDebugEnter();

    globus_l_gfs_open_count--;
    if(globus_l_gfs_terminated || globus_i_gfs_config_bool("single"))
    {
        if(globus_l_gfs_open_count == 0)
        {
            globus_l_gfs_terminated = GLOBUS_TRUE;
            globus_cond_signal(&globus_l_gfs_cond);
        }
    }
 
    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_close_cb);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        globus_i_gfs_connection_closed();
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_error_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_ipc_error_cb);
    GlobusGFSDebugEnter();

    globus_i_gfs_log_result("IPC ERROR", result);
    globus_l_gfs_server_closed(user_arg);

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_ipc_open_cb(
    globus_gfs_ipc_handle_t             ipc_handle,
    globus_result_t                     result,
    globus_gfs_finished_info_t *        reply,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_ipc_open_cb);
    GlobusGFSDebugEnter();

    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result("IPC ERROR", result);
    }

    GlobusGFSDebugExit();
}


static
void
globus_l_gfs_new_server_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_system_native_handle_t   system_handle;
    char *                              remote_contact;
    char *                              local_contact;
    GlobusGFSName(globus_l_gfs_new_server_cb);
    GlobusGFSDebugEnter();
    
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
            result = globus_gfs_ipc_handle_create(
                &globus_gfs_ipc_default_iface,
                system_handle,
                globus_l_gfs_ipc_open_cb,
                NULL,
                globus_l_gfs_ipc_error_cb,
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
    GlobusGFSDebugExit();
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

    GlobusGFSDebugExitWithError();
}

/* begin new server, this is called locked and it is assumed that
   the application is not in the termintated state */
static
globus_result_t
globus_l_gfs_open_new_server(
    globus_xio_handle_t                 handle)
{
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_open_new_server);
    GlobusGFSDebugEnter();
    
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
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_open:    
    GlobusGFSDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_gfs_prepare_stack(
    globus_xio_stack_t *                stack)
{
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_prepare_stack);
    GlobusGFSDebugEnter();
    
    result = globus_xio_stack_init(stack, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_xio_stack_push_driver(*stack, globus_l_gfs_tcp_driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
    
error:
    GlobusGFSDebugExitWithError();
    return result;
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
    GlobusGFSName(globus_l_gfs_convert_inetd_handle);
    GlobusGFSDebugEnter();
    
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
    
    globus_xio_stack_destroy(stack);
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_stack:
    globus_xio_stack_destroy(stack);
error:
    GlobusGFSDebugExitWithError();
    return result;
}


static
void
globus_l_gfs_reject_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        globus_l_gfs_outstanding--;
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
}

static
void
globus_l_gfs_reject_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        result = globus_xio_register_close(
            handle,
            NULL,
            globus_l_gfs_reject_close_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_gfs_outstanding--;
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
}


static
void
globus_l_gfs_reject_open_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    char * sorry_msg = "421 Service not available, closing control connection\r\n";

    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }

        result = globus_xio_register_write(
            handle,
            sorry_msg,
            strlen(sorry_msg),
            strlen(sorry_msg),
            NULL,
            globus_l_gfs_reject_write_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    return;

error:

    result = globus_xio_register_close(
        handle,
        NULL,
        globus_l_gfs_reject_close_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_gfs_outstanding--;
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
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
    GlobusGFSName(globus_l_gfs_server_accept_cb);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        globus_l_gfs_outstanding--;
        globus_l_gfs_xio_server_accepting = GLOBUS_FALSE;
        if(result != GLOBUS_SUCCESS)
        {
            goto error_accept;
        }

        /* if too many already open */
        if(globus_l_gfs_max_open_count != 0 &&
            globus_l_gfs_open_count >= globus_l_gfs_max_open_count)
        {
            result = globus_xio_register_open(
                handle,
                NULL,
                NULL,
                globus_l_gfs_reject_open_cb,
                NULL);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_accept;
            }
            globus_l_gfs_outstanding++;
        }
        else
        {
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

        if(globus_i_gfs_config_bool("single"))
        {
            result = globus_xio_server_register_close(
                globus_l_gfs_xio_server, globus_l_gfs_server_close_cb, NULL);
            if(result == GLOBUS_SUCCESS)
            {
                globus_l_gfs_outstanding++;
            }
            else
            {
                globus_l_gfs_xio_server = GLOBUS_NULL;
            }
        }
        else if(!globus_l_gfs_terminated &&
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
            globus_l_gfs_outstanding++;
            globus_l_gfs_xio_server_accepting = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
    
    GlobusGFSDebugExit();
    return;

error_register_accept:
    
error_accept:
    globus_l_gfs_terminated = GLOBUS_TRUE;
    if(globus_l_gfs_open_count == 0)
    {
        globus_cond_signal(&globus_l_gfs_cond);
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    GlobusGFSDebugExitWithError();
}

/* start up a daemon which will spawn server instances */
static
globus_result_t
globus_l_gfs_be_daemon()
{
    char *                              contact_string;
    char *                              interface;
    globus_result_t                     result;
    globus_xio_stack_t                  stack;
    globus_xio_attr_t                   attr;
    GlobusGFSName(globus_l_gfs_be_daemon);
    GlobusGFSDebugEnter();

    result = globus_callback_register_signal_handler(
        SIGCHLD,
        GLOBUS_TRUE,
        globus_l_gfs_sigchld,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

#ifndef BUILD_LITE
/* when threaded add a periodic callback to simulate the SIGCHLD signal, since 
 * many versions of LinuxThreads don't seem to pass that to right thread */
    {
        globus_reltime_t                delay;
        
        GlobusTimeReltimeSet(
            delay, GLOBUS_L_GFS_SIGCHLD_DELAY, 0);
        result = globus_callback_register_periodic(
            &globus_l_gfs_sigchld_periodic_handle,
            &delay,
            &delay,
            globus_l_gfs_sigchld,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
#endif

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
    globus_l_gfs_outstanding++;

    globus_l_gfs_xio_server_accepting = GLOBUS_TRUE;
    globus_xio_stack_destroy(stack);
    globus_xio_attr_destroy(attr);

    GlobusGFSDebugExit();
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
    GlobusGFSDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_server_build_child_args()
{
    int                                 i;
    int                                 j;
    char **                             prog_argv;
    GlobusGFSName(globus_l_gfs_server_build_child_args);

    /* exec the process */
    prog_argv = (char **) globus_i_gfs_config_get("argv");
    for(i = 0; prog_argv[i] != NULL; i++)
    {
    }
    globus_l_gfs_child_argv = (char **)
        globus_calloc(1, sizeof(char *) * (i + 2));
    if(globus_l_gfs_child_argv == NULL)
    {
        globus_result_t             result;
        char *                      error_msg;

        error_msg = globus_common_create_string("%s",
            _GSSL("Small malloc failed.  Unrecoverable error."));
        result = GlobusGFSErrorSystemError("malloc", errno);
        globus_i_gfs_log_result(error_msg, result);

        exit(1);
    }

    if((globus_l_gfs_child_argv[0]=globus_i_gfs_config_string("exec")) == NULL)
    {
        globus_l_gfs_child_argv[0] = globus_i_gfs_config_string("exec_name");
    }
    for(i = 1, j = 1; prog_argv[i] != NULL; i++)
    {
        if(strcmp(prog_argv[i], "-S") != 0 &&
            strcmp(prog_argv[i], "-s") != 0)
        {
            globus_l_gfs_child_argv[j++] = prog_argv[i];
        }
    }
    globus_l_gfs_child_argv[j++] = "-i";
    globus_l_gfs_child_argv[j] = NULL;
    globus_l_gfs_child_argc = j;
}

static
void
globus_l_gfs_server_detached()
{
    int                                 rc;
    pid_t                               pid;
    GlobusGFSName(globus_l_gfs_server_detached);

    globus_l_gfs_server_build_child_args();
    globus_l_gfs_child_argv[globus_l_gfs_child_argc-1] = "-s";

    pid = fork();
    if(pid < 0)
    {
    }
    /* if parent just end */
    else if(pid != 0)
    {
        exit(0);
    }
    /* if child */
    else
    {
        setsid();
        freopen("/dev/null", "w+", stdin);
        freopen("/dev/null", "w+", stdout);
        freopen("/dev/null", "w+", stderr);

       /* exec the process */
        if(*globus_l_gfs_child_argv[0] == '/')
        {
            rc = execv(globus_l_gfs_child_argv[0], globus_l_gfs_child_argv);
        }
        else
        {
            rc = execvp(globus_l_gfs_child_argv[0], globus_l_gfs_child_argv);
        }
        if(rc == -1)
        {
            globus_result_t             result;
            char *                      error_msg;

            error_msg = globus_common_create_string("%s\n%s\n%s\n%s",
                _GSSL("Could not exec process."),
                _GSSL("Please verify that a gridftp server is located at: "),
                globus_l_gfs_child_argv[0],
                _GSSL("Or try the -exec flag."));
            result = GlobusGFSErrorSystemError("execv", errno);
            globus_i_gfs_log_result(error_msg, result);

            exit(1);
        }
    }

}

int
main(
    int                                 argc,
    char **                             argv)
{
    int                                 rc = 0;
    char *                              config;
    globus_result_t                     result;
    GlobusGFSName(main);

    /* activte globus stuff */    
    if((rc = globus_module_activate(GLOBUS_COMMON_MODULE)) != GLOBUS_SUCCESS ||
        (rc = globus_module_activate(GLOBUS_XIO_MODULE)) != GLOBUS_SUCCESS ||
        (rc = globus_module_activate(
            GLOBUS_GRIDFTP_SERVER_MODULE)) != GLOBUS_SUCCESS ||
        (rc = globus_module_activate(GLOBUS_USAGE_MODULE)) != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
            "Error: Failed to initialize:\n%s",
            globus_error_print_friendly(globus_error_peek(rc)));
        goto error_activate;
    }
        
    /* init all the server modules */
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

#if !defined(BUILD_LITE) && defined(TARGET_ARCH_LINUX) 
    {
        char                            buf[256];
        
        buf[0] = '\0';
#if defined(_CS_GNU_LIBPTHREAD_VERSION)        
        confstr(_CS_GNU_LIBPTHREAD_VERSION, buf, sizeof(buf));
#endif        
        if((strstr(buf, "linuxthreads") || buf[0] == '\0') &&
            (!globus_i_gfs_config_bool("ignore_bad_threads") &&
            getuid() == 0))
        {
            fprintf(stderr, 
                "For security reasons, running as root with LinuxThreads \n"
                "is not supported.  Please use a non-threaded flavor, update \n"
                "your libc libraries, and/or unset the LD_ASSUME_KERNEL\n"
                "environment variable. \n"
                "(confstr = %s)\n", buf); 
            rc = -1;
            goto error_ver;
        }
    }
#endif

    /* detach from the terminal if we need to */
    if(globus_i_gfs_config_bool("detach"))
    {
        globus_l_gfs_server_detached();
    }
    
    /* XXX we're missing this */
    if(globus_i_gfs_config_bool("detach"))
    {
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
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_INFO,
                "Server started in inetd mode.\n");
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
            globus_l_gfs_server_build_child_args();
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_INFO,
                "Server started in daemon mode.\n");
            if(config)
            {
                globus_i_gfs_log_message(
                    GLOBUS_I_GFS_LOG_INFO,
                    "Configuration read from %s.\n", config);
            }            
            result = globus_l_gfs_be_daemon();
        }
        if(result != GLOBUS_SUCCESS)
        {
            rc = 1;
            goto error_lock;
        }

        /* run until we are done */ 
        while(!globus_l_gfs_terminated || 
                globus_l_gfs_open_count > 0 ||
                globus_l_gfs_outstanding > 0)
        {
            globus_cond_wait(&globus_l_gfs_cond, &globus_l_gfs_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    globus_xio_attr_destroy(globus_l_gfs_xio_attr);
    globus_xio_driver_unload(globus_l_gfs_tcp_driver);
    globus_i_gfs_log_close();

#ifndef BUILD_LITE
    if(globus_l_gfs_sigchld_periodic_handle != GLOBUS_NULL_HANDLE)
    {
        globus_callback_unregister(
            globus_l_gfs_sigchld_periodic_handle,
            NULL,
            NULL,
            NULL);
        globus_l_gfs_sigchld_periodic_handle = GLOBUS_NULL_HANDLE;
    }     
#endif

    globus_module_deactivate_all();

    GlobusGFSDebugExit();
    return 0;

error_lock:
    globus_i_gfs_log_result(_GSSL("Could not start server"), result);
    globus_mutex_unlock(&globus_l_gfs_mutex);
error_ver:
    globus_xio_attr_destroy(globus_l_gfs_xio_attr);
    globus_xio_driver_unload(globus_l_gfs_tcp_driver);
    globus_i_gfs_log_close();

error_activate:
    globus_module_deactivate_all();


    GlobusGFSDebugExitWithError();
    return rc;
}

static
void
globus_l_gfs_server_closed(
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_server_closed);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        globus_i_gfs_connection_closed();
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    GlobusGFSDebugExit();
}
