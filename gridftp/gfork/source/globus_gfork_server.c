#include "globus_i_gfork.h"
#include "errno.h"
#include <sys/types.h>
#include <sys/wait.h>

static globus_mutex_t                   gfork_l_mutex;
static globus_cond_t                    gfork_l_cond;
static globus_hashtable_t               gfork_l_pid_table;
static globus_bool_t                    gfork_l_done = GLOBUS_FALSE;
globus_extension_handle_t               gfork_i_plugin_handle;

static
void
gfork_new_child(
    gfork_i_options_t *                 gfork_h,
    globus_xio_system_socket_t          socket_handle,
    int                                 read_fd,
    int                                 write_fd);

void
gfork_log(
    gfork_i_options_t *                 gfork_h,
    int                                 level,
    char *                              fmt,
    ...)
{
    va_list                             ap;

    if(gfork_h->quiet)
    {
        return;
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static
void
gfork_l_call_close(
    gfork_i_child_handle_t *            kid_handle,
    gfork_i_state_t                     temp_state)
{
    gfork_i_options_t *                 gfork_h;

    if(temp_state != GFORK_STATE_CLOSING)
    {
        return;
    }
    gfork_h = kid_handle->whos_my_daddy;

    gfork_h->module->close_func(
        gfork_h->user_arg, kid_handle, kid_handle->user_arg);

    globus_mutex_lock(&gfork_l_mutex);
    {
        kid_handle->state = gfork_i_state_next(
            kid_handle->state, GFORK_EVENT_CLOSE_RETURNS);
        globus_assert(kid_handle->state != GFORK_STATE_NONE
            && "Bad state");

        if(kid_handle->state == GFORK_STATE_CLOSED)
        {
            close(kid_handle->write_fd);
            close(kid_handle->read_fd);
            globus_xio_close(kid_handle->write_xio_handle, NULL);
            globus_xio_close(kid_handle->read_xio_handle, NULL);
            globus_free(kid_handle);
        }
    }
    globus_mutex_unlock(&gfork_l_mutex);
}


static
void
gfork_l_sigchld(
    void *                              user_arg)
{
    int                                 child_pid;
    int                                 child_status;
    int                                 child_rc;
    gfork_i_options_t *                 gfork_h;
    gfork_i_child_handle_t *            kid_handle;
    gfork_i_state_t                     temp_state;
    globus_result_t                     res;

    gfork_h = (gfork_i_options_t *) user_arg;

    while((child_pid = waitpid(-1, &child_status, WNOHANG)) > 0)
    {
        if(WIFEXITED(child_status))
        {
            /* normal exit */
            child_rc = WEXITSTATUS(child_status);
        }
        else if(WIFSIGNALED(child_status))
        {
            /* killed by */
        }

        globus_mutex_lock(&gfork_l_mutex);
        {
            kid_handle = (gfork_i_child_handle_t *)
                globus_hashtable_lookup(&gfork_l_pid_table, (void *)child_pid);
            assert(kid_handle != NULL);

            gfork_h = kid_handle->whos_my_daddy;
            globus_hashtable_remove(&gfork_l_pid_table, (void *)child_pid);

            temp_state = gfork_i_state_next(
                kid_handle->state, GFORK_EVENT_SIGCHILD);
            globus_assert(temp_state != GFORK_STATE_NONE 
                && "Bad state");
            kid_handle->state = temp_state;

            /* react to new state */
        }
        globus_mutex_unlock(&gfork_l_mutex);

        /* call close ? */
        gfork_l_call_close(kid_handle, temp_state);
    }

    res = globus_callback_register_signal_handler(
        SIGCHLD,
        GLOBUS_FALSE,
        gfork_l_sigchld,
        &gfork_h);
    globus_assert(res == GLOBUS_SUCCESS);
}

static
globus_result_t
gfork_init_handle(
    gfork_i_options_t *                 gfork_h)
{
    memset(gfork_h, '\0', sizeof(gfork_i_options_t));

    return GLOBUS_SUCCESS;
}

static
void
gfork_l_server_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    pid_t                               pid;
    int                                 infds[2];
    int                                 outfds[2];
    int                                 rc;
    gfork_i_options_t *                 gfork_h;
    globus_xio_system_socket_t          socket_handle;
    gfork_i_child_handle_t *            kid_handle;
    gfork_i_state_t                     temp_state;
    GForkFuncName(gfork_l_server_accept_cb);

    gfork_h = (gfork_i_options_t *) user_arg;

    globus_mutex_lock(&gfork_l_mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            goto error_accept;
        }

        rc = pipe(infds);
        if(rc != 0)
        {
            result = GForkErrorErrno(strerror(errno), errno);
            goto error_inpipe;
        }
        rc = pipe(outfds);
        if(rc != 0)
        {
            result = GForkErrorErrno(strerror(errno), errno);
            goto error_outpipe;
        }

        result = globus_xio_handle_cntl(
            handle,
            gfork_i_tcp_driver,
            GLOBUS_XIO_TCP_GET_HANDLE,
            &socket_handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_getsocket;
        }

        pid = fork();
        if(pid < 0)
        {
            /* error */
            result = GForkErrorErrno(strerror(errno), errno);
            goto error_fork;
        }
        else if(pid == 0)
        {
            close(outfds[1]);
            close(infds[0]);

            gfork_new_child(gfork_h, socket_handle, outfds[0], infds[1]);

            /* hsould not return from this, if we do it is an error */
            goto error_fork;
        }
        else
        {
            /* server */
            fcntl(outfds[1], F_SETFD, FD_CLOEXEC);
            fcntl(infds[0], F_SETFD, FD_CLOEXEC);

            close(outfds[0]);
            close(infds[1]);

            close(socket_handle);
        }
        /* i think we dont care when the close happens */
        globus_xio_register_close(handle, NULL, NULL, NULL);

        kid_handle = (gfork_i_child_handle_t *)
            globus_calloc(1, sizeof(gfork_i_child_handle_t));
        kid_handle->pid = pid;
        kid_handle->whos_my_daddy = gfork_h;
        kid_handle->write_fd = outfds[1];
        kid_handle->read_fd = infds[0];
        kid_handle->state = GFORK_STATE_OPENING;
        kid_handle->state = gfork_i_state_next(
            GFORK_STATE_NONE, GFORK_EVENT_ACCEPT_CB);

        result = gfork_i_make_xio_handle(
            &kid_handle->write_xio_handle, kid_handle->write_fd);
        if(result != GLOBUS_SUCCESS)
        {
            gfork_log(gfork_h, 1, "write handle make failed %s\n",
                globus_error_print_friendly(globus_error_get(result)));
        }
        result = gfork_i_make_xio_handle(
            &kid_handle->read_xio_handle, kid_handle->read_fd);
        if(result != GLOBUS_SUCCESS)
        {
            gfork_log(gfork_h, 1, "read handle make failed %s\n",
                globus_error_print_friendly(globus_error_get(result)));
        }

        globus_hashtable_insert(
            &gfork_l_pid_table,
            (void *)pid,
            kid_handle);

        result = globus_xio_server_register_accept(
            gfork_h->tcp_server,
            gfork_l_server_accept_cb,
            gfork_h);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_register;
        }
    }
    globus_mutex_unlock(&gfork_l_mutex);

    /* tell the module about it */
    gfork_h->module->open_func(
        gfork_h->user_arg,
        kid_handle,
        &kid_handle->user_arg);

    globus_mutex_lock(&gfork_l_mutex);
    {
        temp_state =
            gfork_i_state_next(kid_handle->state, GFORK_EVENT_OPEN_RETURNS);
        globus_assert(temp_state != GFORK_STATE_NONE && "Bad state");
        kid_handle->state = temp_state;
        /* now react to new state */
    }
    globus_mutex_unlock(&gfork_l_mutex);

    gfork_l_call_close(kid_handle, temp_state);

    return;

error_register:
error_fork:
    globus_mutex_lock(&gfork_l_mutex);
    globus_xio_register_close(handle, NULL, NULL, NULL);
    close(socket_handle);
    close(outfds[0]);
    close(outfds[1]);
error_getsocket:
error_outpipe:
    close(infds[0]);
    close(infds[1]);
error_inpipe:
error_accept:
    globus_mutex_unlock(&gfork_l_mutex);

    /* log an error */
    return;
}


static
globus_result_t
gfork_init_server(
    gfork_i_options_t *                 gfork_h)
{
    globus_result_t                     res;
    char *                              contact_string;

    res = globus_xio_server_create(
        &gfork_h->tcp_server, gfork_i_tcp_attr, gfork_i_tcp_stack);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_create;
    }

    res = globus_xio_server_get_contact_string(
        gfork_h->tcp_server, &contact_string);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_contact;
    }
    gfork_log(gfork_h, 1, "Listening on: %s\n", contact_string);
    globus_free(contact_string);

    res = globus_xio_server_register_accept(
        gfork_h->tcp_server,
        gfork_l_server_accept_cb,
        gfork_h);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_register;
    }
    return GLOBUS_SUCCESS;

error_register:
    free(contact_string);
error_contact:
    globus_xio_server_close(gfork_h->tcp_server);
error_create:

    return res;
}

/*
 *  post for in child.  Never returns from here 
 */
static
void
gfork_new_child(
    gfork_i_options_t *                 gfork_h,
    globus_xio_system_socket_t          socket_handle,
    int                                 read_fd,
    int                                 write_fd)
{
    globus_result_t                     res;
    int                                 rc = 1;
    char                                tmp_str[32];
    GlobusGForkFuncName(gfork_new_child);

    /* set up the state pipe and envs */
    sprintf(tmp_str, "%d", read_fd);
    globus_libc_setenv(GFORK_CHILD_READ_ENV, tmp_str, 1);
    sprintf(tmp_str, "%d", write_fd);
    globus_libc_setenv(GFORK_CHILD_WRITE_ENV, tmp_str, 1);

    /* dup the incoming socket */
    rc = dup2(socket_handle, STDIN_FILENO);
    if(rc < 0)
    {
        res = GForkErrorErrno(strerror, errno);
        goto error_dupin;
    }
    rc = dup2(socket_handle, STDOUT_FILENO);
    if(rc < 0)
    {
        res = GForkErrorErrno(strerror, errno);
        goto error_dupout;
    }
    close(socket_handle);

    /* start it */
    rc = execv(gfork_h->argv[0], gfork_h->argv);
    /* if we get to here ecxec failed, fall through to error handling */

error_dupout:
error_dupin:
    /* log error */
    exit(rc);
}

static
globus_result_t
gfork_i_opts_unknown(
   globus_options_handle_t              opts_handle,
    void *                              unknown_arg,
    int                                 argc,
    char **                             argv)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "gfork_i_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        unknown_arg));
}



int
main(
    int                                 argc,
    char **                             argv)
{
    int                                 rc;
    gfork_i_options_t                   gfork_h;
    globus_options_handle_t             opt_h;
    globus_result_t                     res;

    rc = globus_module_activate(GLOBUS_GFORK_PARENT_MODULE);
    if(rc != 0)
    {
        gfork_h.quiet = 0;
        gfork_log(&gfork_h, 1, "Activation error\n");
        goto error_act;
    }

    globus_hashtable_init(
        &gfork_l_pid_table,
        1024,
        globus_hashtable_int_hash,
        globus_hashtable_int_keyeq);
    globus_mutex_init(&gfork_l_mutex, NULL);
    globus_cond_init(&gfork_l_cond, NULL);

    gfork_init_handle(&gfork_h);

    globus_options_init(
        &opt_h, gfork_i_opts_unknown, &gfork_h);
    globus_options_add_table(opt_h, gfork_l_opts_table, &gfork_h);

    res = globus_options_command_line_process(opt_h, argc, argv);
    if(res != GLOBUS_SUCCESS)
    {
        gfork_log(&gfork_h, 1, "Bad command line options\n");
        goto error_opts;
    }
        gfork_log(&gfork_h, 1, "port %d\n",
            gfork_h.port);

    /* verify options */
    if(gfork_h.plugin_name == NULL)
    {
        gfork_log(&gfork_h, 1, "You must specify a plugin\n");
        goto error_opts;
    }
    if(gfork_h.argv == NULL)
    {
        gfork_log(&gfork_h, 1, "You must specify a a program to run\n");
        goto error_opts;
    }

    /* load the plug in */
    rc = globus_extension_activate(gfork_h.plugin_name);
    if(rc != 0)
    {
        gfork_log(&gfork_h, 1, "Failed to activate extenstion %s\n",
            gfork_h.plugin_name);
        goto error_activate;
    }

    gfork_h.module = (globus_gfork_module_t *) globus_extension_lookup(
        &gfork_i_plugin_handle,
        &gfork_i_plugin_registry,
        (void *) gfork_h.plugin_name);
    if(gfork_h.module == NULL)
    {
        gfork_log(&gfork_h, 1, "Failed to find %s in extension\n",
            gfork_h.plugin_name);
        goto error_activate;
    }

    globus_mutex_lock(&gfork_l_mutex);
    {
        res = globus_callback_register_signal_handler(
            SIGCHLD,
            GLOBUS_FALSE,
            gfork_l_sigchld,
            &gfork_h);
        if(res != GLOBUS_SUCCESS)
        {
            gfork_log(&gfork_h, 1, "Failed to register signal handler\n");
            goto error_signal;
        }

        res = gfork_init_server(&gfork_h);
        if(res != GLOBUS_SUCCESS)
        {
            gfork_log(&gfork_h, 1, "Failed to init server\n");
            goto error_server;
        }

        while(!gfork_l_done)
        {
            globus_cond_wait(&gfork_l_cond, &gfork_l_mutex);
        }
    }
    globus_mutex_unlock(&gfork_l_mutex);

    gfork_log(&gfork_h, 1, "Server Done\n");
    return 0;
error_signal:
error_server:
error_activate:
error_opts:
error_act:

    gfork_log(&gfork_h, 1, "Error\n");
    return 1;
}
