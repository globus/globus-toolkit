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

#include "globus_ftp_control_test.h"
#include "globus_common.h"

static globus_ftp_control_test_monitor_t        connect_monitor;

static    globus_ftp_control_auth_info_t              auth;

static char *                                   g_user_name;
static char *                                   g_password;
static char *                                   g_base_dir;
static char *                                   g_host;
static unsigned short                           g_port;

void
connect_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    globus_result_t                             result;

    if(ftp_response == GLOBUS_NULL)
    {
        globus_mutex_lock(&connect_monitor.mutex);
        {
            connect_monitor.rc = GLOBUS_FALSE;
            connect_monitor.done = GLOBUS_FALSE;
            verbose_printf(2, "signal condition error:%s\n",
                 globus_object_printable_to_string(error));
            globus_cond_signal(&connect_monitor.cond);
        }
        globus_mutex_unlock(&connect_monitor.mutex);

        return;
    }

    verbose_printf(2, "connect_response_callback() : start: %s\n",
                   ftp_response->response_buffer);
    if(ftp_response->code == 530)
    {
        verbose_printf(1, "not logged in: %s\n", ftp_response->response_buffer);
        globus_mutex_lock(&connect_monitor.mutex);
        {
            connect_monitor.rc = GLOBUS_FALSE;
            connect_monitor.done = GLOBUS_FALSE;
            verbose_printf(2, "signal condition\n");
            globus_cond_signal(&connect_monitor.cond);
        }
        globus_mutex_unlock(&connect_monitor.mutex);
    }
    else if(ftp_response->code == 220)
    {
        memset(&auth, '\0', sizeof(auth));
        result = globus_ftp_control_auth_info_init(
                     &auth,
		     GLOBUS_NULL,
                     g_user_name, g_password,
      /*               GLOBUS_NULL, GLOBUS_NULL, 
        */             GLOBUS_NULL,

                     GLOBUS_NULL);
          /*           "/C=US/O=Globus/O=Argonne National Laboratory/OU=Mathematics and Computer Science Division/CN=John Bresnahan");
   */
        assert(result==GLOBUS_SUCCESS);

        result = globus_ftp_control_authenticate(
                     handle,
                     &auth,
                     GLOBUS_FALSE,
                     connect_response_callback,
                     GLOBUS_NULL);
if(result != GLOBUS_SUCCESS)
{
printf("#####-> %s\n", globus_object_printable_to_string(globus_error_get(result)));
}
        assert(result==GLOBUS_SUCCESS);
    }
    else if(ftp_response->code == 230)
    {
        result = globus_ftp_control_send_command(
            handle,
            "CWD %s\r\n",
            connect_response_callback,
            GLOBUS_NULL,
            g_base_dir);
        if(result != GLOBUS_SUCCESS)
        {
            verbose_printf(1, "failed to send cd\n");
            exit(1);
        }
    }
    else if(ftp_response->code == 250)
    {
        globus_mutex_lock(&connect_monitor.mutex);
        {
            connect_monitor.rc = GLOBUS_TRUE;
            connect_monitor.done = GLOBUS_TRUE;
            globus_cond_signal(&connect_monitor.cond);
        }
        globus_mutex_unlock(&connect_monitor.mutex);
    }
    else if(ftp_response->code == 221)
    {
        globus_mutex_lock(&connect_monitor.mutex);
        {
            connect_monitor.rc = GLOBUS_TRUE;
            connect_monitor.done = GLOBUS_TRUE;
            globus_cond_signal(&connect_monitor.cond);
        }
        globus_mutex_unlock(&connect_monitor.mutex);
    }
    else if(ftp_response->code >= 500)
    {
        globus_mutex_lock(&connect_monitor.mutex);
        {
            connect_monitor.rc = GLOBUS_FALSE;
            connect_monitor.done = GLOBUS_FALSE;
            globus_cond_signal(&connect_monitor.cond);
        }
        globus_mutex_unlock(&connect_monitor.mutex);
    }
}

globus_bool_t
connect_control_handle(
    globus_ftp_control_handle_t *               control_handle,
    char *                                      user_name,
    char *                                      password,
    char *                                      base_dir,
    char *                                      hostname,
    unsigned short                              port)
{
    globus_result_t                             result;

    g_user_name = user_name;
    g_password = password;
    g_base_dir = base_dir;
    g_host = hostname;
    g_port = port;

    globus_mutex_init(&connect_monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&connect_monitor.cond, GLOBUS_NULL);
    connect_monitor.done = GLOBUS_FALSE;
    connect_monitor.rc = GLOBUS_TRUE;

    result = globus_ftp_control_connect(
                 control_handle,
                 g_host,
                 g_port,
                 connect_response_callback,
                 GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        verbose_printf(1, "error: could not connect\n");
        return GLOBUS_FALSE;
    }

    globus_mutex_lock(&connect_monitor.mutex);
    {
        verbose_printf(2, "waiting for signal\n");
        while(!connect_monitor.done)
        {
            globus_cond_wait(&connect_monitor.cond, &connect_monitor.mutex);
        }
    }
    globus_mutex_unlock(&connect_monitor.mutex);

    verbose_printf(2, "connect_control_handle() : test %d\n",
                   connect_monitor.rc);

    return connect_monitor.rc;
}


globus_bool_t
disconnect_control_handle(
    globus_ftp_control_handle_t *               control_handle)
{
    globus_result_t                             result;

    connect_monitor.done = GLOBUS_FALSE;
    connect_monitor.rc = GLOBUS_TRUE;

    result = globus_ftp_control_quit(
                 control_handle,
                 connect_response_callback,
                 GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        verbose_printf(1, "globus_ftp_control_quit() failed\n");
        return GLOBUS_FALSE;
    }

    globus_mutex_lock(&connect_monitor.mutex);
    {
        while(!connect_monitor.done)
        {
            globus_cond_wait(&connect_monitor.cond, &connect_monitor.mutex);
        }
    }
    globus_mutex_unlock(&connect_monitor.mutex);

    globus_mutex_destroy(&connect_monitor.mutex);
    globus_cond_destroy(&connect_monitor.cond);
    connect_monitor.done = GLOBUS_FALSE;

    return connect_monitor.rc;
}

