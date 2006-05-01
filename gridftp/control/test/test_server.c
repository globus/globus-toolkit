/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_ftp_control.h"
#include <string.h>

static globus_bool_t  g_done;

char * g_init_response =
    "220 Globus Proxy Server";

void
error_msg(
    globus_result_t res,
    int line)
{
    globus_object_t * error;

    if(res != GLOBUS_SUCCESS)
    {
        error = globus_error_get(res);
        printf("Error: %s\n", globus_object_printable_to_string(error));
        printf("At Line: %d\n", line);
        assert(0);
    }
}

void
gpftpd_ac_response_callback(
    void *                                     callback_arg,
    globus_ftp_control_handle_t *              handle,
    globus_object_t *                          error)
{  
}

/*
 *
 */
void
gpftpd_auth_callback(
    void *                                   callback_arg,
    globus_ftp_control_handle_t *            handle,
    globus_object_t *                        error,
    globus_ftp_control_auth_info_t *         auth_result)
{
    globus_result_t                          res;
    char *                                   username;
    globus_bool_t                            accepted;
    char *                                   tmp_ptr;

    if(error)
    {
        error_msg(globus_error_put(error), __LINE__);
    }

    accepted = GLOBUS_FALSE;
    if(strcmp(auth_result->user, ":globus-mapping:") == 0 &&
       globus_gss_assist_gridmap(
           auth_result->auth_gssapi_subject, &username) == 0)
    {
        accepted = GLOBUS_TRUE;
    }
    else if(strcmp(auth_result->user, "ftp") == 0 ||
            strcmp(auth_result->user, "anonymous") == 0)
    {
        accepted = GLOBUS_TRUE;
        username = auth_result->user;
    }

    if(accepted)
    {
        res = globus_ftp_control_send_response(
                  handle,
                  "230 User %s logged on.\r\n",
                  gpftpd_ac_response_callback,
                  callback_arg,
                  g_init_response,
                  username);
    }
    else
    {
        res = globus_ftp_control_send_response(
                  handle,
                  "530 No local mapping for Globus ID.\r\n",
                  gpftpd_ac_response_callback,
                  callback_arg,
                  g_init_response);
    }

    error_msg(res, __LINE__);
}

void
gpftpd_response_callback(
    void *                                     callback_arg,
    globus_ftp_control_handle_t *              handle,
    globus_object_t *                          error)
{
    globus_result_t                            res;
    globus_ftp_control_auth_requirements_t     auth_req;

    if(error)
    {
        error_msg(globus_error_put(error), __LINE__);
    }

    auth_req = GLOBUS_FTP_CONTROL_AUTH_REQ_GSSAPI |
               GLOBUS_FTP_CONTROL_AUTH_REQ_USER |
               GLOBUS_FTP_CONTROL_AUTH_REQ_PASS;

    res = globus_ftp_control_server_authenticate(
              handle,
              auth_req,
              gpftpd_auth_callback,
              callback_arg);
    error_msg(res, __LINE__);
}

void
gpftpd_accept_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error)
{
    globus_result_t                             res;

    if(error)
    {
        error_msg(globus_error_put(error), __LINE__);
    }

    res = globus_ftp_control_send_response(
              handle,
              "%s\r\n",
              gpftpd_response_callback,
              callback_arg,
              g_init_response);
    error_msg(res, __LINE__);
}

void 
gpftpd_listen_callback(
    void *                                      callback_arg,
    globus_ftp_control_server_t *               server_handle,
    globus_object_t *                           error)
{
    globus_ftp_control_handle_t *               new_handle;
    globus_result_t                             res;

    if(error)
    {
        error_msg(globus_error_put(error), __LINE__);
    }

    new_handle = (globus_ftp_control_handle_t *)
                      globus_malloc(sizeof(globus_ftp_control_handle_t));
    res = globus_ftp_control_handle_init(new_handle);
    error_msg(res, __LINE__);

    res = globus_ftp_control_server_accept(
              server_handle,
              new_handle,
              gpftpd_accept_callback,
              callback_arg);
    error_msg(res, __LINE__);
}

int
main(
    int                               argc,
    char *                            argv[])
{
    unsigned short                    port = 0;
    globus_result_t                   res;
    globus_ftp_control_server_t       server_handle;

    globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);

    res = globus_ftp_control_server_handle_init(&server_handle);
    error_msg(res, __LINE__);

    res = globus_ftp_control_server_listen(
              &server_handle,
              &port,
              gpftpd_listen_callback,
              NULL);
    error_msg(res, __LINE__);

    printf("%d\n", port);

    while(!g_done)
    {
        globus_poll();
    }

    return 0;
}
