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

#ifndef GLOBUS_INCLUDE_FTP_I_CONTROL_H
#define GLOBUS_INCLUDE_FTP_I_CONTROL_H 1

#define GLOBUS_I_FTP_CONTROL_BUF_SIZE 200
#define GLOBUS_I_FTP_CONTROL_BUF_INCR 100

#define GLOBUS_I_TELNET_IP "\xFF\xF4"
#define GLOBUS_I_TELNET_SYNCH "\xFF\xF2"
#define GLOBUS_I_TELNET_IAC '\xFF'

#include "globus_config.h"

extern
FILE *          globus_i_ftp_control_devnull;

typedef enum
{
    GLOBUS_I_FTP_AUTH,
    GLOBUS_I_FTP_ACCT,
    GLOBUS_I_FTP_ADAT,
    GLOBUS_I_FTP_QUIT,
    GLOBUS_I_FTP_USER,
    GLOBUS_I_FTP_PASS,
    GLOBUS_I_FTP_NOOP
}
globus_i_ftp_cmd_t;

typedef struct globus_i_ftp_passthru_cb_arg_s
{
    globus_ftp_control_response_callback_t	     user_cb;
    void *				             user_cb_arg;
    globus_i_ftp_cmd_t                               cmd;
    globus_ftp_control_handle_t *	             handle;
} globus_i_ftp_passthru_cb_arg_t;

typedef struct globus_i_ftp_server_passthru_cb_arg_s
{
    globus_ftp_control_server_callback_t	callback;
    void *					callback_arg;
    globus_ftp_control_server_t *		server_handle;
} globus_i_ftp_server_passthru_cb_arg_t;


void
globus_i_ftp_control_call_close_cb(
    globus_ftp_control_handle_t *             handle);

void 
globus_i_ftp_control_write_next(
    globus_ftp_control_handle_t *             handle);

globus_result_t
globus_i_ftp_control_radix_encode(
    unsigned char *                        inbuf,
    unsigned char *                        outbuf,
    int *                                  length);

globus_result_t
globus_i_ftp_control_radix_decode(
    unsigned char *                        inbuf,
    unsigned char *                        outbuf,
    int *                                  length);

globus_result_t
globus_i_ftp_control_decode_command(
    char *                                    cmd,
    char **                                   decoded_cmd,
    globus_ftp_control_auth_info_t *          auth_info);

globus_result_t
globus_i_ftp_control_encode_command(
    globus_ftp_cc_handle_t *               cc_handle,
    char *                                 cmd,
    char **                                encoded_cmd);


globus_result_t
globus_i_ftp_control_encode_reply(
    char *                                    reply,
    char **                                   encoded_reply,
    globus_ftp_control_auth_info_t *          auth_info);

globus_result_t
globus_i_ftp_control_data_set_netlogger(
    globus_ftp_control_handle_t *               handle,
    globus_netlogger_handle_t *                 nl_handle,
    globus_bool_t                               nl_ftp_control,
    globus_bool_t                               nl_globus_io);

globus_result_t
globus_i_ftp_control_client_set_netlogger(
    globus_ftp_control_handle_t *               handle,
    globus_netlogger_handle_t *                 nl_handle);

globus_result_t
globus_i_ftp_control_data_activate(void);

globus_result_t
globus_i_ftp_control_data_deactivate(void);


globus_result_t
globus_i_ftp_control_client_activate(void);

globus_result_t
globus_i_ftp_control_client_deactivate(void);

globus_result_t
globus_i_ftp_control_server_activate(void);

globus_result_t
globus_i_ftp_control_server_deactivate(void);

globus_result_t
globus_i_ftp_control_data_cc_destroy(
    globus_ftp_control_handle_t *                control_handle);

globus_result_t
globus_i_ftp_control_data_cc_blocking_destroy(
    globus_ftp_control_handle_t *                control_handle);

globus_result_t
globus_i_ftp_control_data_abort(
    globus_ftp_control_handle_t *                control_handle,
    globus_object_t *                            error);

globus_result_t 
globus_i_ftp_control_auth_info_init(
    globus_ftp_control_auth_info_t *        dest,
    globus_ftp_control_auth_info_t *        src);

globus_result_t 
globus_i_ftp_control_auth_info_destroy(
    globus_ftp_control_auth_info_t *        auth_info);

globus_result_t
globus_i_ftp_control_get_connection_info(
    globus_ftp_control_handle_t *               handle,
    int *                                       local_host,
    unsigned short *                            local_port,
    int *                                       remote_host,
    unsigned short *                            remote_port);

/*
 *  internal function defintions
 */
globus_result_t
globus_i_ftp_parallelism_copy(
    globus_ftp_control_parallelism_t *             dest_parallelism,
    globus_ftp_control_parallelism_t *             src_parallelism);

int
globus_i_ftp_parallelism_get_size(
    globus_ftp_control_parallelism_t *             parallelism);

int
globus_i_ftp_parallelism_get_min_size(
    globus_ftp_control_parallelism_t *             parallelism);

int
globus_i_ftp_parallelism_get_max_size(
    globus_ftp_control_parallelism_t *             parallelism);

void
globus_ftp_control_host_port_init(
    globus_ftp_control_host_port_t *              host_port,
    char *                                        host,
    unsigned short                                port);

void
globus_ftp_control_host_port_destroy(
    globus_ftp_control_host_port_t *              host_port);

void
globus_ftp_control_host_port_get_host(
    globus_ftp_control_host_port_t *              host_port,
    char *                                        host);

unsigned short
globus_ftp_control_host_port_get_port(
    globus_ftp_control_host_port_t *              host_port);

void
globus_ftp_control_host_port_copy(
    globus_ftp_control_host_port_t *              dest,
    globus_ftp_control_host_port_t *              src);

globus_result_t
globus_i_ftp_control_client_get_connection_info(
    globus_ftp_control_handle_t *         handle,
    int                                   localhost[4],
    unsigned short *                      localport,
    int                                   remotehost[4],
    unsigned short *                      remoteport);

extern const char * globus_i_ftp_server_welcome;
extern const char * globus_i_ftp_server_user_reply;
extern const char * globus_i_ftp_server_pass_reply;

extern int globus_i_ftp_control_debug_level;

#ifdef BUILD_DEBUG
#define globus_i_ftp_control_debug(Level)                   \
    (globus_i_ftp_control_debug_level >= (Level))

#define globus_i_ftp_control_debug_printf(level, message)   \
do {                                                        \
    if (globus_i_ftp_control_debug(level))                  \
    {                                                       \
	globus_libc_fprintf message;                        \
    }                                                       \
} while (0)
#else
#define globus_i_ftp_control_debug_printf(level, message)
#endif


#endif


