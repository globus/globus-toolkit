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

#if !defined(GLOUBS_FTP_CONTROL_TEST_H)
#define GLOUBS_FTP_CONTROL_TEST_H

#include "globus_ftp_control.h"
#include "test_common.h"
/**********************************************************************
*  TESTS
*
*  for ascii and binary
*
*  a call to globus_module_activate should preceed each test
*  and tehy should be followed by a corresponding call to _deactivate
*
*  control_connect_test
*     test connecting the control channel
*
*  control_disconnect_test
*     disconnect the control channel
*
*  async_control_test
*      send commands via the callbacks of other commands
*
*  simple_control_test
*     send several non data requesting commands and wait for
*     appropriate responses
*
*  simple_data_test
*     put bytes / get bytes / compare bytes
*     only 1 read or write request is oustanding a time
*
*  simple_dir_test
*     requests a list from the server.  Tests the data channel.
*
*  outstanding_io_test
*     same as simple_data_test only several read/write can be registered
*     at one time
*
*  simple_fail_test
*      a variety of functions called that due to the current state
*      should fail with useful error codes
*
*  abort_restart_test
*      same as the abort_test only restart the transfer after the
*      abort is successful
*
*  data_commands_connect_test
*      Test if a  control handle hasn't been  established prior to calling 
*       globus_ftp_data commands.
*
*  data_commands_pasvorport_test
*      Test if globus_ftp_data_local_pasv()/port() has been called prior to
*      calling globus_ftp_data commands.
*
*  pending_test
*      Test for pending commands that have been sent but the reply is  not yet
*      been received. In this case a call to send_command() returns FAILURE.
* 
**********************************************************************/

typedef struct login_s
{
    char                                        login[512];
    char                                        password[512];
    char                                        dir[512];
    char                                        hostname[512];
    int                                         port;
} login_t;

typedef struct globus_ftp_control_test_monitor_s
{
    globus_mutex_t                            mutex;
    globus_cond_t                             cond;
    globus_bool_t                             done;
    globus_bool_t                             rc;
    int                                       count;

    void *                                    user_arg;
} globus_ftp_control_test_monitor_t;

void
fake_file_init(
    globus_ftp_control_fake_file_t *          fake_file,
    int                                       file_size,
    int                                       chunk_size);

globus_byte_t *
fake_file_get_chunk(
    globus_ftp_control_fake_file_t *          fake_file,
    int *                                     chunk_size);

globus_bool_t
fake_file_seek(
    globus_ftp_control_fake_file_t *          fake_file,
    int                                       offset);

globus_bool_t
fake_file_is_eof(
    globus_ftp_control_fake_file_t *          fake_file);

globus_bool_t
fake_file_cmp(
    globus_ftp_control_fake_file_t *          fake_file,
    globus_byte_t *                           buffer,
    int                                       offset,
    int                                       length);
   
void
fake_file_destroy(
    globus_ftp_control_fake_file_t *          fake_file);
 
void
verbose_printf(
    int                                       level,
    char *                                    s,
    ...);

void
help_print();

globus_bool_t
connect_control_handle(
    globus_ftp_control_handle_t *               control_handle,
    char *                                      user_name,
    char *                                      password,
    char *                                      base_dir,
    char *                                      hostname,
    unsigned short                              port);

globus_bool_t
disconnect_control_handle(
    globus_ftp_control_handle_t *               control_handle);

globus_bool_t
simple_control_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
simple_data_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
eb_data_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
eb_simple_data_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
outstanding_io_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
async_control_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
simple_dir_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
pending_response_test(
    globus_ftp_control_handle_t *               handle);


globus_bool_t
data_commands_connect_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
data_commands_pasvorport_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
abort_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
pasv_to_host_port(
    char *                                      parse_str,
    globus_ftp_control_host_port_t *            addr);

extern int                                      verbose_print_level;

void
verbose_printf(
    int                                       level,
    char *                                    s,
    ...);

void
help_print();

globus_bool_t
simple_control_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
simple_data_test(
    globus_ftp_control_handle_t *               handle);

globus_bool_t
pasv_to_host_port(
    char *                                      parse_str,
    globus_ftp_control_host_port_t *            addr);

extern int                                      verbose_print_level;
extern login_t                                  login_info;
#endif
