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

#ifndef HTTP_TEST_COMMON_H
#define HTTP_TEST_COMMON_H

#include "globus_xio.h"
#include "globus_xio_http.h"

#define PINGPONG_MAX_SIZE   1000000
#define THROUGHPUT_MAX_SIZE 1000000
#define START_SIZE 1000000
#define TCP_BUF_SIZE 8000000

typedef struct
{
    globus_byte_t *			buffer;			
    globus_size_t			size;
    int					iterations;
    int					temp_iterations;
    int                                 done;
    globus_xio_http_version_t           version;
    char *				contact;
    char *                              transfer_encoding;
    globus_xio_driver_t                 tcp_driver;
    globus_xio_driver_t                 http_driver;
    globus_xio_stack_t                  stack;
}
http_test_info_t;

typedef struct
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;

    int                                 outstanding_operation;

    globus_xio_server_t                 server;
    globus_xio_handle_t                 handle;

    char *				contact;
    globus_bool_t                       shutdown;
    globus_bool_t                       shutdown_done;

    globus_hashtable_t                  uri_handlers;
    http_test_info_t *			info;
    globus_xio_driver_t                 http_driver;
}
http_test_server_t;

typedef int
(*pingpong_func_t)(          
    http_test_info_t *	     info,
    int                      timer);

typedef int
(*next_size_func_t)(
    int                       last_size);

typedef void (*globus_xio_http_request_ready_callback_t)(
    void *                              user_arg,
    globus_result_t                     result,
    const char *                        method,
    const char *                        uri,
    globus_xio_http_version_t           http_version,
    globus_hashtable_t                  headers);

typedef struct _performance_s
{
    next_size_func_t         next_size;
    pingpong_func_t	     pingpong;
    char *                   name;
    void *                   user_arg;
    int			     iterations;	
} performance_t;

globus_result_t
http_test_server_init(
    http_test_server_t *                server,
    globus_xio_driver_t                 tcp_driver,
    globus_xio_driver_t                 http_driver,
    globus_xio_stack_t                  stack);

globus_result_t
http_test_server_register_handler(
    http_test_server_t *                server,
    const char *                        uri,
    globus_xio_http_request_ready_callback_t
                                        ready_callback,
    void *                              arg);

globus_result_t
http_test_server_run(
    http_test_server_t *                server);

globus_result_t
http_test_server_shutdown(
    http_test_server_t *                server);

void
http_test_server_destroy(
    http_test_server_t *                server);

globus_result_t
http_test_server_respond(
    http_test_server_t *                server,
    int                                 status_code,
    char *                              reason_phrase,
    globus_xio_http_header_t *          header_array,
    size_t                              header_array_len);

globus_result_t
http_test_server_close_handle(
    http_test_server_t *                test_server);

globus_result_t
http_test_client_request(
    globus_xio_handle_t *               new_handle,
    globus_xio_driver_t                 tcp_driver,
    globus_xio_driver_t                 http_driver,
    globus_xio_stack_t                  stack,
    const char *                        contact,
    const char *                        uri,
    const char *                        method,
    globus_xio_http_version_t           http_version,
    globus_xio_http_header_t *          header_array,
    size_t                              header_array_length);

int
http_test_initialize(
    globus_xio_driver_t *               tcp_driver,
    globus_xio_driver_t *               http_driver,
    globus_xio_stack_t *                stack);

globus_bool_t
http_is_eof(
    globus_result_t                     res);

void
performance_init(
    performance_t *          perf,
    pingpong_func_t	     pingpong,	
    next_size_func_t         next_size,
    int			     iterations,	
    char *                   test_name,
    int			     buf_size);

void
performance_start_slave(
    performance_t *          perf,
    http_test_info_t *       info);

int
performance_start_master(
    performance_t *          perf,
    http_test_info_t *       info);

int
throughput_next_size(
    int                       last_size);

int
pingpong_next_size(
    int                       last_size);

int
pingpong_next_size(
    int                       last_size);

int
throughput_next_size(
    int                       last_size);

void
prep_timers(
    performance_t *           perf,
    char *                    label,
    int                       iterations,
    int			      buf_size);

void
write_timers(
    char *                    label);

void
performance_write_timers(
    performance_t *           perf);

#endif
