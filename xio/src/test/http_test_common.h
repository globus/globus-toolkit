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

typedef void (*globus_xio_http_request_ready_callback_t)(
    void *                              user_arg,
    globus_result_t                     result,
    const char *                        method,
    const char *                        uri,
    globus_xio_http_version_t           http_version,
    globus_hashtable_t                  headers);

typedef struct
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;

    int                                 outstanding_operation;

    globus_xio_server_t                 server;
    globus_xio_handle_t                 handle;

    char *                              contact;

    globus_bool_t                       shutdown;
    globus_bool_t                       shutdown_done;

    globus_xio_http_version_t           http_version;
    char *                              transfer_encoding;
    globus_size_t                       buffer_size_t;

    globus_xio_driver_t                 http_driver;
    globus_xio_driver_t                 tcp_driver;

    globus_hashtable_t                  uri_handlers;
}
http_test_server_t;


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

#endif /* HTTP_TEST_COMMON_H */
