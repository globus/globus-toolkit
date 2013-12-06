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

/**
 * throughput plugin
 *
 * Allow the throughput performance data be retrieved to a callback.
 */

#ifndef GLOBUS_INCLUDE_FTP_CLIENT_TEST_THROUGHPUT_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_TEST_THROUGHPUT_PLUGIN_H

#include "globus_ftp_client.h"
#include "globus_ftp_client_plugin.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/** Module descriptor
 */
#define GLOBUS_FTP_CLIENT_TEST_THROUGHPUT_PLUGIN_MODULE (&globus_i_ftp_client_test_throughput_plugin_module)

extern
globus_module_descriptor_t globus_i_ftp_client_test_throughput_plugin_module;

globus_result_t
globus_ftp_client_test_throughput_plugin_init(
    globus_ftp_client_plugin_t *			plugin);

globus_result_t
globus_ftp_client_test_throughput_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_TEST_THROUGHPUT_PLUGIN_H */
