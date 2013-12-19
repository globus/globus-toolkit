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
 * Abort plugin
 *
 * Allow the abort to happen from plugin in a callback.
 */

#ifndef GLOBUS_INCLUDE_FTP_CLIENT_TEST_ABORT_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_TEST_ABORT_PLUGIN_H

#include "globus_ftp_client.h"

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
#define GLOBUS_FTP_CLIENT_TEST_ABORT_PLUGIN_MODULE (&globus_i_ftp_client_test_abort_plugin_module)

extern
globus_module_descriptor_t globus_i_ftp_client_test_abort_plugin_module;
typedef enum
{
    FTP_ABORT_NEVER,
    FTP_ABORT_AT_CONNECT,
    FTP_ABORT_AT_CONNECT_RESPONSE,
    FTP_ABORT_AT_AUTH,
    FTP_ABORT_AT_AUTH_RESPONSE,
    FTP_ABORT_AT_SITE_HELP,
    FTP_ABORT_AT_SITE_HELP_RESPONSE,
    FTP_ABORT_AT_FEAT,
    FTP_ABORT_AT_FEAT_RESPONSE,
    FTP_ABORT_AT_TYPE,
    FTP_ABORT_AT_TYPE_RESPONSE,
    FTP_ABORT_AT_MODE,
    FTP_ABORT_AT_MODE_RESPONSE,
    FTP_ABORT_AT_OPTS_RETR,
    FTP_ABORT_AT_OPTS_RETR_RESPONSE,
    FTP_ABORT_AT_PASV,
    FTP_ABORT_AT_PASV_RESPONSE,
    FTP_ABORT_AT_PORT,
    FTP_ABORT_AT_PORT_RESPONSE,
    FTP_ABORT_AT_REST,
    FTP_ABORT_AT_REST_RESPONSE,
    FTP_ABORT_AT_RETR,
    FTP_ABORT_AT_RETR_RESPONSE,
    FTP_ABORT_AT_STOR,
    FTP_ABORT_AT_STOR_RESPONSE,
    FTP_ABORT_AT_LIST,
    FTP_ABORT_AT_LIST_RESPONSE,
    FTP_ABORT_AT_NLST,
    FTP_ABORT_AT_NLST_RESPONSE,
    FTP_ABORT_AT_MLSD,
    FTP_ABORT_AT_MLSD_RESPONSE,
    FTP_ABORT_AT_MKD,
    FTP_ABORT_AT_MKD_RESPONSE,
    FTP_ABORT_AT_RMD,
    FTP_ABORT_AT_RMD_RESPONSE,
    FTP_ABORT_AT_DELE,
    FTP_ABORT_AT_DELE_RESPONSE,
    FTP_ABORT_AT_RNFR,
    FTP_ABORT_AT_RNFR_RESPONSE,
    FTP_ABORT_AT_RNTO,
    FTP_ABORT_AT_RNTO_RESPONSE,
    FTP_ABORT_AT_DATA,
    FTP_ABORT_AT_READ,
    FTP_ABORT_AT_WRITE,
    FTP_ABORT_LAST
}
globus_ftp_client_test_abort_plugin_when_t;

globus_result_t
globus_ftp_client_test_abort_plugin_init(
    globus_ftp_client_plugin_t *			plugin);

globus_result_t
globus_ftp_client_test_abort_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin);

globus_result_t
globus_ftp_client_test_abort_plugin_set_abort_point(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_test_abort_plugin_when_t			when);

globus_result_t
globus_ftp_client_test_abort_plugin_set_abort_counter(
    globus_ftp_client_plugin_t *			plugin,
    int *						counter);
EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_TEST_ABORT_PLUGIN_H */
