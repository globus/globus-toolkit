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
 * Restart plugin
 *
 * Allow the restart to happen from plugin in a callback.
 */

#ifndef GLOBUS_INCLUDE_FTP_CLIENT_TEST_RESTART_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_TEST_RESTART_PLUGIN_H

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
#define GLOBUS_FTP_CLIENT_TEST_RESTART_PLUGIN_MODULE (&globus_i_ftp_client_test_restart_plugin_module)

extern
globus_module_descriptor_t globus_i_ftp_client_test_restart_plugin_module;
typedef enum
{
    FTP_RESTART_NEVER,
    FTP_RESTART_AT_CONNECT,
    FTP_RESTART_AT_CONNECT_RESPONSE,
    FTP_RESTART_AT_AUTH,
    FTP_RESTART_AT_AUTH_RESPONSE,
    FTP_RESTART_AT_SITE_HELP,
    FTP_RESTART_AT_SITE_HELP_RESPONSE,
    FTP_RESTART_AT_FEAT,
    FTP_RESTART_AT_FEAT_RESPONSE,
    FTP_RESTART_AT_TYPE,
    FTP_RESTART_AT_TYPE_RESPONSE,
    FTP_RESTART_AT_MODE,
    FTP_RESTART_AT_MODE_RESPONSE,
    FTP_RESTART_AT_OPTS_RETR,
    FTP_RESTART_AT_OPTS_RETR_RESPONSE,
    FTP_RESTART_AT_PASV,
    FTP_RESTART_AT_PASV_RESPONSE,
    FTP_RESTART_AT_PORT,
    FTP_RESTART_AT_PORT_RESPONSE,
    FTP_RESTART_AT_REST,
    FTP_RESTART_AT_REST_RESPONSE,
    FTP_RESTART_AT_RETR,
    FTP_RESTART_AT_RETR_RESPONSE,
    FTP_RESTART_AT_STOR,
    FTP_RESTART_AT_STOR_RESPONSE,
    FTP_RESTART_AT_LIST,
    FTP_RESTART_AT_LIST_RESPONSE,
    FTP_RESTART_AT_NLST,
    FTP_RESTART_AT_NLST_RESPONSE,
    FTP_RESTART_AT_MLSD,
    FTP_RESTART_AT_MLSD_RESPONSE,
    FTP_RESTART_AT_MLST,
    FTP_RESTART_AT_MLST_RESPONSE,
    FTP_RESTART_AT_MKD,
    FTP_RESTART_AT_MKD_RESPONSE,
    FTP_RESTART_AT_RMD,
    FTP_RESTART_AT_RMD_RESPONSE,
    FTP_RESTART_AT_DELE,
    FTP_RESTART_AT_DELE_RESPONSE,
    FTP_RESTART_AT_RNFR,
    FTP_RESTART_AT_RNFR_RESPONSE,
    FTP_RESTART_AT_RNTO,
    FTP_RESTART_AT_RNTO_RESPONSE,
    FTP_RESTART_AT_CHMOD,
    FTP_RESTART_AT_CHMOD_RESPONSE,    
    FTP_RESTART_AT_CKSM,
    FTP_RESTART_AT_CKSM_RESPONSE,    
    FTP_RESTART_AT_DATA,
    FTP_RESTART_AT_READ,
    FTP_RESTART_AT_WRITE,
    FTP_RESTART_LAST
}
globus_ftp_client_test_restart_plugin_when_t;

globus_result_t
globus_ftp_client_test_restart_plugin_init(
    globus_ftp_client_plugin_t *			plugin);

globus_result_t
globus_ftp_client_test_restart_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin);

globus_result_t
globus_ftp_client_test_restart_plugin_set_restart_point(
    globus_ftp_client_plugin_t *			plugin,
    globus_ftp_client_test_restart_plugin_when_t	when,
    globus_reltime_t *					timeout);
EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_TEST_RESTART_PLUGIN_H */




