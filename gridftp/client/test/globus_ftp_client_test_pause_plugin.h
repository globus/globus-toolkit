/*
 * pause plugin definition.
 */

#ifndef GLOBUS_INCLUDE_FTP_CLIENT_TEST_PAUSE_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_TEST_PAUSE_PLUGIN_H

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
#define GLOBUS_FTP_CLIENT_TEST_PAUSE_PLUGIN_MODULE (&globus_i_ftp_client_test_pause_plugin_module)

extern
globus_module_descriptor_t globus_i_ftp_client_test_pause_plugin_module;

globus_result_t
globus_ftp_client_test_pause_plugin_init(
    globus_ftp_client_plugin_t *			plugin);

globus_result_t
globus_ftp_client_test_pause_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_TEST_PAUSE_PLUGIN_H */
