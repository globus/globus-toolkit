#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_system_config.h
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef GLOBUS_GSI_SYSTEM_CONFIG_H
#define GLOBUS_GSI_SYSTEM_CONFIG_H

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN

#include "globus_common.h"
#include "globus_gsi_system_config_constants.h"
#include <openssl/x509.h>

/**
 * @defgroup globus_gsi_system_config Globus Credential System Config API
 *
 */

/**
 * @defgroup globus_gsi_system_config_win32 Globus Credential 
 * System Config API for Win32 platforms
 *
 */

/**
 * @defgroup globus_gsi_system_config_unix Globus Credential System Config
 * API for Unix platforms
 *
 */

/**
 * @defgroup globus_i_gsi_system_config Internal Globus Credential
 * System Config API
 *
 */

/**
 * @defgroup globus_i_gsi_system_config_win32 Internal Globus Credential
 * System Config API for Win32 platforms
 *
 */

/**
 * @defgroup globus_i_gsi_system_config_unix Internal Globus Credential
 * System Config API for Unix platforms
 *
 */


/** Module descriptor
 * @ingroup globus_gsi_credential_activation
 * @hideinitializer
 */
#define GLOBUS_GSI_SYSCONFIG_MODULE    (&globus_i_gsi_sysconfig_module)

extern 
globus_module_descriptor_t              globus_i_gsi_sysconfig_module;

#ifdef WIN32
#    define GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR \
            globus_gsi_sysconfig_get_cert_dir_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_USER_CERT_FILENAME \
            globus_gsi_sysconfig_get_user_cert_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_HOST_CERT_FILENAME \
            globus_gsi_sysconfig_get_host_cert_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_SERVICE_CERT_FILENAME \
            globus_gsi_sysconfig_get_service_cert_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME \
            globus_gsi_sysconfig_get_proxy_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_SIGNING_POLICY_FILENAME \
            globus_gsi_sysconfig_get_signing_policy_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_CA_CERT_FILES \
            globus_gsi_sysconfig_get_ca_cert_files_win32
#else
#    define GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR \
            globus_gsi_sysconfig_get_cert_dir_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_USER_CERT_FILENAME \
            globus_gsi_sysconfig_get_user_cert_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_HOST_CERT_FILENAME \
            globus_gsi_sysconfig_get_host_cert_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_SERVICE_CERT_FILENAME \
            globus_gsi_sysconfig_get_service_cert_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME \
            globus_gsi_sysconfig_get_proxy_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_SIGNING_POLICY_FILENAME \
            globus_gsi_sysconfig_get_signing_policy_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_CA_CERT_FILES \
            globus_gsi_sysconfig_get_ca_cert_files_unix
#endif

#define     GLOBUS_GSI_SYSCONFIG_GET_UNIQUE_PROXY_FILENAME \
            globus_gsi_sysconfig_get_unique_proxy_filename

#ifdef WIN32

globus_result_t
globus_gsi_sysconfig_get_cert_dir_win32(
    char **                             cert_dir);

globus_result_t
globus_gsi_sysconfig_get_user_cert_filename_win32(
    char **                             user_cert_filename,
    char **                             user_key_filename);

globus_result_t
globus_gsi_sysconfig_get_host_cert_filename_win32(
    char **                             host_cert_filename,
    char **                             host_key_filename);

globus_result_t
globus_gsi_sysconfig_get_service_cert_filename_win32(
    char *                              service_name,
    char **                             service_cert_filename,
    char **                             service_key_filename);

globus_result_t
globus_gsi_sysconfig_get_proxy_filename_win32(
    char **                             proxy_filename,
    int                                 proxy_in);

globus_result_t
globus_gsi_sysconfig_get_signing_policy_filename_win32(
    char *                              cert_dir,
    char **                             signing_policy_filename);

globus_result_t
globus_gsi_sysconfig_get_ca_cert_files_win32(
    char *                              ca_cert_dir,
    globus_fifo_t *                     ca_cert_list);

#else /* if WIN32 is not defined, then define the unix functions */

globus_result_t
globus_gsi_sysconfig_get_cert_dir_unix(
    char **                             cert_dir);

globus_result_t
globus_gsi_sysconfig_get_user_cert_filename_unix(
    char **                             user_cert_filename,
    char **                             user_key_filename);

globus_result_t
globus_gsi_sysconfig_get_host_cert_filename_unix(
    char **                             host_cert_filename,
    char **                             host_key_filename);

globus_result_t
globus_gsi_sysconfig_get_service_cert_filename_unix(
    char *                              service_name,
    char **                             service_cert_filename,
    char **                             service_key_filename);

globus_result_t
globus_gsi_sysconfig_get_proxy_filename_unix(
    char **                             user_proxy,
    globus_gsi_proxy_file_type_t        proxy_file_type);

globus_result_t
globus_gsi_sysconfig_get_signing_policy_filename_unix(
    X509_NAME *                         ca_name,
    char *                              cert_dir,
    char **                             signing_policy_filename);

globus_result_t
globus_gsi_sysconfig_get_ca_cert_files_unix(
    char *                              ca_cert_dir,
    globus_fifo_t *                     ca_cert_list);

#endif /* WIN32 */

globus_result_t
globus_gsi_sysconfig_get_unique_proxy_filename(
    char **                             unique_filename);

#endif /* GLOBUS_GSI_SYSTEM_CONFIG_H */


