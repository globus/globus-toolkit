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
#    define GLOBUS_GSI_SYSCONFIG_SET_KEY_PERMISSIONS \
            globus_gsi_sysconfig_set_key_permissions_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_HOME_DIR \
            globus_gsi_sysconfig_get_home_dir_win32
#    define GLOBUS_GSI_SYSCONFIG_CHECK_KEYFILE \
            globus_gsi_sysconfig_check_keyfile_win32
#    define GLOBUS_GSI_SYSCONFIG_CHECK_CERTFILE \
            globus_gsi_sysconfig_check_certfile_win32
#    define GLOBUS_GSI_SYSCONFIG_FILE_EXISTS \
            globus_gsi_sysconfig_file_exists_win32
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
#    define GLOBUS_GSI_SYSCONFIG_GET_CURRENT_WORKING_DIR \
            globus_gsi_sysconfig_get_current_working_dir_win32
#    define GLOBUS_GSI_SYSCONFIG_MAKE_ABSOLUTE_PATH_FOR_FILENAME \
            globus_gsi_sysconfig_make_absolute_path_for_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_SPLIT_DIR_AND_FILENAME \
            globus_gsi_sysconfig_split_dir_and_fliename_win32
#    define GLOBUS_GSI_SYSCONFIG_REMOVE_ALL_OWNED_FILES \
            globus_gsi_sysconfig_remove_all_owned_files_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME \
            globus_gsi_sysconfig_get_gridmap_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_IS_SUPERUSER \
            globus_gsi_sysconfig_is_superuser_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_USER_ID_STRING \
            globus_gsI_sysconfig_get_user_id_string_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_PROC_ID_STRING \
            globus_gsi_sysconfig_get_proc_id_string_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_USERNAME \
            globus_gsi_sysconfig_get_username_win32
#else
#    define GLOBUS_GSI_SYSCONFIG_SET_KEY_PERMISSIONS \
            globus_gsi_sysconfig_set_key_permissions_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_HOME_DIR \
            globus_gsi_sysconfig_get_home_dir_unix
#    define GLOBUS_GSI_SYSCONFIG_CHECK_KEYFILE \
            globus_gsi_sysconfig_check_keyfile_unix
#    define GLOBUS_GSI_SYSCONFIG_CHECK_CERTFILE \
            globus_gsi_sysconfig_check_certfile_unix
#    define GLOBUS_GSI_SYSCONFIG_FILE_EXISTS \
            globus_gsi_sysconfig_file_exists_unix
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
#    define GLOBUS_GSI_SYSCONFIG_GET_CURRENT_WORKING_DIR \
            globus_gsi_sysconfig_get_current_working_dir_unix
#    define GLOBUS_GSI_SYSCONFIG_MAKE_ABSOLUTE_PATH_FOR_FILENAME \
            globus_gsi_sysconfig_make_absolute_path_for_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_SPLIT_DIR_AND_FILENAME \
            globus_gsi_sysconfig_split_dir_and_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_REMOVE_ALL_OWNED_FILES \
            globus_gsi_sysconfig_remove_all_owned_files_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME \
            globus_gsi_sysconfig_get_gridmap_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_AUTHZ_CONF_FILENAME \
            globus_gsi_sysconfig_get_authz_conf_filename_unix
#    define GLOBUS_GSI_SYSCONFIG_IS_SUPERUSER \
            globus_gsi_sysconfig_is_superuser_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_USER_ID_STRING \
            globus_gsi_sysconfig_get_user_id_string_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_PROC_ID_STRING \
            globus_gsi_sysconfig_get_proc_id_string_unix
#    define GLOBUS_GSI_SYSCONFIG_GET_USERNAME \
            globus_gsi_sysconfig_get_username_unix
#endif

#define     GLOBUS_GSI_SYSCONFIG_GET_UNIQUE_PROXY_FILENAME \
            globus_gsi_sysconfig_get_unique_proxy_filename

#ifdef WIN32

globus_result_t
globus_gsi_sysconfig_set_key_permissions_win32(
    char *                              filename);

globus_result_t
globus_gsi_sysconfig_get_home_dir_win32(
    char **                             home_dir);

globus_result_t
globus_gsi_sysconfig_file_exists_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_gsi_sysconfig_check_keyfile_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_gsi_sysconfig_check_certfile_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

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
    globus_gsi_proxy_file_type_t        proxy_file_type);

globus_result_t
globus_gsi_sysconfig_get_signing_policy_filename_win32(
    char *                              cert_dir,
    char **                             signing_policy_filename);

globus_result_t
globus_gsi_sysconfig_get_ca_cert_files_win32(
    char *                              ca_cert_dir,
    globus_fifo_t *                     ca_cert_list);

globus_result_t
globus_gsi_sysconfig_get_current_working_dir_win32(
    char **                             working_dir);

globus_result_t
globus_gsi_sysconfig_make_absolute_path_for_filename_win32(
    char *                              filename);

globus_result_t
globus_gsi_sysconfig_split_dir_and_filename_win32(
    char *                              full_filename,
    char **                             dir_string,
    char **                             filename_string);

globus_result_t
globus_gsi_sysconfig_remove_all_owned_files_win32(
    char *                              default_filename);

globus_result_t
globus_gsi_sysconfig_is_superuser_win32(
    int *                               is_superuser);

globus_result_t
globus_gsi_sysconfig_get_user_id_string_win32(
    char **                             user_id_string);

globus_result_t
globus_gsi_sysconfig_get_username_win32(
    char **                             username);

globus_result_t
globus_gsi_sysconfig_get_proc_id_string_win32(
    char **                             proc_id_string);

globus_result_t
globus_gsi_sysconfig_get_gridmap_filename_win32(
    char **                             filename);

#else /* if WIN32 is not defined, then define the unix functions */

globus_result_t
globus_gsi_sysconfig_set_key_permissions_unix(
    char *                              filename);

globus_result_t
globus_gsi_sysconfig_get_home_dir_unix(
    char **                             home_dir,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_gsi_sysconfig_file_exists_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_gsi_sysconfig_check_keyfile_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_gsi_sysconfig_check_certfile_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

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

globus_result_t
globus_gsi_sysconfig_get_current_working_dir_unix(
    char **                             working_dir);

globus_result_t
globus_gsi_sysconfig_make_absolute_path_for_filename_unix(
    char *                              filename,
    char **                             absolute_path);

globus_result_t
globus_gsi_sysconfig_split_dir_and_filename_unix(
    char *                              full_filename,
    char **                             dir_string,
    char **                             filename_string);

globus_result_t
globus_gsi_sysconfig_remove_all_owned_files_unix(
    char *                              default_filename);

globus_result_t
globus_gsi_sysconfig_is_superuser_unix(
    int *                               is_superuser);

globus_result_t
globus_gsi_sysconfig_get_user_id_string_unix(
    char **                             user_id_string);

globus_result_t
globus_gsi_sysconfig_get_username_unix(
    char **                             username);

globus_result_t
globus_gsi_sysconfig_get_proc_id_string_unix(
    char **                             proc_id_string);

globus_result_t
globus_gsi_sysconfig_get_gridmap_filename_unix(
    char **                             filename);

globus_result_t
globus_gsi_sysconfig_get_authz_conf_filename_unix(
    char **                             filename);

#endif /* WIN32 */

globus_result_t
globus_gsi_sysconfig_get_unique_proxy_filename(
    char **                             unique_filename);

EXTERN_C_END

#endif /* GLOBUS_GSI_SYSTEM_CONFIG_H */
