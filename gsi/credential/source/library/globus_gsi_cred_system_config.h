#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_cred_system_config.h
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef GLOBUS_I_GSI_SYSTEM_CONFIG_H
#define GLOBUS_I_GSI_SYSTEM_CONFIG_H

#include "globus_common.h"

/**
 * @defgroup globus_gsi_cred_system_config Globus Credential System Config API
 *
 */

/**
 * @defgroup globus_gsi_cred_system_config_win32 Globus Credential 
 * System Config API for Win32 platforms
 *
 */

/**
 * @defgroup globus_gsi_cred_system_config_unix Globus Credential System Config
 * API for Unix platforms
 *
 */

/**
 * @defgroup globus_i_gsi_cred_system_config Internal Globus Credential
 * System Config API
 *
 */

/**
 * @defgroup globus_i_gsi_cred_system_config_win32 Internal Globus Credential
 * System Config API for Win32 platforms
 *
 */

/**
 * @defgroup globus_i_gsi_cred_system_config_unix Internal Globus Credential
 * System Config API for Unix platforms
 *
 */

/**
 * Status Check Result Enumerator 
 * @ingroup globus_gsi_cred_system_config
 */
/* @{ */
/**
 * Enumerator containing the results of a status check on a file
 *  
 * @enum globus_gsi_statcheck_t
 *
 * The globus_gsi_statcheck_t enum provides
 * a set of values that can be used to
 * determine the status of a certificate or
 * key file.
 *
 * @param GLOBUS_VALID
 *        If the status of the file being checked is valid with
 *        respect to the type of file, this is used.  For example,
 *        if a proxy file is being checked, then its only valid
 *        if only the user has read-only permissions on it
 * @param GLOBUS_DOES_NOT_EXIST
 *        The file doesn't exist
 * @param GLOBUS_NOT_OWNED
 *        The file being checked isn't owned by the current user
 * @param GLOBUS_BAD_PERMISSIONS
 *        The file being checked doesn't have the right permissions
 *        with respect to the type of file it is - see GLOBUS_VALID
 * @param GLOBUS_ZERO_LENGTH
 *        The file has zero length
 */
typedef enum
{
    GLOBUS_VALID,
    GLOBUS_DOES_NOT_EXIST,
    GLOBUS_NOT_OWNED,
    GLOBUS_BAD_PERMISSIONS,
    GLOBUS_ZERO_LENGTH
} globus_gsi_statcheck_t;
/* @} */

/**
 * Proxy File Type Enumerator
 * @ingroup globus_gsi_cred_system_config
 */
/* @{ */
/**
 * Enumerator used to keep track of input/output types of filenames
 *
 * @param GLOBUS_PROXY_FILE_INPUT
 *        If the proxy filename is intended for 
 *        reading (it should already exist)
 * @param GLOBUS_PROXY_FILE_OUTPUT
 *        If the proxy filename is intended for
 *        writing (it does not need to exist)
 */
typedef enum
{
    GLOBUS_PROXY_FILE_INPUT,
    GLOBUS_PROXY_FILE_OUTPUT
} globus_gsi_proxy_file_type_t;
/* @} */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

#ifdef WIN32
#    define GLOBUS_I_GSI_GET_HOME_DIR globus_i_gsi_get_home_dir_win32
#    define GLOBUS_I_GSI_GET_USER_ID_STRING \
            globus_i_gsI_get_user_id_string_win32
#    define GLOBUS_I_GSI_GET_PROC_ID_STRING \
            globus_i_gsi_get_proc_id_string_win32
#    define GLOBUS_I_GSI_CHECK_KEYFILE globus_i_gsi_check_keyfile_win32
#    define GLOBUS_I_GSI_CHECK_CERTFILE globus_i_gsi_check_certfile_win32
#    define GLOBUS_I_GSI_FILE_EXISTS globus_i_gsi_file_exists_win32
#    define GLOBUS_GSI_CRED_GET_CERT_DIR globus_gsi_cred_get_cert_dir_win32
#    define GLOBUS_GSI_CRED_GET_USER_CERT_FILENAME \
            globus_gsi_cred_get_user_cert_filename_win32
#    define GLOBUS_GSI_CRED_GET_HOST_CERT_FILENAME \
            globus_gsi_cred_get_host_cert_filename_win32
#    define GLOBUS_GSI_CRED_GET_SERVICE_CERT_FILENAME \
            globus_gsi_cred_get_service_cert_filename_win32
#    define GLOBUS_GSI_CRED_GET_PROXY_FILENAME \
            globus_gsi_cred_get_proxy_filename_win32
#else
#    define GLOBUS_I_GSI_GET_HOME_DIR globus_i_gsi_get_home_dir_unix
#    define GLOBUS_I_GSI_GET_USER_ID_STRING \
            globus_i_gsi_get_user_id_string_unix
#    define GLOBUS_I_GSI_GET_PROC_ID_STRING \
            globus_i_gsi_get_proc_id_string_unix
#    define GLOBUS_I_GSI_CHECK_KEYFILE globus_i_gsi_check_keyfile_unix
#    define GLOBUS_I_GSI_CHECK_CERTFILE globus_i_gsi_check_certfile_unix
#    define GLOBUS_I_GSI_FILE_EXISTS globus_i_gsi_file_exists_unix
#    define GLOBUS_GSI_CRED_GET_CERT_DIR globus_gsi_cred_get_cert_dir_unix
#    define GLOBUS_GSI_CRED_GET_USER_CERT_FILENAME \
            globus_gsi_cred_get_user_cert_filename_unix
#    define GLOBUS_GSI_CRED_GET_HOST_CERT_FILENAME \
            globus_gsi_cred_get_host_cert_filename_unix
#    define GLOBUS_GSI_CRED_GET_SERVICE_CERT_FILENAME \
            globus_gsi_cred_get_service_cert_filename_unix
#    define GLOBUS_GSI_CRED_GET_PROXY_FILENAME \
            globus_gsi_cred_get_proxy_filename_unix
#endif

#define     GLOBUS_GSI_CRED_GET_UNIQUE_PROXY_FILENAME \
            globus_gsi_cred_get_unique_proxy_filename


globus_result_t
globus_gsi_cred_create_cert_dir_string(
    char **                             cert_dir,
    char **                             cert_dir_value,
    const char *                        format,
    ...);

globus_result_t
globus_i_gsi_cred_create_cert_string(
    char **                             cert_string,
    char **                             cert_string_value,
    const char *                        format,
    ...);

globus_result_t
globus_i_gsi_cred_create_key_string(
    char **                             key_string,
    char **                             key_string_value,
    const char *                        format,
    ...);


#ifdef WIN32

globus_result_t
globus_i_gsi_get_home_dir_win32(
    char **                             home_dir);

globus_result_t
globus_i_gsi_file_exists_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_i_gsi_check_keyfile_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_i_gsi_check_certfile_win32(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_gsi_cred_get_cert_dir_win32(
    char **                             cert_dir);

globus_result_t
globus_gsi_cred_get_user_cert_filename_win32(
    char **                             user_cert_filename,
    char **                             user_key_filename);

globus_result_t
globus_gsi_cred_get_host_cert_filename_win32(
    char **                             host_cert_filename,
    char **                             host_key_filename);

globus_result_t
globus_gsi_cred_get_service_cert_filename_win32(
    char *                              service_name,
    char **                             service_cert_filename,
    char **                             service_key_filename);

globus_result_t
globus_gsi_cred_get_proxy_filename_win32(
    char **                             proxy_filename,
    int                                 proxy_in);

#else /* if WIN32 is not defined, then define the unix functions */

globus_result_t
globus_i_gsi_get_home_dir_unix(
    char **                             home_dir);

globus_result_t
globus_i_gsi_file_exists_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_i_gsi_check_keyfile_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_i_gsi_check_certfile_unix(
    const char *                        filename,
    globus_gsi_statcheck_t *            status);

globus_result_t
globus_gsi_cred_get_cert_dir_unix(
    char **                             cert_dir);

globus_result_t
globus_gsi_cred_get_user_cert_filename_unix(
    char **                             user_cert_filename,
    char **                             user_key_filename);

globus_result_t
globus_gsi_cred_get_host_cert_filename_unix(
    char **                             host_cert_filename,
    char **                             host_key_filename);

globus_result_t
globus_gsi_cred_get_service_cert_filename_unix(
    char *                              service_name,
    char **                             service_cert_filename,
    char **                             service_key_filename);

globus_result_t
globus_gsi_cred_get_proxy_filename_unix(
    char **                             user_proxy,
    globus_gsi_proxy_file_type_t        proxy_file_type);

#endif /* WIN32 */

globus_result_t
globus_gsi_cred_get_unique_proxy_filename(
    char **                             unique_filename);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#endif
