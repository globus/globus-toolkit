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
#include "openssl/x509.h"

/**
 * @mainpage Globus GSI System Config API
 *
 * This API provides helper functions for detecting installation and
 * environment specific settings applicabale to GSI. It also servers as a
 * abstraction layer for OS specific programming details. This is achieves by
 * defining preprocessor symbols that point at the correct platform specific
 * function. <b>You should never use the platform specific functions
 * directly.</b>.
 * Any program that uses Globus GSI System Config functions must include
 * "globus_gsi_system_config.h".  
 *
 * @htmlonly
 * <a href="main.html" target="_top">View documentation without frames</a><br>
 * <a href="index.html" target="_top">View documentation with frames</a><br>
 * @endhtmlonly
 */

/**
 * @defgroup globus_gsi_system_config_defines Defines
 *
 * These precompiler defines allow for a platform (ie Win32 vs UNIX)
 * independent API.
 *
 */


/**
 * @defgroup globus_gsi_sysconfig_unix Functions for UNIX platforms
 *
 * These functions implement the UNIX version of the Globus GSI System
 * Configuration API. <b>They should never be called directly, please use the
 * provided platform independent defines.</b>
 *
 */

/**
 * @defgroup globus_gsi_sysconfig_win32 Functions for Win32 platforms 
 *
 * These functions implement the Win32 version of the Globus GSI System
 * Configuration API. <b>They should never be called directly, please use the
 * provided platform independent defines.</b>
 *
 */

/**
 * @defgroup globus_gsi_sysconfig_shared Functions for all platforms
 *
 * These functions are platform independent members of the Globus GSI System
 * Configuration API. 
 *
 */


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
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
#endif

/** 
 * @defgroup globus_gsi_sysconfig_activation Activation
 *
 * Globus GSI System Configuration API uses standard Globus module activation
 * and deactivation.  Before any Globus GSI System Configuration API functions
 * are called, the following function must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if the Globus GSI System Configuration
 * API was successfully initialized, and you are therefore allowed to
 * subsequently call Globus GSI System Configuration API functions.  Otherwise,
 * an error code is returned, and Globus GSI Credential functions should not be
 * subsequently called. This function may be called multiple times.
 *
 * To deactivate Globus GSI System Configuration API, the following function
 * must be called: 
 *
 * @code
 *    globus_module_deactivate(GLOBUS_GSI_SYSCONFIG_MODULE)
 * @endcode
 *
 * This function should be called once for each time Globus GSI System
 * Configuration API was activated. 
 *
 */

/** Module descriptor
 * @ingroup globus_gsi_sysconfig_activation
 * @hideinitializer
 */
#define GLOBUS_GSI_SYSCONFIG_MODULE    (&globus_i_gsi_sysconfig_module)

extern 
globus_module_descriptor_t              globus_i_gsi_sysconfig_module;

#define _GSSL(s) globus_common_i18n_get_string(\
			GLOBUS_GSI_SYSCONFIG_MODULE,\
			s)

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
#    define GLOBUS_GSI_SYSCONFIG_DIR_EXISTS \
            globus_gsi_sysconfig_dir_exists_win32
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
            globus_gsi_sysconfig_split_dir_and_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_REMOVE_ALL_OWNED_FILES \
            globus_gsi_sysconfig_remove_all_owned_files_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME \
            globus_gsi_sysconfig_get_gridmap_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_AUTHZ_CONF_FILENAME \
            globus_gsi_sysconfig_get_authz_conf_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_GAA_CONF_FILENAME \
            globus_gsi_sysconfig_get_gaa_conf_filename_win32
#    define GLOBUS_GSI_SYSCONFIG_IS_SUPERUSER \
            globus_gsi_sysconfig_is_superuser_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_USER_ID_STRING \
            globus_gsi_sysconfig_get_user_id_string_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_PROC_ID_STRING \
            globus_gsi_sysconfig_get_proc_id_string_win32
#    define GLOBUS_GSI_SYSCONFIG_GET_USERNAME \
            globus_gsi_sysconfig_get_username_win32
#else
/**
 * Set the correct file permissions on a private key.
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_set_key_permissions_unix() and
 * globus_gsi_sysconfig_set_key_permissions_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_SET_KEY_PERMISSIONS \
            globus_gsi_sysconfig_set_key_permissions_unix
/**
 * Get the current users home directory
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_home_dir_unix() and
 * globus_gsi_sysconfig_get_home_dir_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_HOME_DIR \
            globus_gsi_sysconfig_get_home_dir_unix
/**
 * Check for the correct file permissions on a private key.
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_check_keyfile_unix() and
 * globus_gsi_sysconfig_check_keyfile_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_CHECK_KEYFILE \
            globus_gsi_sysconfig_check_keyfile_unix
/**
 * Check for the correct file permissions on a certificate.
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_check_certfile_unix() and
 * globus_gsi_sysconfig_check_certfile_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_CHECK_CERTFILE \
            globus_gsi_sysconfig_check_certfile_unix
/**
 * Check whether a given file exists
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_file_exists_unix() and
 * globus_gsi_sysconfig_file_exists_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_FILE_EXISTS \
            globus_gsi_sysconfig_file_exists_unix
/**
 * Check whether a given directory exists
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_dir_exists_unix() and
 * globus_gsi_sysconfig_dir_exists_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_DIR_EXISTS \
            globus_gsi_sysconfig_dir_exists_unix
/**
 * Determine the location of the trusted certificates directory
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_cert_dir_unix() and
 * globus_gsi_sysconfig_get_cert_dir_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR \
            globus_gsi_sysconfig_get_cert_dir_unix
/**
 * Determine the location of the users certificate and private key
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_user_cert_filename_unix() and
 * globus_gsi_sysconfig_get_user_cert_filename_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_USER_CERT_FILENAME \
            globus_gsi_sysconfig_get_user_cert_filename_unix
/**
 * Determine the location of the host certificate and private key
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_host_cert_filename_unix() and
 * globus_gsi_sysconfig_get_host_cert_filename_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_HOST_CERT_FILENAME \
            globus_gsi_sysconfig_get_host_cert_filename_unix
/**
 * Determine the location of a service certificate and private key
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_service_cert_filename_unix() and
 * globus_gsi_sysconfig_get_service_cert_filename_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_SERVICE_CERT_FILENAME \
            globus_gsi_sysconfig_get_service_cert_filename_unix
/**
 * Determine the location of a proxy certificate and private key
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_proxy_filename_unix() and
 * globus_gsi_sysconfig_get_proxy_filename_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME \
            globus_gsi_sysconfig_get_proxy_filename_unix
/**
 * Determine the name of the signing policy file for a given CA
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_signing_policy_filename_unix() and
 * globus_gsi_sysconfig_get_signing_policy_filename_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_SIGNING_POLICY_FILENAME \
            globus_gsi_sysconfig_get_signing_policy_filename_unix
/**
 * Get a list of of trusted CA certificate filenames in a trusted CA
 * certificate directory. 
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_ca_cert_files_unix() and
 * globus_gsi_sysconfig_get_ca_cert_files_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_CA_CERT_FILES \
            globus_gsi_sysconfig_get_ca_cert_files_unix
/**
 * Get the current working directory
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_current_working_dir_unix() and
 * globus_gsi_sysconfig_get_current_working_dir_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_CURRENT_WORKING_DIR \
            globus_gsi_sysconfig_get_current_working_dir_unix
/**
 * Prepend the current working directory to the give filename
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_make_absolute_path_for_filename_unix() and
 * globus_gsi_sysconfig_make_absolute_path_for_filename_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_MAKE_ABSOLUTE_PATH_FOR_FILENAME \
            globus_gsi_sysconfig_make_absolute_path_for_filename_unix
/**
 * Split directory component of path from filename.
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_split_dir_and_filename_unix() and
 * globus_gsi_sysconfig_split_dir_and_filename_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_SPLIT_DIR_AND_FILENAME \
            globus_gsi_sysconfig_split_dir_and_filename_unix
/**
 * Remove all proxies owned by current uid 
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_remove_all_owned_files_unix() and
 * globus_gsi_sysconfig_remove_all_owned_files_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_REMOVE_ALL_OWNED_FILES \
            globus_gsi_sysconfig_remove_all_owned_files_unix
/**
 * Determine the location of the grid map file. 
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_gridmap_filename_unix() and
 * globus_gsi_sysconfig_get_gridmap_filename_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME \
            globus_gsi_sysconfig_get_gridmap_filename_unix
/**
 * Determine the location of the authorization callout config file. 
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_authz_conf_filename_unix()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_AUTHZ_CONF_FILENAME \
            globus_gsi_sysconfig_get_authz_conf_filename_unix

/**
 * Determine the location of the GAA callout config file. 
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_gaa_conf_filename_unix()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_GAA_CONF_FILENAME \
            globus_gsi_sysconfig_get_gaa_conf_filename_unix
/**
 * Determine whether the current user is the super user
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_is_superuser_unix() and
 * globus_gsi_sysconfig_is_superuser_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_IS_SUPERUSER \
            globus_gsi_sysconfig_is_superuser_unix
/**
 * Get the current UID in string form
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_user_id_string_unix() and
 * globus_gsi_sysconfig_get_user_id_string_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_USER_ID_STRING \
            globus_gsi_sysconfig_get_user_id_string_unix
/**
 * Get the current PID in string form
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_proc_id_string_unix() and
 * globus_gsi_sysconfig_get_proc_id_string_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_PROC_ID_STRING \
            globus_gsi_sysconfig_get_proc_id_string_unix
/**
 * Get the current user name 
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_username_unix() and
 * globus_gsi_sysconfig_get_username_win32()
 */
#    define GLOBUS_GSI_SYSCONFIG_GET_USERNAME \
            globus_gsi_sysconfig_get_username_unix
#endif

/**
 * Generate a unqiue proxy file name
 * @ingroup globus_gsi_system_config_defines
 * @hideinitializer
 * See globus_gsi_sysconfig_get_unique_proxy_filename() 
 */
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
    const char *                        filename);

globus_result_t
globus_gsi_sysconfig_dir_exists_win32(
    const char *                        filename);

globus_result_t
globus_gsi_sysconfig_check_keyfile_win32(
    const char *                        filename);

globus_result_t
globus_gsi_sysconfig_check_certfile_win32(
    const char *                        filename);

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
    X509_NAME *                         ca_name,
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
    char *                              filename,
	char **								absolute_path);

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

globus_result_t
globus_gsi_sysconfig_get_authz_conf_filename_win32(
    char **                             filename);


#else /* if WIN32 is not defined, then define the unix functions */

globus_result_t
globus_gsi_sysconfig_set_key_permissions_unix(
    char *                              filename);

globus_result_t
globus_gsi_sysconfig_get_home_dir_unix(
    char **                             home_dir);

globus_result_t
globus_gsi_sysconfig_file_exists_unix(
    const char *                        filename);

globus_result_t
globus_gsi_sysconfig_dir_exists_unix(
    const char *                        filename);

globus_result_t
globus_gsi_sysconfig_check_keyfile_unix(
    const char *                        filename);

globus_result_t
globus_gsi_sysconfig_check_certfile_unix(
    const char *                        filename);

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

globus_result_t
globus_gsi_sysconfig_get_gaa_conf_filename_unix(
    char **                             filename);

#endif /* WIN32 */

globus_result_t
globus_gsi_sysconfig_get_unique_proxy_filename(
    char **                             unique_filename);

EXTERN_C_END

#endif /* GLOBUS_GSI_SYSTEM_CONFIG_H */
