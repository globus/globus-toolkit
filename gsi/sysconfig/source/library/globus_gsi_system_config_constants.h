#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_system_config_constants.h
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef _GLOBUS_GSI_SYSTEM_CONFIG_CONSTANTS_H_
#define _GLOBUS_GSI_SYSTEM_CONFIG_CONSTANTS_H_

/**
 * @defgroup globus_gsi_sysconfig_constants GSI Credential Constants
 */
/**
 * GSI System Config Error codes
 * @ingroup globus_gsi_sysconfig_constants
 */
typedef enum
{
    GLOBUS_GSI_SYSCONFIG_ERROR_SUCCESS = 0,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_DIR = 1,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_STRING = 2,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_KEY_STRING = 3,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_HOME_DIR = 4,
    GLOBUS_GSI_SYSCONFIG_ERROR_ERRNO = 5,
    GLOBUS_GSI_SYSCONFIG_ERROR_CHECKING_FILE_EXISTS = 6,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CERT_FILENAME = 7,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_PROXY_FILENAME = 8,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_DELEG_FILENAME = 9,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CA_CERT_FILENAMES = 10,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_CWD = 11,
    GLOBUS_GSI_SYSCONFIG_ERROR_REMOVING_OWNED_FILES = 12,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_GRIDMAP_FILENAME = 13,
    GLOBUS_GSI_SYSCONFIG_ERROR_CHECKING_SUPERUSER = 14,
    GLOBUS_GSI_SYSCONFIG_ERROR_SETTING_PERMS = 15,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_SIGNING_POLICY = 16,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_PW_ENTRY = 17,
    GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_AUTHZ_FILENAME = 18,
    GLOBUS_GSI_SYSCONFIG_ERROR_FILE_NOT_REGULAR = 19,
    GLOBUS_GSI_SYSCONFIG_ERROR_FILE_DOES_NOT_EXIST = 20,
    GLOBUS_GSI_SYSCONFIG_ERROR_FILE_BAD_PERMISSIONS = 21,
    GLOBUS_GSI_SYSCONFIG_ERROR_FILE_NOT_OWNED = 22,
    GLOBUS_GSI_SYSCONFIG_ERROR_FILE_IS_DIR = 23,
    GLOBUS_GSI_SYSCONFIG_ERROR_FILE_ZERO_LENGTH = 24,
    GLOBUS_GSI_SYSCONFIG_ERROR_LAST = 25
} globus_gsi_sysconfig_error_t;


/**
 * Status Check Result Enumerator 
 * @ingroup globus_gsi_system_config
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
    GLOBUS_FILE_VALID = 0,
    GLOBUS_FILE_INVALID = 1,
    GLOBUS_FILE_DIR  = 2,
    GLOBUS_FILE_DOES_NOT_EXIST = 3,
    GLOBUS_FILE_NOT_OWNED = 4,
    GLOBUS_FILE_BAD_PERMISSIONS = 5,
    GLOBUS_FILE_ZERO_LENGTH = 6,
    GLOBUS_FILE_STATUS_LAST = 7
} globus_gsi_statcheck_t;
/* @} */


/**
 * Proxy File Type Enumerator
 * @ingroup globus_gsi_system_config
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

#endif /* _GLOBUS_GSI_SYSTEM_CONFIG_CONSTANTS_H_ */
