#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_cred_constants.h
 * Globus GSI Credential Library
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef GLOBUS_GSI_CREDENTIAL_CONSTANTS_H
#define GLOBUS_GSI_CREDENTIAL_CONSTANTS_H

/**
 * @defgroup globus_gsi_credential_constants GSI Credential Constants
 */
/**
 * GSI Credential Error codes
 * @ingroup globus_gsi_credential_constants
 */
typedef enum
{
    GLOBUS_GSI_CRED_ERROR_SUCCESS = 0,
    GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED = 1,
    GLOBUS_GSI_CRED_ERROR_READING_HOST_CRED = 2,
    GLOBUS_GSI_CRED_ERROR_READING_SERVICE_CRED = 3,
    GLOBUS_GSI_CRED_ERROR_READING_CRED = 4,
    GLOBUS_GSI_CRED_ERROR_WRITING_CRED = 5,
    GLOBUS_GSI_CRED_ERROR_WRITING_PROXY_CRED = 6,
    GLOBUS_GSI_CRED_ERROR_CHECKING_PROXY = 7,
    GLOBUS_GSI_CRED_ERROR_VERIFYING_CRED = 8,
    GLOBUS_GSI_CRED_ERROR_WITH_CRED = 9,
    GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT = 10,
    GLOBUS_GSI_CRED_ERROR_WITH_CRED_PRIVATE_KEY = 11,
    GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN = 12,
    GLOBUS_GSI_CRED_ERROR_ERRNO = 13,
    GLOBUS_GSI_CRED_ERROR_SYSTEM_CONFIG = 14,
    GLOBUS_GSI_CRED_ERROR_WITH_CRED_HANDLE_ATTRS = 15,
    GLOBUS_GSI_CRED_ERROR_WITH_SSL_CTX = 16,
    GLOBUS_GSI_CRED_ERROR_WITH_CALLBACK_DATA = 17,
    GLOBUS_GSI_CRED_ERROR_CREATING_ERROR_OBJ = 18,
    GLOBUS_GSI_CRED_ERROR_KEY_IS_PASS_PROTECTED = 19,
    GLOBUS_GSI_CRED_ERROR_NO_CRED_FOUND = 20,
    GLOBUS_GSI_CRED_ERROR_SUBJECT_CMP = 21,
    GLOBUS_GSI_CRED_ERROR_GETTING_SERVICE_NAME = 22,
    GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER = 23,
    GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_NAME = 24,
    GLOBUS_GSI_CRED_ERROR_LAST = 25
} globus_gsi_cred_error_t;

/**
 * GSI Credential Type
 * @ingroup globus_gsi_credential_handle
 *
 * An enum representing a GSI Credential Type which holds info about 
 * the type of a particular credential.  The three types of credential
 * can be: GLOBUS_PROXY, GLOBUS_USER, or GLOBUS_HOST.
 * 
 * @see globus_gsi_credential_handle
 */
typedef enum 
{
    GLOBUS_PROXY,
    GLOBUS_USER,
    GLOBUS_HOST,
    GLOBUS_SERVICE,
    GLOBUS_SO_END
} globus_gsi_cred_type_t;

#define GLOBUS_NULL_GROUP               "GLOBUS_NULL_GROUP"
#define GLOBUS_NULL_POLICY              "GLOBUS_NULL_POLICY"

#endif

