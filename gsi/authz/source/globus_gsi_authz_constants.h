#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_cred_constants.h
 * Globus GSI Authorization Library
 *
 */
#endif

#ifndef GLOBUS_GSI_AUTHZ_CONSTANTS_H
#define GLOBUS_GSI_AUTHZ_CONSTANTS_H

/**
 * @defgroup globus_gsi_authz_constants GSI Credential Constants
 */
/**
 * GSI Authz Error codes
 * @ingroup globus_gsi_authz_constants
 */
typedef enum
{
/*****?????????? this needs update ???????????***********/
    GLOBUS_GSI_AUTHZ_ERROR_SUCCESS = 0,
    GLOBUS_GSI_AUTHZ_ERROR_ERRNO = 13,
    GLOBUS_GSI_AUTHZ_ERROR_SYSTEM_CONFIG = 14,
    GLOBUS_GSI_AUTHZ_ERROR_WITH_AUTHZ_HANDLE_ATTRS = 15,
    GLOBUS_GSI_AUTHZ_ERROR_WITH_CALLBACK_DATA = 17,
    GLOBUS_GSI_AUTHZ_ERROR_NO_AUTHZ_FOUND = 20,
    GLOBUS_GSI_AUTHZ_ERROR_SUBJECT_CMP = 21,
    GLOBUS_GSI_AUTHZ_ERROR_GETTING_SERVICE_NAME = 22,
    GLOBUS_GSI_AUTHZ_ERROR_BAD_PARAMETER = 23,
    GLOBUS_GSI_AUTHZ_ERROR_LAST = 24
} globus_gsi_authz_error_t;

#endif

