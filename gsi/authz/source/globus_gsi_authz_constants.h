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
    GLOBUS_GSI_AUTHZ_ERROR_SUCCESS = 0,
    GLOBUS_GSI_AUTHZ_ERROR_ERRNO = 1,
    GLOBUS_GSI_AUTHZ_ERROR_BAD_PARAMETER = 2,
    GLOBUS_GSI_AUTHZ_ERROR_CALLOUT = 3,
    GLOBUS_GSI_AUTHZ_ERROR_LAST = 4
} globus_gsi_authz_error_t;

#endif

