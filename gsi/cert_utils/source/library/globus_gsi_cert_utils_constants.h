#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_cert_utils_constants.h
 * Globus GSI Cert Utils
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef GLOBUS_GSI_CERT_UTILS_CONSTANTS_H
#define GLOBUS_GSI_CERT_UTILS_CONSTANTS_H

/**
 * @defgroup globus_gsi_cert_utils_constants GSI Cert Utils Constants
 */
/**
 * GSI Cert Utils Error Codes
 * @ingroup globus_gsi_cert_utils_constants
 */
typedef enum
{
    GLOBUS_GSI_CERT_UTILS_ERROR_SUCCESS = 0,
    GLOBUS_GSI_CERT_UTILS_ERROR_GETTING_NAME_ENTRY_OF_SUBJECT = 1,
    GLOBUS_GSI_CERT_UTILS_ERROR_COPYING_SUBJECT = 2,
    GLOBUS_GSI_CERT_UTILS_ERROR_GETTING_CN_ENTRY = 3,
    GLOBUS_GSI_CERT_UTILS_ERROR_ADDING_CN_TO_SUBJECT = 4,
    GLOBUS_GSI_CERT_UTILS_ERROR_OUT_OF_MEMORY = 5,
    GLOBUS_GSI_CERT_UTILS_ERROR_UNEXPECTED_FORMAT = 6,
    GLOBUS_GSI_CERT_UTILS_ERROR_LAST = 7
} globus_gsi_cert_utils_error_t;

/**
 * Globus Proxy Type Enum
 * @ingroup globus_gsi_cert_utils_constants
 *
 * SLANG: This enum needs documentation
 */
typedef enum
{
    GLOBUS_ERROR_PROXY = -1,
    GLOBUS_NOT_PROXY = 0,
    GLOBUS_FULL_PROXY = 1,
    GLOBUS_LIMITED_PROXY = 2,
    GLOBUS_RESTRICTED_PROXY = 3
} globus_gsi_cert_utils_proxy_type_t;

#endif
