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
    GLOBUS_GSI_CERT_UTILS_ERROR_NON_COMPLIANT_PROXY = 7,
    GLOBUS_GSI_CERT_UTILS_ERROR_DETERMINING_CERT_TYPE = 8,
    GLOBUS_GSI_CERT_UTILS_ERROR_LAST = 9
} globus_gsi_cert_utils_error_t;


/**
 * Certificate Types.
 * @ingroup globus_gsi_cert_utils_constants
 *
 * The C version of GSI currently supports three types of proxies:
 *
 * - GLOBUS_GSI_CERT_UTILS_TYPE_EEC - a end entity certificate
 * - GLOBUS_GSI_CERT_UTILS_TYPE_CA - a CA certificate
 * - GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_PROXY - a proxy conforming
 *   to the GGF X.509 Proxy Certificate Profile document.
 * - GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY - a full globus proxy
 * - GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY - a limited globus proxy
 */

typedef enum globus_gsi_cert_utils_cert_type_e
{
    GLOBUS_GSI_CERT_UTILS_TYPE_EEC,
    GLOBUS_GSI_CERT_UTILS_TYPE_CA,
    GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY,
    GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_INDEPENDENT_PROXY,
    GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY,
    GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_RESTRICTED_PROXY,
    GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY,
    GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY
} globus_gsi_cert_utils_cert_type_t;

#endif
