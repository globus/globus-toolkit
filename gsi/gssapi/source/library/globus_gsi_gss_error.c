#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_gssapi_error.h
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gsi_gss_utils.h"
#include "globus_gsi_gss_constants.h"
#include "globus_error_openssl.h"

char *
globus_l_gsi_gssapi_error_strings[GLOBUS_GSI_GSSAPI_ERROR_LAST] =
{

/* 0 */   "SSLv3 handshake problems",
/* 1 */   "globusid not found",
/* 2 */   "getting cert subject name",
/* 3 */   "Mutual authentication failed",
/* 4 */   "internal problem with SSL BIO",
/* 5 */   "Peer is using (limited) proxy",
/* 6 */   "Failed to receive proxy request",
/* 7 */   "Bad argument",
/* 8 */   "Internal SSL problem",
/* 9 */   "Cipher not available",
/* 10 */  "Token is wrong length",
/* 11 */  "Error with gss credential handle",
/* 12 */  "Unable to marshal credential for export",
/* 13 */  "Unable to read credential for import",
/* 14 */  "Input Error",
/* 15 */  "Output Error",
/* 16 */  "Error with gss context",
/* 17 */  "Not in expected Format",
/* 18 */  "Error with GSI proxy",
/* 19 */  "Error with GSS credential",
/* 20 */  "Cannot verify message date",
/* 21 */  "Requested mechanism not supported",
/* 22 */  "Unable to add extension",
/* 23 */  "remote side did not "
          "like my creds for unknown reason\n     "
          "check server logs for details",
/* 24 */  "Out of memory",
/* 25 */   "Bad GSS name",
/* 26 */  "Cert chain not in signing order",

};

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @defgroup globus_i_gsi_gssapi_error Internal GSS-API Error Functions
 */
globus_result_t
globus_i_gsi_gssapi_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_gssapi_openssl_error_result";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    error_object =
        globus_error_wrap_openssl_error(
            GLOBUS_GSI_GSSAPI_MODULE,
            error_type,
            "%s:%d: %s: %s",
            filename,
            line_number,
            function_name,
            globus_l_gsi_gssapi_error_strings[error_type]);
    
    globus_error_set_long_desc(error_object, long_desc);

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_i_gsi_gssapi_error_result(
    const OM_uint32                     major_status,
    const OM_uint32                     minor_status,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_gssapi_error_result";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    error_object =
        globus_error_wrap_gssapi_error(
            GLOBUS_GSI_GSSAPI_MODULE,
            major_status,
            GLOBUS_GSI_GSSAPI_ERROR_MINOR_STATUS(minor_status),
            minor_status,
            "%s:%d: %s: %s",
            filename, line_number, function_name,
            globus_l_gsi_gssapi_error_strings[minor_status]);

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return result;
}
    
globus_result_t
globus_i_gsi_gssapi_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc)
{
    globus_result_t                     result;
    globus_object_t *                   error_object;
    
    static char *                       _function_name_ =
        "globus_i_gsi_gssapi_error_chain_result";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    error_object = 
        globus_error_construct_error(
            GLOBUS_GSI_GSSAPI_MODULE,
            globus_error_get(chain_result),
            error_type,
            "%s:%d: %s: %s",
            filename, line_number, function_name,
            globus_l_gsi_gssapi_error_strings[error_type]);
        
    globus_error_set_long_desc(error_object, long_desc);
    
    result = globus_error_put(error_object);

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
