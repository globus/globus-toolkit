
#include "globus_i_gsi_proxy.h"
#include "globus_gsi_proxy_constants.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

static char * 
globus_l_gsi_proxy_error_strings[GLOBUS_GSI_PROXY_ERROR_LAST] =
{

/* 0 */   "Success",
/* 1 */   "Error with the proxy handle",
/* 2 */   "Error with the proxy handle attributes",
/* 3 */   "Error with ASN1 proxycertinfo structure",
/* 4 */   "Error with ASN1 proxyrestriction structure",
/* 5 */   "Error with ASN1 proxygroup structure",
/* 6 */   "Error with pathlength of proxyrestriction",
/* 7 */   "Error with X509 request structure",
/* 8 */   "Error with X509 structure",
/* 9 */   "Error with X509 extensions",
/* 10 */  "Error with private key",
/* 11 */  "Error with openssl's BIO handle",
/* 12 */  "Error with credential",
/* 13 */  "Error with credential handle",
/* 14 */  "Error with credential handle attributes",
/* 15 */  "System error"

};

globus_result_t
globus_i_gsi_proxy_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_proxy_openssl_error_result";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    error_object =
        globus_error_wrap_openssl_error(
            GLOBUS_GSI_PROXY_MODULE,
            error_type,
            "%s:%d: %s: %s",
            filename,
            line_number,
            function_name,
            globus_l_gsi_proxy_error_strings[error_type]);
    
    globus_error_set_long_desc(error_object, long_desc);

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
        
globus_result_t
globus_i_gsi_proxy_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_proxy_error_result";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    error_object = globus_error_construct_error(
        GLOBUS_GSI_PROXY_MODULE,
        NULL,
        error_type,
        "%s:%d: %s: %s",
        filename, line_number, function_name,
        globus_l_gsi_proxy_error_strings[error_type]);

    globus_error_set_long_desc(error_object, long_desc);

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
        
globus_result_t
globus_i_gsi_proxy_error_chain_result(
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
        "globus_i_gsi_proxy_error_chain_result";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    error_object = 
        globus_error_construct_error(
            GLOBUS_GSI_PROXY_MODULE,
            globus_error_get(chain_result),
            error_type,
            "%s:%d: %s: %s",
            filename, line_number, function_name,
            globus_l_gsi_proxy_error_strings[error_type]);
        
    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
