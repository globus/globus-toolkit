#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_cred_error.c
 * Globus GSI Credential Library
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gsi_credential.h"
#include "globus_gsi_cred_constants.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

char * 
globus_l_gsi_cred_error_strings[GLOBUS_GSI_CRED_ERROR_LAST] =
{

/* 0 */   "Success",
/* 1 */   "Error Reading Proxy Credential",
/* 2 */   "Error Reading Host Credential",
/* 3 */   "Error Reading Service Credential",
/* 4 */   "Error Reading Credential",
/* 5 */   "Error Writing Credential",
/* 6 */   "Error Writing Proxy Credential",
/* 7 */   "Error Checking For Proxy Credential",
/* 8 */   "Error Verifying Credential",
/* 9 */   "Error with Credential",
/* 10 */  "Error with Credential's Certificate",
/* 11 */  "Error with Credential's Private Key",
/* 12 */  "Error with Credential's Cert Chain",
/* 13 */  "System Error",
/* 14 */  "Error with System Configuration",
/* 15 */  "Error with Credential Handle Attributes",
/* 16 */  "Error with Credential's SSL context"
};

/* ERROR FUNCTIONS */

globus_result_t
globus_i_gsi_cred_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_cred_openssl_error_result";
    
    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    error_object = 
        globus_error_wrap_openssl_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            error_type,
            "%s:%d: %s: %s",
            filename,
            line_number,
            function_name,
            globus_l_gsi_cred_error_strings[error_type]);    

    globus_error_set_long_desc(error_object, long_desc);

    result = globus_error_put(error_object);
    
    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_i_gsi_cred_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_cred_error_result";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    error_object = globus_error_construct_error(
        GLOBUS_GSI_CREDENTIAL_MODULE,
        NULL,
        error_type,
        "%s:%d: %s: %s",
        filename, line_number, function_name, 
        globus_l_gsi_cred_error_strings[error_type]);

    globus_error_set_long_desc(error_object, long_desc);

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_i_gsi_cred_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_credential_error_chain_result";
    
    GLOBUS_I_GSI_CRED_DEBUG_ENTER;
    
    error_object =
        globus_error_construct_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            globus_error_get(chain_result),
            error_type,
            "%s:%d: %s: %s",
            filename, line_number, function_name, 
            globus_l_gsi_cred_error_strings[error_type]);

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
