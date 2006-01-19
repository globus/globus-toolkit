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
 * @file globus_gsi_callback_error.c
 * Globus GSI Callback
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif


#include "globus_i_gsi_callback.h"
#include "globus_gsi_callback_constants.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

char * 
globus_l_gsi_callback_error_strings[GLOBUS_GSI_CALLBACK_ERROR_LAST] =
{

/* 0 */   "Success",
/* 1 */   "Could not verify credential",
/* 2 */   "The certificate is not yet valid",
/* 3 */   "Can't get the local trusted CA certificate",
/* 4 */   "The certificate has expired",
/* 5 */   "Invalid proxy certificate",
/* 6 */   "Error with limited proxy certificate",
/* 7 */   "Invalid CRL",
/* 8 */   "The certificate has been revoked",
/* 9 */   "Error verifying new proxy certificate",
/* 10 */  "Error with signing policy",
/* 11 */  "Error in OLD GAA code",
/* 12 */  "Error with callback data",
/* 13 */  "System error",
/* 14 */  "Error in the certificate chain",
/* 15 */  "Error with callback data index",
/* 16 */  "Proxy path length exceeded",
/* 17 */  "Found incompatible proxy types in certificate chain"
};

/* ERROR FUNCTIONS */

globus_result_t
globus_i_gsi_callback_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_callback_openssl_error_result";
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    error_object = 
        globus_error_wrap_openssl_error(
            GLOBUS_GSI_CALLBACK_MODULE,
            error_type,
            filename,
            function_name,
            line_number,
            "%s%s%s",
            _CLS(globus_l_gsi_callback_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");    

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_i_gsi_callback_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_callback_error_result";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    error_object = globus_error_construct_error(
        GLOBUS_GSI_CALLBACK_MODULE,
        NULL,
        error_type,
        filename,
        function_name,
        line_number, 
        "%s%s%s",
        _CLS(globus_l_gsi_callback_error_strings[error_type]),
        short_desc ? ": " : "",
        short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_i_gsi_callback_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc)
{
    globus_object_t *                   error_object;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_i_gsi_callback_error_chain_result";
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
    
    error_object =
        globus_error_construct_error(
            GLOBUS_GSI_CALLBACK_MODULE,
            globus_error_get(chain_result),
            error_type,
            filename,
            function_name,
            line_number, 
            "%s%s%s",
            _CLS(globus_l_gsi_callback_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
