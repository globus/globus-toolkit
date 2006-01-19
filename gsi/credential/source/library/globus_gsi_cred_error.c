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
/* 1 */   "Error reading proxy credential",
/* 2 */   "Error reading host credential",
/* 3 */   "Error reading service credential",
/* 4 */   "Error reading user credential",
/* 5 */   "Error writing credential",
/* 6 */   "Error writing proxy credential",
/* 7 */   "Error checking for proxy credential",
/* 8 */   "Error verifying credential",
/* 9 */   "Error with credential",
/* 10 */  "Error with credential's certificate",
/* 11 */  "Error with credential's private key",
/* 12 */  "Error with credential's cert chain",
/* 13 */  "System error",
/* 14 */  "Error with system configuration",
/* 15 */  "Error with credential handle attributes",
/* 16 */  "Error with credential's SSL context",
/* 17 */  "Error with callback data",
/* 18 */  "Error creating two errors from one",
/* 19 */  "Key is password protected",
/* 20 */  "Valid credentials could not be found in any of the"
          " possible locations specified by the credential search order.",
/* 21 */  "Error comparing subject names.",
/* 22 */  "Error determining service name.",
/* 23 */  "Bad parameter",
/* 24 */  "Error with credential's certificate name"
};

/* ERROR FUNCTIONS */

globus_result_t
globus_i_gsi_cred_openssl_error_result(
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
        "globus_i_gsi_cred_openssl_error_result";
    
    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    error_object = 
        globus_error_wrap_openssl_error(
            GLOBUS_GSI_CREDENTIAL_MODULE,
            error_type,
            filename,
            function_name,
            line_number,
            "%s%s%s",
            _GCRSL(globus_l_gsi_cred_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");    

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

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
    const char *                        short_desc,
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
        filename,
        function_name,
        line_number, 
        "%s%s%s",
        _GCRSL(globus_l_gsi_cred_error_strings[error_type]),
        short_desc ? ": " : "",
        short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

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
    const char *                        short_desc,
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
            filename,
            function_name,
            line_number, 
            "%s%s%s",
            _GCRSL(globus_l_gsi_cred_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_i_gsi_cred_error_join_chains_result(
    globus_result_t                     outter_error,
    globus_result_t                     inner_error)
{
    globus_result_t                     result;
    globus_object_t *                   result_error_obj = NULL;
    globus_object_t *                   outter_error_obj = NULL;
    globus_object_t *                   inner_error_obj = NULL;
    globus_object_t *                   temp_error_obj = NULL;
    static char *                       _function_name_ =
        "globus_i_gsi_cred_error_join_chains";
    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    outter_error_obj = globus_error_get(outter_error);
    inner_error_obj = globus_error_get(inner_error);
    if(outter_error_obj && inner_error_obj)
    {
        temp_error_obj = outter_error_obj;
        while(globus_error_get_cause(temp_error_obj))
        {
            temp_error_obj = globus_error_get_cause(temp_error_obj);
        }

        temp_error_obj = globus_error_initialize_base(temp_error_obj,
                                                      globus_error_get_source(temp_error_obj),
                                                      inner_error_obj);
        result_error_obj = outter_error_obj;
    }
    else if(inner_error_obj)
    {
        result_error_obj = inner_error_obj;
    }
    else
    {
        result_error_obj = 
            globus_error_construct_error(
                GLOBUS_GSI_CREDENTIAL_MODULE,
                NULL,
                GLOBUS_GSI_CRED_ERROR_CREATING_ERROR_OBJ,
                __FILE__,
                _function_name_,
                __LINE__,
                "Couldn't join inner and outter error chains");
    }

    result = globus_error_put(result_error_obj);

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
