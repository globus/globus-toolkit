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
 * @file globus_gss_assist_error.c
 * @brief GSS Assist Error Handling
 * @author Sam Lang, Sam Meder
 */

#include "globus_common.h"
#include "globus_i_gss_assist.h"
#include "globus_gss_assist_constants.h"

char *
globus_l_gsi_gss_assist_error_strings[GLOBUS_GSI_GSS_ASSIST_ERROR_LAST] =
{

/* 0 */   "Success",
/* 1 */   "Error with arguments passed to function",
/* 2 */   "Error user ID doesn't match",
/* 3 */   "No user entry in gridmap file",
/* 4 */   "Error querying gridmap file",
/* 5 */   "Invalid gridmap file format",
/* 6 */   "System Error",
/* 7 */   "Error during context initialization",
/* 8 */   "Error during message wrap",
/* 9 */   "Error with token",
/* 10 */  "Error exporting context",
/* 11 */  "Error importing context",
/* 12 */  "Error initializing callout handle",
/* 13 */  "Error reading callout configuration",
/* 14 */  "Error invoking callout",
/* 15 */  "A GSSAPI returned an error",
/* 16 */  "Gridmap lookup failure",
/* 17 */  "Caller provided insufficient buffer space for local identity",
/* 18 */  "Failed to obtain canonical host name"
};

globus_result_t
globus_i_gsi_gss_assist_error_result(
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
        "globus_i_gsi_gss_assist_error_result";
    
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    error_object = globus_error_construct_error(
        GLOBUS_GSI_GSS_ASSIST_MODULE,
        NULL,
        error_type,
        filename,
        function_name,
        line_number, 
        "%s%s%s",
        _GASL(globus_l_gsi_gss_assist_error_strings[error_type]),
        short_desc ? ": " : "",
        short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_i_gsi_gss_assist_error_chain_result(
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
        "globus_i_gsi_gss_assist_error_chain_result";

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    error_object = 
        globus_error_construct_error(
            GLOBUS_GSI_GSS_ASSIST_MODULE,
            globus_error_get(chain_result),
            error_type,
            filename,
            function_name,
            line_number, 
            "%s%s%s",
            _GASL(globus_l_gsi_gss_assist_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return result;
}
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
