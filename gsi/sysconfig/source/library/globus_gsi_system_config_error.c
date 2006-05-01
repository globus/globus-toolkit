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
 * @file globus_gsi_system_config_error.c
 * Globus GSI System Config Library
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_error_openssl.h"
#include "globus_i_gsi_system_config.h"
#include "globus_gsi_system_config_constants.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

char * 
globus_l_gsi_sysconfig_error_strings[GLOBUS_GSI_SYSCONFIG_ERROR_LAST] =
{
/* 0 */   "Success",
/* 1 */   "Could not find a valid trusted CA certificates directory",
/* 2 */   "Error with certificate filename",
/* 3 */   "Error with key filename",
/* 4 */   "Could not find a valid home directory for the current user",
/* 5 */   "Error with system call",
/* 6 */   "Error checking the status of a file",
/* 7 */   "Could not find a valid certificate file",
/* 8 */   "Could not find a valid proxy certificate file location",
/* 9 */   "Could not find a valid delegated proxy certificate file location",
/* 10 */  "Error getting the list of trusted CA certificates",
/* 11 */  "Error getting the current working directory",
/* 12 */  "Error removing all owned files from secure tmp directory",
/* 13 */  "Could not find a valid gridmap file",
/* 14 */  "Error checking superuser status",
/* 15 */  "Error setting file permissions",
/* 16 */  "Error getting signing policy file",
/* 17 */  "Error getting password entry for current user",
/* 18 */  "Could not find a valid authorization callback config file",
/* 19 */  "Not a regular file",
/* 20 */  "File does not exist",
/* 21 */  "File has bad permissions",
/* 22 */  "File is not owned by current user",
/* 23 */  "File is a directory",
/* 24 */  "File has zero length",
/* 25 */  "Invalid argument",
/* 26 */  "File has more than one link, i.e. file may be a hard link",
/* 27 */  "File changed while trying to set permissions",
/* 28 */  "Could not find a valid authorization callout library configuration file",
/* 29 */  "Could not find a valid  GAA configuration file",
/* 30 */  "File is not a directory"
};
/* @} */ 


/* ERROR FUNCTIONS */

globus_result_t
globus_i_gsi_sysconfig_openssl_error_result(
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
        "globus_i_gsi_sysconfig_openssl_error_result";
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    error_object = 
        globus_error_wrap_openssl_error(
            GLOBUS_GSI_SYSCONFIG_MODULE,
            error_type,
            filename,
            function_name,
            line_number,
            "%s%s%s",
            _GSSL(globus_l_gsi_sysconfig_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");    

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_i_gsi_sysconfig_error_result(
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
        "globus_i_gsi_sysconfig_error_result";

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;

    error_object = globus_error_construct_error(
        GLOBUS_GSI_SYSCONFIG_MODULE,
        NULL,
        error_type,
        filename,
        function_name,
        line_number,
        "%s%s%s",
        _GSSL(globus_l_gsi_sysconfig_error_strings[error_type]),
        short_desc ? ": " : "",
        short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_i_gsi_sysconfig_error_chain_result(
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
        "globus_i_gsi_sysconfig_error_chain_result";
    
    GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER;
    
    error_object =
        globus_error_construct_error(
            GLOBUS_GSI_SYSCONFIG_MODULE,
            globus_error_get(chain_result),
            error_type,
            filename,
            function_name,
            line_number,
            "%s%s%s",
            _GSSL(globus_l_gsi_sysconfig_error_strings[error_type]),
            short_desc ? ": " : "",
            short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT;

    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
















