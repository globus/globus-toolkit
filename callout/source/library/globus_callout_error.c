/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_callout_error.c
 * Globus Callout Infrastructure
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_callout_constants.h"
#include "globus_i_callout.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

char * 
globus_l_callout_error_strings[GLOBUS_CALLOUT_ERROR_LAST] =
{

/* 0 */   "Success",
/* 1 */   "Error with hash table",
/* 2 */   "Error opening configuration file",
/* 3 */   "Error parsing configuration file",
/* 4 */   "Error with dynamic library",
/* 5 */   "Out of memory",
/* 6 */   "The callout type has not been configured",
/* 7 */   "The callout returned an error"
};

/* ERROR FUNCTIONS */

globus_result_t
globus_i_callout_error_result(
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
        "globus_i_callout_error_result";

    GLOBUS_I_CALLOUT_DEBUG_ENTER;

    error_object = globus_error_construct_error(
        GLOBUS_CALLOUT_MODULE,
        NULL,
        error_type,
        filename,
        function_name,
        line_number,
        "%s%s%s",
        globus_l_callout_error_strings[error_type],
        short_desc ? ": " : "",
        short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_CALLOUT_DEBUG_EXIT;

    return result;
}

globus_result_t
globus_i_callout_error_chain_result(
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
        "globus_i_callout_error_chain_result";
    
    GLOBUS_I_CALLOUT_DEBUG_ENTER;
    
    error_object =
        globus_error_construct_error(
            GLOBUS_CALLOUT_MODULE,
            globus_error_get(chain_result),
            error_type,
            filename,
            function_name,
            line_number,
            "%s%s%s",
            globus_l_callout_error_strings[error_type],
            short_desc ? ": " : "",
            short_desc ? short_desc : "");

    if(long_desc)
    {
        globus_error_set_long_desc(error_object, long_desc);
    }

    result = globus_error_put(error_object);

    GLOBUS_I_CALLOUT_DEBUG_EXIT;
    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
