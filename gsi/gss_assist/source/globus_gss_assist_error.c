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

#include "globus_common.h"
#include "globus_i_gss_assist.h"
#include "globus_gss_assist_constants.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

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
/* 17 */   "Caller provided insufficient buffer space for local identity"
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
        "%s:%d: %s: %s%s%s",
        filename, line_number, function_name,
        globus_l_gsi_gss_assist_error_strings[error_type],
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
            "%s:%d: %s: %s%s%s",
            filename, line_number, function_name,
            globus_l_gsi_gss_assist_error_strings[error_type],
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
