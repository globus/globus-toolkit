#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file release_buffer.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */

static char *rcsid = "$Id$";

#include "gssapi_openssl.h"

OM_uint32 
GSS_CALLCONV gss_release_buffer(
    OM_uint32 *                         minor_status,
    gss_buffer_t                        buffer)
{
    static char *                       _function_name_ =
        "gss_release_buffer";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if (buffer == NULL || buffer == GSS_C_NO_BUFFER) {
        goto exit;
    }

    if (buffer->value && buffer->length) {
        free(buffer->value);
    }

    buffer->length = (size_t) 0 ;
    buffer->value = NULL;

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return GSS_S_COMPLETE;

} 
/* gss_release_buffer */
/* @} */
