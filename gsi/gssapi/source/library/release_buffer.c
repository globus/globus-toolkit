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
 * @file release_buffer.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

/**
 * @name Release Buffer
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * 
 * @param minor_status
 * @param buffer
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_release_buffer(
    OM_uint32 *                         minor_status,
    gss_buffer_t                        buffer)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
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
    return major_status;

} 
/* gss_release_buffer */
/* @} */
