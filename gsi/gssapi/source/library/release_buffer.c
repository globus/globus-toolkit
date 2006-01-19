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
