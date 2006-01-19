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
 * @file display_name.c
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi.h"
#include "globus_i_gsi_gss_utils.h"
#include "gssapi_openssl.h"
#include <string.h>

#define GSS_I_ANON_NAME "<anonymous>"

/**
 * @name Display Name
 * @ingroup globus_gsi_gssapi
 *
 * Produces a single line version of the internal x509 name
 *
 * @param minor_status 
 * @param input_name_P
 * @param output_name
 * @param output_name_type
 *
 * @return 
 */
OM_uint32 
GSS_CALLCONV 
gss_display_name(
    OM_uint32 *                         minor_status,
    const gss_name_t                    input_name_P,
    gss_buffer_t                        output_name,
    gss_OID *                           output_name_type)
{
    OM_uint32                           major_status;

    const gss_name_desc*                input_name = 
                                        (gss_name_desc*) input_name_P;
    static char *                       _function_name_ =
        "gss_display_name";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if (!(input_name) ||
        (!(input_name->x509n) &&
         !g_OID_equal(input_name->name_oid,
                      GSS_C_NT_ANONYMOUS)) ||
        !(output_name)) {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, 
            GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME,
            (NULL));
        goto exit;
    }

    if(!g_OID_equal(input_name->name_oid, GSS_C_NT_ANONYMOUS))
    {
#ifdef WIN32
        /* On Windows allocating memory with X509_NAME_oneline() and freeing
           it with free() causes an Assertion */
        char *value = NULL;
        size_t length = 0;
        value = X509_NAME_oneline(input_name->x509n, NULL, 0);
        if(value)
        {
            length = strlen((char *) value)+1;
            output_name->value = malloc(length);
            if(output_name->value)
            {
                memcpy(output_name->value,value,length);
                output_name->length = length;
                X509_free(value);
            }
            else
            {
                output_name->value = (void *) strdup(GSS_I_ANON_NAME);
                output_name->length = strlen(GSS_I_ANON_NAME);
            }
        }
        else
        {
            output_name->value = (void *) strdup(GSS_I_ANON_NAME);
            output_name->length = strlen(GSS_I_ANON_NAME);
        }
#else
        output_name->value = X509_NAME_oneline(input_name->x509n, NULL, 0);
        output_name->length = strlen((char *) output_name->value);
#endif
    }
    else
    {
        output_name->value = (void *) strdup(GSS_I_ANON_NAME);
        output_name->length = strlen(GSS_I_ANON_NAME);
    }
  
    if(output_name_type)
    {
        *output_name_type = input_name->name_oid;
    }

    major_status = GSS_S_COMPLETE;

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
} 
/* gss_display_name */
/* @} */
