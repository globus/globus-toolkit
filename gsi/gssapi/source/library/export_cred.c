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
 * @file export_cred.c
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "globus_gsi_gss_constants.h"
#include "globus_gsi_system_config.h"
#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"
#include <string.h>

/* Only build if we have the extended GSSAPI */
#ifdef  _HAVE_GSI_EXTENDED_GSSAPI

/**
 * @name Export Cred
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Saves the credential so it can be checkpointed and 
 * imported by gss_import_cred
 *
 * @param minor_status
 * @param cred_handle
 * @param desired_mech
 *        Should either be @ref gss_mech_globus_gssapi_openssl or
 *        NULL (in which case gss_mech_globus_gssapi_openssl is
 *        assumed).
 * @param option_req
 * @param export_buffer
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_export_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    gss_buffer_t                        export_buffer)
{
    OM_uint32                           major_status = GLOBUS_SUCCESS;
    BIO *                               bp = NULL;
    gss_cred_id_desc *                  cred_desc = NULL;
    globus_result_t                     local_result;
    char *                              proxy_filename = NULL;
    static char *                       _function_name_ =
        "gss_export_cred";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    cred_desc = (gss_cred_id_desc *) cred_handle;
    
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if (export_buffer == NULL ||
        export_buffer == GSS_C_NO_BUFFER)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("NULL or emtpy export_buffer parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }

    export_buffer->length = 0;
    export_buffer->value = NULL;

    if (cred_handle == NULL)
    { 
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("NULL or emtpy export_buffer parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(desired_mech != NULL &&
       g_OID_equal(desired_mech, (gss_OID) gss_mech_globus_gssapi_openssl))
    {
        major_status = GSS_S_BAD_MECH;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH,
            (_GGSL("The desired mechanism of: %s, is not supported by this "
             "GSS implementation"), desired_mech->elements));
        goto exit;
    }

    if(option_req == GSS_IMPEXP_OPAQUE_FORM)
    {
        /* When option_req is equal to EXPORT_OPAQUE_FORM (0), it exports
         * an opaque buffer suitable for storage in memory or on  
         * disk or passing to another process, which 
         * can import the buffer with gss_import_cred().
         */
        bp = BIO_new(BIO_s_mem());
        if(bp == NULL)
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                (_GGSL("Couldn't initialize IO bio for exporting credential")));
            major_status = GSS_S_FAILURE;
            goto exit;
        }

	local_result = globus_gsi_cred_write(cred_desc->cred_handle, bp);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL);
            major_status = GSS_S_FAILURE;
            goto exit;
        }            
		
        export_buffer->length = BIO_pending(bp);
		
        if (export_buffer->length > 0)
        {
            export_buffer->value = (char *) malloc(export_buffer->length);
            if (export_buffer->value == NULL)
            {
                export_buffer->length = 0;
                GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
                major_status = GSS_S_FAILURE;
                goto exit;
            }
			
            BIO_read(bp, export_buffer->value, export_buffer->length);
        }
        else
        {
            export_buffer->value = NULL;
        }

        major_status = GSS_S_COMPLETE;
    }
    else if(option_req == GSS_IMPEXP_MECH_SPECIFIC)
    {
        /* With option_req is equal to EXPORT_MECH_SPECIFIC (1), 
         * it exports a buffer filled with mechanism-specific 
         * information that the calling application can use 
         * to pass the credentials to another process that 
         * is not written to the GSS-API.
         */
        local_result = 
            GLOBUS_GSI_SYSCONFIG_GET_UNIQUE_PROXY_FILENAME(&proxy_filename);
        if(local_result != GLOBUS_SUCCESS)
        {
            proxy_filename = NULL;
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            3, (globus_i_gsi_gssapi_debug_fstream,
                "Writing exported cred to: %s", proxy_filename));

        local_result = globus_gsi_cred_write_proxy(cred_desc->cred_handle,
                                                   proxy_filename);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
            major_status = GSS_S_FAILURE;
            goto exit;
        }                                       

        export_buffer->value = globus_common_create_string(
            "X509_USER_PROXY=%s",
            proxy_filename);
        export_buffer->length = strlen((char *) export_buffer->value);
    }
    else
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Unrecognized option_req of: %d"), option_req));
        goto exit;
    }

 exit:

    if(proxy_filename != NULL)
    { 
        free(proxy_filename);
    }
    
    if (bp) 
    {
        BIO_free(bp);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

#endif /*  _HAVE_GSI_EXTENDED_GSSAPI */
