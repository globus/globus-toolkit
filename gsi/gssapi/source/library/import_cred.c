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
 * @file import_cred.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"
#include <string.h>

/* Only build if we have the extended GSSAPI */
#ifdef  _HAVE_GSI_EXTENDED_GSSAPI

static char *rcsid = "$Id$";

/**
 * @name Import Cred
 * @ingroup globus_gsi_gssapi_extensions
 */
/* @{ */
/**
 * Import a credential that was exported by gss_export_cred().
 *
 * This function will import credentials exported by
 * gss_export_cred(). It is intended to allow a multiple use
 * application to checkpoint delegated credentials.  
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param output_cred_handle
 *        Upon success, this paramter will contain the imported
 *        credential. When no longer needed this credential should be
 *        freed using gss_release_cred().
 * @param desired_mech
 *        This paramter may be used to specify the desired security
 *        mechanism. May be GSS_C_NO_OID.
 * @param option_req
 *        This paramater indicates which option_req value was used to
 *        produce the import_buffer.
 * @param import_buffer
 *        A buffer produced by gss_export_credential().
 * @param time_req
 *        The requested period of validity (seconds) for the imported
 *        credential. May be NULL.
 * @param time_rec
 *        This parameter will contain the received period of validity
 *        of the imported credential upon success. May be NULL.
 * @return
 *        GSS_S_COMPLETE         upon successful completion
 *        GSS_S_BAD_MECH         if the requested security mechanism
 *                               is unavailable
 *        GSS_S_DEFECTIVE_TOKEN  if the import_buffer is defective
 *        GSS_S_FAILURE          upon general failure
 */
OM_uint32 
GSS_CALLCONV gss_import_cred(
    OM_uint32 *                         minor_status,
    gss_cred_id_t *                     output_cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    const gss_buffer_t                  import_buffer,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec)
{
    globus_result_t                     local_result = GLOBUS_SUCCESS;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    BIO *                               bp = NULL;
    char *                              filename;
    FILE *                              fp;

    static char *                       _function_name_ =
        "gss_import_cred";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    /* module activation if not already done by calling
     * globus_module_activate
     */
    globus_thread_once(
        &once_control,
        globus_l_gsi_gssapi_activate_once);
    
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if (import_buffer == NULL ||
        import_buffer ==  GSS_C_NO_BUFFER ||
        import_buffer->length < 1) 
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, 
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid import_buffer passed to function: %s"),
             _function_name_));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if (output_cred_handle == NULL )
    { 
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid output_cred_handle parameter passed to function: %s"),
             _function_name_));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if(desired_mech != NULL &&
       desired_mech != (gss_OID) gss_mech_globus_gssapi_openssl)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH,
            (_GGSL("The desired_mech: %s, is not supported"),
             ((gss_OID_desc *)desired_mech)->elements));
        major_status = GSS_S_BAD_MECH;
        goto exit;
    }
    
    if (import_buffer->length > 0)
    {
        if(option_req == GSS_IMPEXP_OPAQUE_FORM)
        {
            bp = BIO_new(BIO_s_mem());
            
            BIO_write(bp,
                      import_buffer->value,
                      import_buffer->length);
        }
        else if(option_req == GSS_IMPEXP_MECH_SPECIFIC) 
        {
            filename = strchr((char *) import_buffer->value, '=');

            if(filename == NULL)
            {
                GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
                    (_GGSL("Import buffer does not contain a =")));
                major_status = GSS_S_FAILURE;
                goto exit;
            }
            
            filename++;
            
            if ((fp = fopen(filename,"r")) == NULL)
            {
                GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_IMPORT_FAIL,
                    (_GGSL("Couldn't open the file: %s"),
                     filename));
                major_status = GSS_S_FAILURE;
                goto exit;
            }
            
            bp = BIO_new(BIO_s_file());
            BIO_set_fp(bp, fp, BIO_CLOSE);
        }
        else
        {
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
                (_GGSL("Invalid option req of: %d, not supported"),
                 option_req));
            major_status = GSS_S_FAILURE;
            goto exit;
        }
    }
    else
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
            (_GGSL("Invalid token passed to function")));
        major_status = GSS_S_DEFECTIVE_TOKEN;
        goto exit;
    }
    
    major_status = globus_i_gsi_gss_cred_read_bio(
        &local_minor_status,
        GSS_C_BOTH,
        output_cred_handle,
        bp);

    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPORT_FAIL);
        goto exit;
    }
    
    /* If I understand this right, time_rec should contain the time
     * until the cert expires */    
    if (time_rec != NULL)
    {
        local_result = globus_gsi_cred_get_lifetime(
            ((gss_cred_id_desc *) *output_cred_handle)->cred_handle,
            (time_t *) time_rec);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
    }
        
 exit:
    if (bp) 
    {
        BIO_free(bp);
    }
    return major_status;
}
/* @} */

#endif /* _HAVE_GSI_EXTENDED_GSSAPI */
