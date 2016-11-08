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
 * @file acquire_cred.c
 * @brief Acquire Credential
 * @author Sam Meder, Sam Lang
 */
#endif

#include "gssapi.h"
#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

#include <stdlib.h>
#include <sys/stat.h>

/**
 * @brief Acquire Credential
 * @ingroup globus_gsi_gssapi
 * @details
 * GSSAPI routine to acquire the local credential.  
 * See the latest IETF draft/RFC on the GSSAPI C bindings.
 *
 * Gets the local credentials.  The proxy_init_cred does most of the
 * work of setting up the SSL_ctx, getting the user's cert, key, etc. 
 
 * The globusid will be obtained from the certificate. (Minus
 * and /CN=proxy entries.)
 *
 * @param minor_status
 *        Mechanism specific status code. In this implementation,
 *        the minor_status is a cast from a globus_result_t value, which
 *        is either GLOBUS_SUCCESS or a globus error object ID if an error
 *        occurred.
 * @param desired_name_P
 *        Name of principle whose credentials should be acquired
 *        This parameter maps to the desired subject of the cert
 *        to be acquired as the credential.  Possible values are:
 *        - For a service cert:  <em>service name</em>\@<em>fqdn</em>
 *        - For a host cert:     <em>fqdn</em>
 *        - For a proxy cert:    <em>subject name</em>
 *        - For a user cert:     <em>subject name</em>
 *        This parameter can be NULL, in which case the cert is chosen
 *        using a default search order of: host, proxy, user, service
 * @param time_req
 *        Number of seconds that credentials should remain valid.
 *        This value can be GSS_C_INDEFINITE for an unlimited lifetime.
 *        NOTE: in the current implementation, this parameter is ignored,
 *        since you can't change the expiration of a signed cert.
 *        
 * @param desired_mechs
 * @param cred_usage
 * @param output_cred_handle_P
 * @param actual_mechs
 * @param time_rec
 */
OM_uint32 
GSS_CALLCONV gss_acquire_cred(
    OM_uint32 *                         minor_status,
    const gss_name_t                    desired_name_P,
    OM_uint32                           time_req,
    const gss_OID_set                   desired_mechs,
    gss_cred_usage_t                    cred_usage,
    gss_cred_id_t *                     output_cred_handle_P,
    gss_OID_set *                       actual_mechs,
    OM_uint32 *                         time_rec) 
{
    char *                              desired_name_string = NULL;
    OM_uint32                           major_status = GSS_S_NO_CRED;
    OM_uint32                           local_minor_status;
    X509_NAME *                         desired_name = NULL;
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    *output_cred_handle_P = NULL;
  
    /* module activation if not already done by calling
     * globus_module_activate
     */
    
    globus_thread_once(
        &once_control,
        globus_l_gsi_gssapi_activate_once);

    globus_mutex_lock(&globus_i_gssapi_activate_mutex);
    if (!globus_i_gssapi_active)
    {
        globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    }
    globus_mutex_unlock(&globus_i_gssapi_activate_mutex);

    if(desired_name_P)
    {
        desired_name = ((gss_name_desc *)desired_name_P)->x509n;
    }

    major_status = globus_i_gsi_gss_cred_read(
        &local_minor_status,
        cred_usage,
        output_cred_handle_P,
        desired_name);

    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        goto error;
    }

    if (time_rec != NULL)
    {
        time_t                          lifetime;
        globus_result_t                 result;                
        
        result = globus_gsi_cred_get_lifetime(
            ((gss_cred_id_desc *) *output_cred_handle_P)->cred_handle,
            &lifetime);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto error;
        }
        
        *time_rec = (OM_uint32) lifetime;
    }
    
    if(desired_name_string)
    {
        free(desired_name_string);
    }

    /* Use new mech OID if present */
    if (desired_mechs != NULL)
    {
        int present = 0;

        if (desired_mechs->count > 1)
        {
            major_status = GSS_S_FAILURE;
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH);
            goto error;
        }

        if ((gss_test_oid_set_member(&local_minor_status,
                         (const gss_OID) gss_mech_globus_gssapi_openssl_micv2,
                         desired_mechs, &present) == GSS_S_COMPLETE) && present)
        {
            (*output_cred_handle_P)->mech = (const gss_OID)gss_mech_globus_gssapi_openssl_micv2;
        }
        else if ((gss_test_oid_set_member(&local_minor_status,
                         (const gss_OID) gss_mech_globus_gssapi_openssl,
                         desired_mechs, &present) == GSS_S_COMPLETE) && present)
        {
            (*output_cred_handle_P)->mech = (const gss_OID)gss_mech_globus_gssapi_openssl;
        }
        else
        {
            major_status = GSS_S_FAILURE;
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH);
            goto error;
        }
    } else if (globus_i_backward_compatible_mic)
    {
            (*output_cred_handle_P)->mech = (const gss_OID)gss_mech_globus_gssapi_openssl;
    } else
    {
            (*output_cred_handle_P)->mech = (const gss_OID)gss_mech_globus_gssapi_openssl_micv2;
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        2, (globus_i_gsi_gssapi_debug_fstream,
            "acquire_cred: %s\n",
            ((*output_cred_handle_P)->mech == GSS_C_NO_OID)? "NO MECH OID":
            ((g_OID_equal((*output_cred_handle_P)->mech, (gss_OID) gss_mech_globus_gssapi_openssl))?
              "OLD MECH OID":
             ((g_OID_equal((*output_cred_handle_P)->mech, (gss_OID) gss_mech_globus_gssapi_openssl_micv2))?
              "MICV2 MECH OID": "UNKNOWN MECH OID"))));
    
    if (actual_mechs != NULL)
    {
        if ((*output_cred_handle_P)->mech != GSS_C_NO_OID)
        {
            major_status = gss_create_empty_oid_set(&local_minor_status, actual_mechs);
            if (major_status == GSS_S_COMPLETE)
                major_status = gss_add_oid_set_member(&local_minor_status,
                                  (*output_cred_handle_P)->mech, actual_mechs);
        } else
            major_status = gss_indicate_mechs(&local_minor_status,
                                          actual_mechs);
        if (GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH);
            goto error;
        }
    }

    goto exit;

 error:

    if(desired_name_string)
    {
        free(desired_name_string);
    }

    if(*output_cred_handle_P)
    {
        gss_release_cred(
            &local_minor_status, 
            output_cred_handle_P);
    }

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
