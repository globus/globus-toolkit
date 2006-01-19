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
 * @file inquire_cred.h
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi.h"
#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

/**
 * @name Inquire Cred
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Get information about the current credential
 *
 * We will also allow the return of the proxy file name,
 * if the minor_status is set to a value of 57056 0xdee0
 * This is done since there is no way to pass back the delegated
 * credential file name. 
 *
 * When 57056 is seen, this will cause a new copy of this
 * credential to be written, and it is the user's responsibility
 * to free the file when done. 
 * The name will be a pointer to a char * of the file name
 * which must be freeed. The minor_status will be set to 
 * 57057 0xdee1 to indicate this. 
 *     
 * DEE - this is a kludge, till the GSSAPI get a better way 
 * to return the name. 
 * 
 * If the minor status is not changed from 57056 to 57057
 * assume it is not this gssapi, and a gss name was returned. 
 *
 * @param minor_status
 * @param cred_handle_P
 * @param name
 * @param lifetime
 * @param cred_usage
 * @param machanisms
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_inquire_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle_P,
    gss_name_t *                        name,
    OM_uint32 *                         lifetime,
    gss_cred_usage_t *                  cred_usage,
    gss_OID_set *                       mechanisms) 
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    OM_uint32                           local_major_status;
    globus_result_t                     local_result;
    gss_cred_id_desc *                  cred_handle =
        (gss_cred_id_desc *)cred_handle_P;

    static char *                       _function_name_ =
        "gss_inquire_cred";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if (cred_handle == GSS_C_NO_CREDENTIAL)
    {
        local_major_status = gss_acquire_cred(
            &local_minor_status,
            NULL,
            GSS_C_INDEFINITE,
            GSS_C_NO_OID_SET,
            GSS_C_BOTH,
            (gss_cred_id_t *) &cred_handle,
            NULL,
            NULL);

        if(GSS_ERROR(local_major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_NO_CRED;
            return major_status;
        }
    }

    if (mechanisms != NULL)
    {
        *mechanisms = GSS_C_NO_OID_SET;
    }

    if (cred_usage != NULL)
    {
        *cred_usage = cred_handle->cred_usage;
    }

    if(lifetime != NULL)
    {
        time_t                      temp_lifetime;
        local_result = globus_gsi_cred_get_lifetime(
            cred_handle->cred_handle,
            &temp_lifetime);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
        *lifetime = (OM_uint32) temp_lifetime;
    }

    if(name != NULL)
    {
        major_status = globus_i_gsi_gss_copy_name_to_name(
            &local_minor_status,
            (gss_name_desc **) name,
            cred_handle->globusid);
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME);
            goto exit;
        }
    }        
    
 exit:
        
    if(cred_handle_P == GSS_C_NO_CREDENTIAL &&
       cred_handle != GSS_C_NO_CREDENTIAL)
    {
        gss_release_cred(&local_minor_status, (gss_cred_id_t *) &cred_handle);
    }
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */
