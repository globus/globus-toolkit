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
 * @file release_name.c
 * @author Sam Meder, Sam Lang
 */
#endif

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

/**
 * @brief GSS Release Name
 * @ingroup globus_gsi_gssapi
 * @details
 * Release the GSS Name
 *
 * @param minor_status
 *        The minor status result - this is a globus_result_t
 *        cast to a (OM_uint32 *).
 * @param name_P
 *        The GSSAPI name to be released
 * @retval GSS_S_COMPLETE Success
 * @retval GSS_S_FAILURE Failure
 */
OM_uint32 
GSS_CALLCONV gss_release_name(
    OM_uint32 *                         minor_status,
    gss_name_t *                        name_P)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_name_desc** name = (gss_name_desc**) name_P ;

    static char *                       _function_name_ =
        "gss_release_name";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    if (name == NULL || minor_status == NULL || 
        *name == NULL || *name == GSS_C_NO_NAME)
    {
        major_status = GSS_S_FAILURE;

        if (minor_status != NULL)
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
                    (_GGSL("Invalid parameter")));
        }

        goto exit;
    } 
    
    if ((*name)->x509n)
    {
        X509_NAME_free((*name)->x509n);
    }
    if ((*name)->x509n_oneline)
    {
        OPENSSL_free((*name)->x509n_oneline);
    }
    if ((*name)->subjectAltNames)
    {
        sk_GENERAL_NAME_pop_free((*name)->subjectAltNames, GENERAL_NAME_free);
    }
    if ((*name)->user_name)
    {
        free((*name)->user_name);
    }
    if ((*name)->service_name)
    {
        free((*name)->service_name);
    }
    if ((*name)->host_name)
    {
        free((*name)->host_name);
    }
    if ((*name)->ip_address)
    {
        free((*name)->ip_address);
    }
    if ((*name)->ip_name)
    {
        free((*name)->ip_name);
    }

    free(*name);
    *name = GSS_C_NO_NAME;
    
 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
    
} 
/* gss_release_name */
