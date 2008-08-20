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

#include "gssapi_openssl.h"
#include "gssapi.h"
#include "globus_gss_assist.h"

int main()
{
    OM_uint32                           minor_status;
    OM_uint32                           major_status;
    gss_cred_id_t                       cred;
    char *                              error_str;

    globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    
    major_status = gss_acquire_cred(
        &minor_status,
        NULL,
        GSS_C_INDEFINITE,
        GSS_C_NO_OID_SET,
        GSS_C_BOTH,
        &cred,
        NULL,
        NULL);
    
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             major_status,
                                             minor_status,
                                             0);
        printf("\nLINE %d ERROR: %s\n", __LINE__, error_str);
        free(error_str);
        globus_module_deactivate_all();
        return 1;
    }
    
    major_status = gss_release_cred(
        &minor_status,
        &cred);
    
    if(GSS_ERROR(major_status))
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             major_status,
                                             minor_status,
                                             0);
        printf("\nLINE %d ERROR: %s\n", __LINE__, error_str);
        free(error_str);
        globus_module_deactivate_all();
        return 1;
    }
    
    globus_module_deactivate_all();
    
    return 0;
}
