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
