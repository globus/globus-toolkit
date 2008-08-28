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
#include "globus_i_gsi_gss_utils.h"

OM_uint32 GSS_CALLCONV gss_inquire_names_for_mech(
    OM_uint32 *                         minor_status,
    const gss_OID                       mechanism,
    gss_OID_set *                       name_types )
{
    static char *                       _function_name_ = "gss_inquire_names_for_mech";
    OM_uint32                           major_status;
    int                                 i;
    gss_OID                             oids[] = {
        GSS_C_NT_HOSTBASED_SERVICE,
        GSS_C_NT_ANONYMOUS,
        GSS_C_NT_EXPORT_NAME,
        (gss_OID) gss_nt_host_ip,
        (gss_OID) gss_nt_x509,
        NULL
    };

    if (minor_status == NULL || mechanism == NULL || name_types == NULL)
    {
        if (minor_status != NULL)
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                        minor_status,
                        GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
                        (_GGSL("Invalid parameter")));
        }

        major_status = GSS_S_FAILURE;

        goto out;
    }

    if (! g_OID_equal(mechanism, gss_mech_globus_gssapi_openssl))
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH,
                    (_GGSL("Requested mechanism not supported")));
        major_status = GSS_S_BAD_MECH;

        goto out;
    }

    major_status = gss_create_empty_oid_set(minor_status, name_types);
    if (major_status != GSS_S_COMPLETE)
    {
        goto out;
    }

    for (i = 0; oids[i] != NULL; i++)
    {
        major_status = gss_add_oid_set_member(
            minor_status,
            oids[i],
            name_types);
        if (major_status != GSS_S_COMPLETE)
        {
            goto free_oids;
        }
    }

free_oids:
    if (major_status != GSS_S_COMPLETE)
    {
        OM_uint32                       local_major;
        OM_uint32                       local_minor;

        local_major = gss_release_oid_set(
            &local_minor,
            name_types);
    }

out:
    return major_status;
}
