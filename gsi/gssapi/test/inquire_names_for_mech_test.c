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

#include "gssapi_test_utils.h"

int
bad_param_test(void)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_OID                             mechanism = (gss_OID) globus_i_gss_mech_globus_gssapi_openssl;
    gss_OID_set                         name_types = NULL;

    major_status = gss_inquire_names_for_mech(
        NULL,
        mechanism,
        &name_types);

    if (major_status != GSS_S_FAILURE)
    {
        return 1;
    }

    major_status = gss_inquire_names_for_mech(
        &minor_status,
        NULL,
        &name_types);
    if (major_status != GSS_S_FAILURE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        return 2;
    }

    major_status = gss_inquire_names_for_mech(
        &minor_status,
        mechanism,
        NULL);

    if (major_status != GSS_S_FAILURE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        return 3;
    }

    return 0;
}
/* bad_param_test() */

int unsupported_mech_test(void)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_OID                             mechanism = (gss_OID) globus_i_gss_proxycertinfo_extension;
    gss_OID_set                         name_types = NULL;

    major_status = gss_inquire_names_for_mech(
        &minor_status,
        mechanism,
        &name_types);

    if (major_status != GSS_S_BAD_MECH)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        return 1;
    }

    return 0;
}

int name_types_test(void)
{
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_OID                             mechanism = (gss_OID) globus_i_gss_mech_globus_gssapi_openssl;
    gss_OID_set                         name_types = NULL;
    int                                 i;
    int                                 rc = 0;
    gss_OID                             expected[] =
    {
        GSS_C_NT_ANONYMOUS,
        GSS_C_NT_HOSTBASED_SERVICE,
        GLOBUS_GSS_C_NT_HOST_IP,
        GLOBUS_GSS_C_NT_X509
    };

    major_status = gss_inquire_names_for_mech(
        &minor_status,
        mechanism,
        &name_types);

    if (major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        rc = 1;
        goto out;
    }

    for (i = 0; i < SIZEOF_ARRAY(expected); i++)
    {
        int present = 0;

        major_status = gss_test_oid_set_member(
                &minor_status,
                expected[i],
                name_types,
                &present);

        if (major_status != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(
                    stderr,
                    major_status,
                    minor_status);
            rc = 2;
            goto free_set_out;
        }
        else if (present == 0)
        {
            fprintf(stderr, "Missing mech %d\n", i);
            rc = 3;
            goto free_set_out;
        }
    }

free_set_out:
    gss_release_oid_set(&minor_status, &name_types);
out:
    return rc;
}

int
main()
{
    int                                 rc;
    globus_module_descriptor_t         *modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_GSI_GSSAPI_MODULE,
        NULL
    }, *failed_module = NULL;
    test_case                           tests[] =
    {
        bad_param_test,
        unsupported_mech_test,
        name_types_test
    };
    int                                 i, failed = 0;

    rc = globus_module_activate_array(modules, &failed_module);
    if (rc != 0)
    {
        fprintf(stderr, "Error initializing %s module\n",
                failed_module->module_name);
        exit(1);
    }
    printf("1..%d\n", (int) SIZEOF_ARRAY(tests));

    for (i = 0; i < SIZEOF_ARRAY(tests); i++)
    {
        rc = (*(tests[i]))();

        if (rc != 0)
        {
            failed++;
        }
        printf("%s\n", rc == 0 ? "ok" : "not ok");
    }

    globus_module_deactivate_all();
    exit(failed);
}


