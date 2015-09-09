/*
 * Copyright 1999-2015 University of Chicago
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
test_import(
    gss_cred_id_t                       orig_cred,
    OM_uint32                           orig_lifetime,
    gss_name_t                          orig_name,
    int                                 form)
{
    OM_uint32                           major_status = 0;
    OM_uint32                           minor_status = 0;
    gss_buffer_desc                     buffer = {0};
    gss_cred_id_t                       cred = {0};
    OM_uint32                           lifetime = 0;
    gss_name_t                          name = {0};
    int                                 name_equal = 0;
    int                                 failed = 1;
    const char                         *form_names[] =
    {
        "opaque",
        "mech_specific"
    };

    major_status = gss_export_cred(
            &minor_status,
            orig_cred,
            GSS_C_NO_OID,
            form,
            &buffer);

    if (major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        goto fail;
    }
    major_status = 0;
    minor_status = 0;

    major_status = gss_import_cred(
            &minor_status,
            &cred,
            GSS_C_NO_OID,
            form,
            &buffer,
            GSS_C_INDEFINITE,
            &lifetime);
    if (major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        goto fail_buffer;
    }
    if (lifetime > orig_lifetime)
    {
        fprintf(stderr, "# Imported credential living longer than original\n");
        goto fail_cred;
    }
    major_status = gss_inquire_cred(&minor_status,
            cred,
            &name,
            NULL,
            NULL,
            NULL);
    if (major_status != GSS_S_COMPLETE)
    {
        fprintf(stderr, "# Imported credential living longer than original\n");
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        goto fail_cred;
    }
    major_status = gss_compare_name(&minor_status,
        orig_name,
        name,
        &name_equal);
    if (major_status != GSS_S_COMPLETE)
    {
        fprintf(stderr, "# Name comparison error\n");
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        goto fail_name;
    }
    if (!name_equal)
    {
        fprintf(stderr, "# Name mismatch\n");
        goto fail_name;
    }
    failed = 0;

fail_name:
    gss_release_name(&minor_status, &name);
fail_cred:
    gss_release_cred(&minor_status, &cred);
fail_buffer:
    gss_release_buffer(&minor_status, &buffer);
fail:
    printf("%s %d - %s\n", failed ? "not ok" : "ok", form+1, form_names[form]);
    return failed;
}

int
main()
{
    OM_uint32                           major_status = {0};
    OM_uint32                           minor_status = {0};
    gss_cred_id_t                       orig_cred = {0};
    gss_name_t                          orig_name = {0};
    OM_uint32                           orig_lifetime = {0};
    int                                 failed = 0;

    do
    {
        major_status = gss_acquire_cred(&minor_status,
                GSS_C_NO_NAME,
                GSS_C_INDEFINITE,
                NULL,
                GSS_C_BOTH,
                &orig_cred,
                NULL,
                &orig_lifetime);
    }
    while (major_status == GSS_S_CONTINUE_NEEDED);
    
    if (GSS_ERROR(major_status))
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        printf("Bail out!\n");
        exit(99);
    }
    major_status = gss_inquire_cred(&minor_status,
            orig_cred,
            &orig_name,
            NULL,
            NULL,
            NULL);
    if (major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
        printf("Bail out!\n");
        exit(99);
    }

    printf("1..2\n");

    failed += test_import(orig_cred, orig_lifetime, orig_name, 0);
    failed += test_import(orig_cred, orig_lifetime, orig_name, 1);

    return failed;
}
