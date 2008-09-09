/*
 * Copyright 1999-2008 University of Chicago
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

#include "gssapi.h"
#include "globus_gss_assist.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_credential.h"
#include "gssapi_test_utils.h"
#include "openssl/x509.h"
#include <strings.h>

int
duplicate_bad_params_test(void)
{
    char *                              subject;
    gss_name_t                          gss_name;
    gss_name_t                          name_copy;
    gss_buffer_desc                     name_tok;
    gss_OID                             name_type;
    OM_uint32                           major_status = 0;
    OM_uint32                           minor_status = 0;

    subject = "service@cvs.globus.org";

    name_tok.value = subject;
    name_tok.length = strlen(subject) + 1;
    name_type = GSS_C_NT_HOSTBASED_SERVICE;
    
    major_status = gss_import_name(&minor_status,
                                   &name_tok,
                                   name_type,
                                   &gss_name);
    if (GSS_ERROR(major_status))
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 1;
    }

    major_status = gss_duplicate_name(NULL, gss_name, &name_copy);
    if (!GSS_ERROR(major_status))
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 2;
    }

    major_status = gss_duplicate_name(&minor_status, NULL, &name_copy);
    if (!GSS_ERROR(major_status))
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 3;
    }

    major_status = gss_duplicate_name(&minor_status, gss_name, NULL);
    if (!GSS_ERROR(major_status))
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 4;
    }

    major_status = gss_release_name(&minor_status, &gss_name);

    return 0;
}
/* duplicate_bad_params_test() */

int
duplicate_username_test(void)
{
    char *                              subject;
    gss_name_t                          gss_name;
    gss_name_t                          name_copy;
    gss_buffer_desc                     name_tok;
    gss_OID                             name_type;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 name_equal;

    subject = "/C=US/O=Globus/CN=Globus Test";

    name_tok.value = subject;
    name_tok.length = strlen(subject) + 1;
    name_type = GSS_C_NO_OID;
    
    major_status = gss_import_name(&minor_status,
                                   &name_tok,
                                   name_type,
                                   &gss_name);

    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 1;
    }

    major_status = gss_duplicate_name(&minor_status, gss_name, &name_copy);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 2;
    }

    major_status = gss_compare_name(
            &minor_status, gss_name, name_copy, &name_equal);

    if (major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 3;
    }

    if (!name_equal)
    {
        fprintf(stderr, "duplicate name does not match original name\n");
        return 4;
    }

    major_status = gss_release_name(&minor_status, &gss_name);
    if (major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 5;
    }
    major_status = gss_release_name(&minor_status, &name_copy);
    if (major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 6;
    }

    return 0;
}
/* duplicate_username_test() */

int
duplicate_anonymous_test(void)
{
    gss_name_t                          gss_name;
    gss_name_t                          name_copy;
    gss_buffer_desc                     name_tok;
    gss_OID                             name_type;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;

    name_tok.value = NULL;
    name_tok.length = 0;
    name_type = GSS_C_NT_ANONYMOUS;
    
    major_status = gss_import_name(&minor_status,
                                   &name_tok,
                                   name_type,
                                   &gss_name);

    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 1;
    }

    
    major_status = gss_duplicate_name(&minor_status, gss_name, &name_copy);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 2;
    }

    major_status = gss_display_name(&minor_status,
                                    name_copy,
                                    &name_tok,
                                    NULL);
    
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 3;
    }

    if (strcasecmp(name_tok.value, "<anonymous>") != 0)
    {
        fprintf(stderr,
            "Expected subject name \"%s\" got \"%s\"\n",
            "<anonymous>",
            (char *) name_tok.value);
        return 4;
    }

    major_status = gss_release_buffer(&minor_status, &name_tok);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 5;
    }

    major_status = gss_release_name(&minor_status, &gss_name);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 6;
    }

    major_status = gss_release_name(&minor_status, &name_copy);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 7;
    }

    return 0;
}
/* duplicate_anonymous_test() */

int
duplicate_hostbase_service_test(void)
{
    char *                              subject;
    gss_name_t                          gss_name;
    gss_name_t                          name_copy;
    gss_buffer_desc                     name_tok;
    gss_OID                             name_type;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 name_equal;

    subject = "service@cvs.globus.org";

    name_tok.value = subject;
    name_tok.length = strlen(subject) + 1;
    name_type = GSS_C_NT_HOSTBASED_SERVICE;
    
    major_status = gss_import_name(&minor_status,
                                   &name_tok,
                                   name_type,
                                   &gss_name);

    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 1;
    }

    major_status = gss_duplicate_name(&minor_status, gss_name, &name_copy);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 2;
    }

    major_status = gss_compare_name(
            &minor_status, gss_name, name_copy, &name_equal);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 3;
    }
    if (!name_equal)
    {
        fprintf(stderr, "duplicate name does not match original name\n");
        return 4;
    }

    major_status = gss_release_name(&minor_status, &gss_name);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 5;
    }

    major_status = gss_release_name(&minor_status, &name_copy);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 6;
    }

    return 0;
}
/* duplicate_hostbase_service_test() */

int
duplicate_host_ip_test(void)
{
    char *                              subject;
    gss_name_t                          gss_name;
    gss_name_t                          name_copy;
    gss_buffer_desc                     name_tok;
    gss_OID                             name_type;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 name_equal;

    subject = "cvs.globus.org/192.5.186.90";

    name_tok.value = subject;
    name_tok.length = strlen(subject) + 1;
    name_type = GLOBUS_GSS_C_NT_HOST_IP;
    
    major_status = gss_import_name(&minor_status,
                                   &name_tok,
                                   name_type,
                                   &gss_name);

    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 1;
    }

    major_status = gss_duplicate_name(&minor_status, gss_name, &name_copy);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 2;
    }

    major_status = gss_compare_name(
            &minor_status, gss_name, name_copy, &name_equal);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 3;
    }

    if (!name_equal)
    {
        fprintf(stderr, "duplicate name does not match original name\n");
        return 4;
    }

    major_status = gss_release_name(&minor_status, &gss_name);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 5;
    }

    major_status = gss_release_name(&minor_status, &name_copy);
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);

        return 6;
    }

    return 0;
}
/* duplicate_host_ip_test() */

int
duplicate_x509_test(void)
{
    char *                              subject;
    globus_gsi_cred_handle_t            cred_handle;
    globus_result_t                     result;
    X509 *                              x509;
    gss_name_t                          gss_name;
    gss_name_t                          name_copy;
    gss_buffer_desc                     name_tok;
    gss_OID                             name_type;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 i;
    int                                 name_equal;
    char *                              test_certs[] =
    {
        "192.168.1.1-2.example.org.pem",    /* multiple ipAddress */
        "192.168.1.1.example.org.pem",      /* single ipAddress */
        "test.example.org.pem",             /* dnsName */
        "star.example.org.pem"              /* Wildcard dNSName */
    };

    result = globus_gsi_cred_handle_init(&cred_handle, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        globus_gsi_gssapi_test_print_result(stderr, result);

        return 2;
    }

    for (i = 0; i < SIZEOF_ARRAY(test_certs); i++)
    {
        result = globus_gsi_cred_read_cert(cred_handle, test_certs[i]);
        if (result != GLOBUS_SUCCESS)
        {
            globus_gsi_gssapi_test_print_result(stderr, result);

            return 3;
        }
        result = globus_gsi_cred_get_cert(cred_handle, &x509);
        if (result != GLOBUS_SUCCESS)
        {
            globus_gsi_gssapi_test_print_result(stderr, result);

            return 4;
        }

        result = globus_gsi_cred_get_subject_name(cred_handle, &subject);
        if(result != GLOBUS_SUCCESS)
        {
            globus_gsi_gssapi_test_print_result(stderr, result);

            return 5;
        }

        name_tok.value = x509;
        name_tok.length = sizeof(*x509);
        name_type = GLOBUS_GSS_C_NT_X509;
        
        major_status = gss_import_name(&minor_status,
                                       &name_tok,
                                       name_type,
                                       &gss_name);

        if(major_status != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(
                    stderr, major_status, minor_status);

            return 6;
        }

        major_status = gss_duplicate_name(&minor_status, gss_name, &name_copy);
        if(major_status != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(
                    stderr, major_status, minor_status);

            return 7;
        }

        major_status = gss_compare_name(
                &minor_status, gss_name, name_copy, &name_equal);

        if(major_status != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(
                    stderr, major_status, minor_status);

            return 8;
        }

        if (!name_equal)
        {
            fprintf(stderr, "duplicate name does not match original name\n");
            return 9;
        }

        major_status = gss_release_name(&minor_status, &gss_name);
        if(major_status != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(
                    stderr, major_status, minor_status);

            return 10;
        }

        major_status = gss_release_name(&minor_status, &name_copy);
        if(major_status != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(
                    stderr, major_status, minor_status);

            return 11;
        }
    }

    return 0;
}
/* duplicate_x509_test() */

int main()
{
    int                                 i, rc = 0, failed = 0;
    globus_module_descriptor_t         *modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_GSI_GSSAPI_MODULE,
        NULL
    }, *failed_module = NULL;

    test_case                           tests[] =
    {
        duplicate_bad_params_test,
        duplicate_username_test,
        duplicate_anonymous_test,
        duplicate_hostbase_service_test,
        duplicate_host_ip_test,
        duplicate_x509_test
    };

    rc = globus_module_activate_array(modules, &failed_module);
    if (rc != 0)
    {
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

    return 0;
}
