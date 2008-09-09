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

typedef enum
{
    GSS_L_ANONYMOUS,
    GSS_L_NO_OID,
    GSS_L_HOSTBASED_SERVICE,
    GSS_L_HOST_IP,
    GSS_L_X509
}
gss_l_test_name_type_t;

const char * name_type_strings[] =
{
    "GSS_C_NT_ANONYMOUS",
    "GSS_C_NO_OID",
    "GSS_C_NT_HOSTBASED_SERVICE",
    "GLOBUS_GSS_C_NT_HOST_IP",
    "GLOBUS_GSS_C_NT_X509"
};

static globus_bool_t                    gss_l_host_ip_support = GLOBUS_FALSE;
static globus_bool_t                    gss_l_x509_support = GLOBUS_FALSE;

typedef struct
{
    gss_l_test_name_type_t              name_type1;
    char *                              name_token1;
    gss_l_test_name_type_t              name_type2;
    char *                              name_token2;
    globus_bool_t                       expectation;

    gss_name_t                          name1;
    gss_name_t                          name2;
}
compare_name_test_case_t;

globus_list_t *                         test_cases = NULL;

static
void
globus_l_gss_test_print_name_error(
    FILE *                              stream,
    gss_name_t                          name1,
    gss_l_test_name_type_t              name_type1,
    gss_name_t                          name2,
    gss_l_test_name_type_t              name_type2,
    int                                 expected_equal);

static
void
import_names()
{
    OM_uint32                           major_status, minor_status;
    globus_gsi_cred_handle_t            handle;
    gss_buffer_desc                     buffer;
    X509 *                              cert;
    gss_OID_set                         name_types;
    globus_result_t                     result;
    globus_list_t                       *i, *j;
    compare_name_test_case_t *          test_case;
    int                                 present;

    major_status = gss_inquire_names_for_mech(
        &minor_status,
        (gss_OID) globus_i_gss_mech_globus_gssapi_openssl,
        &name_types);

    if (major_status == GSS_S_COMPLETE)
    {
        major_status = gss_test_oid_set_member(
                &minor_status,
                GLOBUS_GSS_C_NT_X509,
                name_types,
                &present);

        if (major_status == GSS_S_COMPLETE && present)
        {
            gss_l_x509_support = GLOBUS_TRUE;
        }

        major_status = gss_test_oid_set_member(
                &minor_status,
                GLOBUS_GSS_C_NT_HOST_IP,
                name_types,
                &present);

        if (major_status == GSS_S_COMPLETE && present)
        {
            gss_l_host_ip_support = GLOBUS_TRUE;
        }

        major_status = gss_release_oid_set(&minor_status, &name_types);
    }

    for (i = test_cases; !globus_list_empty(i); i = globus_list_rest(i))
    {
        test_case = globus_list_first(i);

        if (test_case->name1 == GSS_C_NO_NAME)
        {
            switch (test_case->name_type1)
            {
                case GSS_L_ANONYMOUS:
                    major_status = gss_import_name(&minor_status, &buffer, GSS_C_NT_ANONYMOUS, &test_case->name1);
                    if (major_status != GSS_S_COMPLETE)
                    {
                        fprintf(stderr, "Error importing <anonymous>\n");
                        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                        exit(-1);
                    }
                    break;
                case GSS_L_NO_OID:
                    buffer.value = test_case->name_token1;
                    buffer.length = strlen(buffer.value);

                    major_status = gss_import_name(&minor_status, &buffer, GSS_C_NO_OID, &test_case->name1);
                    if (major_status != GSS_S_COMPLETE)
                    {
                        fprintf(stderr, "Error importing %s\n", test_case->name_token1);
                        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                        exit(-1);
                    }
                    break;
                case GSS_L_HOSTBASED_SERVICE:
                    buffer.value = test_case->name_token1;
                    buffer.length = strlen(buffer.value);

                    major_status = gss_import_name(&minor_status, &buffer, GSS_C_NT_HOSTBASED_SERVICE, &test_case->name1);
                    if (major_status != GSS_S_COMPLETE)
                    {
                        fprintf(stderr, "Error importing %s\n", test_case->name_token1);
                        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                        exit(-1);
                    }
                    break;
                case GSS_L_HOST_IP:
                    if (gss_l_host_ip_support)
                    {
                        buffer.value = test_case->name_token1;
                        buffer.length = strlen(buffer.value);

                        major_status = gss_import_name(&minor_status, &buffer, GLOBUS_GSS_C_NT_HOST_IP, &test_case->name1);
                        if (major_status != GSS_S_COMPLETE)
                        {
                            fprintf(stderr, "Error importing %s\n", test_case->name_token1);
                            globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                            exit(-1);
                        }
                    }
                    break;
                case GSS_L_X509:
                    if (gss_l_x509_support)
                    {
                        result = globus_gsi_cred_handle_init(&handle, NULL);
                        if (result != GLOBUS_SUCCESS)
                        {
                            globus_gsi_gssapi_test_print_result(stderr, result);
                            exit(-1);
                        }

                        result = globus_gsi_cred_read_cert(handle, test_case->name_token1);
                        if (result != GLOBUS_SUCCESS)
                        {
                            globus_gsi_gssapi_test_print_result(stderr, result);
                            exit(-2);
                        }

                        result = globus_gsi_cred_get_cert(handle, &cert);

                        buffer.value = cert;
                        buffer.length = sizeof(X509);

                        major_status = gss_import_name(&minor_status, &buffer, GLOBUS_GSS_C_NT_X509, &test_case->name1);
                        if (major_status != GSS_S_COMPLETE)
                        {
                            fprintf(stderr, "Error importing %s\n", test_case->name_token1);
                            globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                            exit(-1);
                        }
                        X509_free(cert);
                        globus_gsi_cred_handle_destroy(handle);
                    }
                    break;
            }

            for (j = i; !globus_list_empty(j); j = globus_list_rest(j))
            {
                compare_name_test_case_t *test_case2 = globus_list_first(j);

                if (test_case->name_type1 == test_case2->name_type1 &&
                    test_case->name_token1 && test_case2->name_token1 &&
                    strcmp(test_case->name_token1, test_case2->name_token1) == 0 &&
                    test_case2->name1 == GSS_C_NO_NAME)
                {
                    test_case2->name1 = test_case->name1;
                }
                if (test_case->name_type1 == test_case2->name_type2 &&
                    test_case->name_token1 && test_case2->name_token2 &&
                    strcmp(test_case->name_token1, test_case2->name_token2) == 0 &&
                    test_case2->name2 == GSS_C_NO_NAME)
                {
                    test_case2->name2 = test_case->name1;
                }
            }
        }
        if (test_case->name2 == GSS_C_NO_NAME)
        {
            switch (test_case->name_type2)
            {
                case GSS_L_ANONYMOUS:
                    major_status = gss_import_name(&minor_status, &buffer, GSS_C_NT_ANONYMOUS, &test_case->name2);
                    if (major_status != GSS_S_COMPLETE)
                    {
                        fprintf(stderr, "Error importing <anonymous>\n");
                        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                        exit(-1);
                    }
                    break;
                case GSS_L_NO_OID:
                    buffer.value = test_case->name_token2;
                    buffer.length = strlen(buffer.value);

                    major_status = gss_import_name(&minor_status, &buffer, GSS_C_NO_OID, &test_case->name2);
                    if (major_status != GSS_S_COMPLETE)
                    {
                        fprintf(stderr, "Error importing %s\n", test_case->name_token2);
                        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                        exit(-1);
                    }
                    break;
                case GSS_L_HOSTBASED_SERVICE:
                    buffer.value = test_case->name_token2;
                    buffer.length = strlen(buffer.value);

                    major_status = gss_import_name(&minor_status, &buffer, GSS_C_NT_HOSTBASED_SERVICE, &test_case->name2);
                    if (major_status != GSS_S_COMPLETE)
                    {
                        fprintf(stderr, "Error importing %s\n", test_case->name_token2);
                        globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                        exit(-1);
                    }
                    break;
                case GSS_L_HOST_IP:
                    if (gss_l_host_ip_support)
                    {
                        buffer.value = test_case->name_token2;
                        buffer.length = strlen(buffer.value);

                        major_status = gss_import_name(&minor_status, &buffer, GLOBUS_GSS_C_NT_HOST_IP, &test_case->name2);
                        if (major_status != GSS_S_COMPLETE)
                        {
                            fprintf(stderr, "Error importing %s\n", test_case->name_token2);
                            globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                            exit(-1);
                        }
                    }
                    break;
                case GSS_L_X509:
                    if (gss_l_x509_support)
                    {
                        result = globus_gsi_cred_handle_init(&handle, NULL);
                        if (result != GLOBUS_SUCCESS)
                        {
                            globus_gsi_gssapi_test_print_result(stderr, result);
                            exit(-1);
                        }

                        result = globus_gsi_cred_read_cert(handle, test_case->name_token2);
                        if (result != GLOBUS_SUCCESS)
                        {
                            globus_gsi_gssapi_test_print_result(stderr, result);
                            exit(-2);
                        }

                        result = globus_gsi_cred_get_cert(handle, &cert);

                        buffer.value = cert;
                        buffer.length = sizeof(X509);

                        major_status = gss_import_name(&minor_status, &buffer, GLOBUS_GSS_C_NT_X509, &test_case->name2);
                        if (major_status != GSS_S_COMPLETE)
                        {
                            fprintf(stderr, "Error importing %s\n", test_case->name_token2);
                            globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
                            exit(-1);
                        }
                        X509_free(cert);
                        globus_gsi_cred_handle_destroy(handle);
                    }
                    break;
            }
            for (j = i; !globus_list_empty(j); j = globus_list_rest(j))
            {
                compare_name_test_case_t *test_case2 = globus_list_first(j);

                if (test_case->name_type2 == test_case2->name_type1 &&
                    test_case->name_token2 && test_case2->name_token1 &&
                    strcmp(test_case->name_token2, test_case2->name_token1) == 0 &&
                    test_case2->name1 == GSS_C_NO_NAME)
                {
                    test_case2->name1 = test_case->name2;
                }
                if (test_case->name_type2 == test_case2->name_type2 &&
                    test_case->name_token2 && test_case2->name_token2 &&
                    strcmp(test_case->name_token2, test_case2->name_token2) == 0 &&
                    test_case2->name2 == GSS_C_NO_NAME)
                {
                    test_case2->name2 = test_case->name2;
                }
            }
        }
    }
}

static
void
compare_l_parse_name_type(
    char *                              name_type,
    char *                              name_token,
    gss_l_test_name_type_t *            name_type_val,
    char **                             name_token_val)
{
    if (strcmp(name_type, "GSS_C_NT_ANONYMOUS") == 0)
    {
        *name_type_val = GSS_L_ANONYMOUS;
        *name_token_val = NULL;
    }
    else
    {
        if (strcmp(name_type, "GSS_C_NO_OID") == 0)
        {
            *name_type_val = GSS_L_NO_OID;
        }
        else if (strcmp(name_type, "GSS_C_NT_HOSTBASED_SERVICE") == 0)
        {
            *name_type_val = GSS_L_HOSTBASED_SERVICE;
        }
        else if (strcmp(name_type, "GLOBUS_GSS_C_NT_HOST_IP") == 0)
        {
            *name_type_val = GSS_L_HOST_IP;
        }
        else if (strcmp(name_type, "GLOBUS_GSS_C_NT_X509") == 0)
        {
            *name_type_val = GSS_L_X509;
        }
        *name_token_val = malloc(strlen(name_token)+1);
        sscanf(name_token, "\"%[^\"]\"", *name_token_val);
    }
}


static
void
globus_l_gss_read_test_cases(char * filename)
{
    int fd;
    int rc;
    struct stat st;
    char * buffer;
    char * line;
    compare_name_test_case_t * test_case;
    globus_list_t * rline_list = NULL;
    static char name_type1[32], name_type2[32];
    static char name_token1[128], name_token2[128];
    static char expectation[16];

    rc = stat(filename, &st);
    if (rc != 0)
    {
        perror("stat");
        exit(1);
    }

    buffer = malloc(st.st_size + 1);
    if (buffer == NULL)
    {
        perror("malloc");
        exit(1);
    }
    fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }

    rc = read(fd, buffer, st.st_size);
    if (rc != st.st_size)
    {
        perror("read");
        exit(1);
    }
    buffer[st.st_size] = '\0';

    /* reversed order list */
    rline_list = globus_list_from_string(buffer, '\n', " \t\r\n");

    while (! globus_list_empty(rline_list))
    {
        line = globus_list_remove(&rline_list, rline_list);

        if (strlen(line) != 0)
        {
            test_case = calloc(1, sizeof(compare_name_test_case_t));

            sscanf(line, "%[^,], %[^,], %[^,], %[^,], %[^,]",
                    name_type1, name_token1,
                    name_type2, name_token2,
                    expectation);

            compare_l_parse_name_type(
                    name_type1, name_token1,
                    &test_case->name_type1, &test_case->name_token1);
            compare_l_parse_name_type(
                    name_type2, name_token2,
                    &test_case->name_type2, &test_case->name_token2);
            if (strcmp(expectation, "GLOBUS_TRUE") == 0)
            {
                test_case->expectation = GLOBUS_TRUE;
            }
            else if (strcmp(expectation, "GLOBUS_FALSE") == 0)
            {
                test_case->expectation = GLOBUS_FALSE;
            }
            else
            {
                globus_assert((strcmp(expectation, "GLOBUS_FALSE") == 0) ||
                              (strcmp(expectation, "GLOBUS_FALSE") == 0));
            }
            globus_list_insert(&test_cases, test_case);
        }
        free(line);
    }
    free(buffer);
}

static
void
globus_l_gss_free_test_cases()
{
    compare_name_test_case_t            *test_case, *tmp_case;
    gss_name_t                          name1, name2;
    globus_list_t *                     tmp;
    OM_uint32                           minor_status;

    while (!globus_list_empty(test_cases))
    {
        test_case = globus_list_first(test_cases);
        name1 = test_case->name1;
        name2 = test_case->name2;

        for (tmp = test_cases;
             !globus_list_empty(tmp);
             tmp = globus_list_rest(tmp))
        {
            tmp_case = globus_list_first(tmp);

            if (name1 == tmp_case->name1 ||
                name2 == tmp_case->name1)
            {
                tmp_case->name1 = NULL;
            }
            if (name1 == tmp_case->name2 ||
                name2 == tmp_case->name2)
            {
                tmp_case->name2 = NULL;
            }
        }
        gss_release_name(&minor_status, &name1);
        if (name1 != name2)
        {
            gss_release_name(&minor_status, &name2);
        }
        if (test_case->name_token1)
        {
            free(test_case->name_token1);
        }
        if (test_case->name_token2)
        {
            free(test_case->name_token2);
        }
        free(test_case);
        globus_list_remove(&test_cases, test_cases);
    }
}

int main(int argc, char * argv[])
{
    int                                 rc = 0, c = 0, failed = 0;
    OM_uint32                           major_status, minor_status;
    int                                 name_equal;
    globus_list_t                       *i;
    compare_name_test_case_t *          test_case;
    globus_module_descriptor_t          *modules[] =
    {
        GLOBUS_COMMON_MODULE,
        GLOBUS_GSI_GSSAPI_MODULE,
        GLOBUS_GSI_CREDENTIAL_MODULE,
        NULL
    }, *failed_module = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "%s test-case-file\n", argv[0]);
        exit(-1);
    }

    rc = globus_module_activate_array(modules, &failed_module);
    if (rc != 0)
    {
        exit(-1);
    }

    globus_l_gss_read_test_cases(argv[1]);
    import_names();

    printf("1..%d\n", globus_list_size(test_cases));

    for (i = test_cases; !globus_list_empty(i); i = globus_list_rest(i))
    {
        test_case = globus_list_first(i);

        if ((!gss_l_host_ip_support) &&
            (test_case->name_type1 == GSS_L_HOST_IP ||
             test_case->name_type2 == GSS_L_HOST_IP))
        {
            printf("ok %d # skip !gss_l_host_ip_support\n", ++c);
            fflush(stdout);
            continue;
        }
        if ((!gss_l_x509_support) &&
            (test_case->name_type1 == GSS_L_X509 ||
             test_case->name_type2 == GSS_L_X509))
        {
            printf("ok %d # skip !gss_l_x509_support\n", ++c);
            fflush(stdout);
            continue;
        }

        rc = 0;
        major_status = gss_compare_name(
                &minor_status, test_case->name1, test_case->name2, &name_equal);

        if (GSS_ERROR(major_status))
        {
            globus_gsi_gssapi_test_print_error(
                stderr, major_status, minor_status);
            rc = 1;
        }
        else if (name_equal != test_case->expectation)
        {
            globus_l_gss_test_print_name_error(
                    stderr,
                    test_case->name1, test_case->name_type1,
                    test_case->name2, test_case->name_type2,
                    test_case->expectation);
            rc = 2;
        }
        major_status = gss_compare_name(
                &minor_status, test_case->name2, test_case->name1, &name_equal);
        if (GSS_ERROR(major_status))
        {
            globus_gsi_gssapi_test_print_error(
                stderr, major_status, minor_status);
            rc = 3;
        }
        else if (name_equal != test_case->expectation)
        {
            globus_l_gss_test_print_name_error(
                    stderr,
                    test_case->name2, test_case->name_type2,
                    test_case->name1, test_case->name_type1,
                    test_case->expectation);
            rc = 4;
        }

        c++;
        if (rc == 0)
        {
            printf("ok\n");
        }
        else
        {
            failed++;
            printf("not ok %d\n", c);
        }
        fflush(stdout);
    }
    globus_l_gss_free_test_cases();

    return failed;
}

static
void
globus_l_gss_test_print_name_error(
    FILE *                              stream,
    gss_name_t                          name1,
    gss_l_test_name_type_t              name_type1,
    gss_name_t                          name2,
    gss_l_test_name_type_t              name_type2,
    int                                 expected_equal)
{
    OM_uint32                           major_status, minor_status;
    gss_buffer_desc                     name_buffer1, name_buffer2;

    major_status = gss_display_name(&minor_status, name1, &name_buffer1, NULL);
    assert(major_status == GSS_S_COMPLETE);
    major_status = gss_display_name(&minor_status, name2, &name_buffer2, NULL);
    assert(major_status == GSS_S_COMPLETE);

    fprintf(stderr, "Error comparing names (%s):\n\t%s [%s]\n\t%s [%s]\n",
            expected_equal ? "expected to match" : "expected to not match",
            (char *) name_buffer1.value,
            name_type_strings[name_type1],
            (char *) name_buffer2.value,
            name_type_strings[name_type2]);

    gss_release_buffer(&minor_status, &name_buffer1);
    gss_release_buffer(&minor_status, &name_buffer2);
}
/* globus_l_gss_test_print_name_error() */
