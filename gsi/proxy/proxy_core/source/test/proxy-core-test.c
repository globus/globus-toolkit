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


#include "globus_common.h"
#include "globus_gsi_proxy.h"

#include <stdbool.h>

struct test_case
{
    const char                         *test_name;
    bool                              (*test_func)(void);
};

#define TEST_CASE_INITIALIZER(c) { #c, c }
#define ARRAY_LEN(x) sizeof(x)/sizeof(*x)

static
bool
create_req_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    BIO                                *bio = BIO_new(BIO_s_mem());
    globus_gsi_proxy_handle_t           handle = NULL;

    result = globus_gsi_proxy_create_req(NULL, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_create_req(NULL, bio);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_init(&handle, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_handle;
    }
    result = globus_gsi_proxy_create_req(handle, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    globus_gsi_proxy_handle_destroy(handle);

no_handle:
    BIO_free(bio);
    return ok;
}

static
bool
inquire_req_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    BIO                                *bio = BIO_new(BIO_s_mem());
    globus_gsi_proxy_handle_t           handle = NULL;

    result = globus_gsi_proxy_inquire_req(NULL, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_inquire_req(NULL, bio);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_init(&handle, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_handle;
    }
    result = globus_gsi_proxy_inquire_req(handle, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    globus_gsi_proxy_handle_destroy(handle);

no_handle:
    BIO_free(bio);
    return ok;
}

static
bool
create_inquire_req_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    BIO                                *bio = NULL;
    globus_gsi_proxy_handle_t           delegatee_handle = NULL;
    globus_gsi_proxy_handle_t           delegator_handle = NULL;
    int                                 pci_languages[] =
    {
        NID_id_ppl_inheritAll,
        NID_Independent,
    };
    size_t                              num_policies = ARRAY_LEN(pci_languages);
    int                                 lang = 0;
    unsigned char                      *data = NULL;
    int                                 data_len = 0;

    for (size_t i = 0; i < num_policies; i++)
    {
        bio = BIO_new(BIO_s_mem());
        if (bio == NULL)
        {
            ok = false;
            continue;
        }
        result = globus_gsi_proxy_handle_init(&delegatee_handle, NULL);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
            goto no_delegatee_handle;
        }
        result = globus_gsi_proxy_handle_init(&delegator_handle, NULL);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
            goto no_delegator_handle;
        }
        result = globus_gsi_proxy_handle_set_policy(
                delegatee_handle,
                NULL,
                0,
                pci_languages[i]);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }

        result = globus_gsi_proxy_create_req(delegatee_handle, bio);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        result = globus_gsi_proxy_inquire_req(delegator_handle, bio);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        result = globus_gsi_proxy_handle_get_policy(delegator_handle, &data, &data_len, &lang);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        if (lang != pci_languages[i])
        {
            ok = false;
        }
        globus_gsi_proxy_handle_destroy(delegator_handle);
no_delegator_handle:
        globus_gsi_proxy_handle_destroy(delegatee_handle);
no_delegatee_handle:
        BIO_free(bio);
    }

    return ok;
}

int
main(int argc, char *argv[])
{
    struct test_case                    test_cases[] =
    {
        TEST_CASE_INITIALIZER(create_req_null_test),
        TEST_CASE_INITIALIZER(inquire_req_null_test),
        TEST_CASE_INITIALIZER(create_inquire_req_test),
    };
    size_t                              num_test_cases = sizeof(test_cases)/sizeof(test_cases[0]);
    int                                 failed = 0;

    globus_module_activate(GLOBUS_GSI_PROXY_MODULE);

    printf("1..%zu\n", num_test_cases);

    for (size_t i = 0; i < num_test_cases; i++)
    {
        if (test_cases[i].test_func())
        {
            printf("ok %zu - %s\n", i+1, test_cases[i].test_name);
        }
        else
        {
            failed++;
            printf("not ok %zu - %s\n", i+1, test_cases[i].test_name);
        }
    }
    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);

    return failed;
}
