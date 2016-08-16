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
#define ARRAY_SIZE(x) sizeof(x)/sizeof(*x)

static
bool
attrs_init_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_gsi_proxy_handle_attrs_init(NULL);

    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    return ok;
}

static
bool
attrs_destroy_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_gsi_proxy_handle_attrs_destroy(NULL);

    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
    }
    return ok;
}

static
bool
attrs_init_destroy_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;

    result = globus_gsi_proxy_handle_attrs_init(&attrs);

    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_destroy(attrs);

    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
    }
    return ok;
}

static
bool
attrs_copy_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    globus_gsi_proxy_handle_attrs_t     copy_attrs = NULL;

    result = globus_gsi_proxy_handle_attrs_copy(NULL, NULL);

    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    result = globus_gsi_proxy_handle_attrs_copy(NULL, &copy_attrs);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    result = globus_gsi_proxy_handle_attrs_copy(attrs, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_copy_destroy_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    globus_gsi_proxy_handle_attrs_t     copy_attrs = NULL;

    result = globus_gsi_proxy_handle_attrs_init(&attrs);

    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    result = globus_gsi_proxy_handle_attrs_copy(attrs, &copy_attrs);

    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_copy;
    }
    result = globus_gsi_proxy_handle_attrs_destroy(copy_attrs);

    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
    }
no_copy:
    result = globus_gsi_proxy_handle_attrs_destroy(attrs);

    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
    }
no_attrs:
    return ok;
}

static
bool
attrs_set_keybits_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_gsi_proxy_handle_attrs_set_keybits(NULL, 0);

    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    return ok;
}

static
bool
attrs_get_keybits_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    int                                 keybits = 0;

    result = globus_gsi_proxy_handle_attrs_get_keybits(NULL, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_get_keybits(NULL, &keybits);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    result = globus_gsi_proxy_handle_attrs_get_keybits(attrs, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_set_get_keybits_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    int                                 test_keybits[] = 
    {
        1024,
        2048,
        4096
    };
    size_t                              num_tests = ARRAY_SIZE(test_keybits);
    int                                 keybits = 0;

    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    for (size_t i = 0; i < num_tests; i++)
    {
        keybits = 0;
        result = globus_gsi_proxy_handle_attrs_set_keybits(
                attrs, test_keybits[i]);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        result = globus_gsi_proxy_handle_attrs_get_keybits(attrs, &keybits);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        if (keybits != test_keybits[i])
        {
            ok = false;
        }
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_set_init_prime_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_gsi_proxy_handle_attrs_set_init_prime(NULL, 0);

    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    return ok;
}


static
bool
attrs_get_init_prime_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    int                                 init_prime = 0;

    result = globus_gsi_proxy_handle_attrs_get_init_prime(NULL, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_get_init_prime(NULL, &init_prime);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    result = globus_gsi_proxy_handle_attrs_get_init_prime(attrs, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_set_get_init_prime_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    int                                 test_init_prime[] = 
    {
        RSA_3,
        RSA_F4,
    };
    size_t                              num_tests = ARRAY_SIZE(test_init_prime);
    int                                 init_prime = 0;

    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    for (size_t i = 0; i < num_tests; i++)
    {
        init_prime = 0;
        result = globus_gsi_proxy_handle_attrs_set_init_prime(
                attrs, test_init_prime[i]);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        result = globus_gsi_proxy_handle_attrs_get_init_prime(
                attrs, &init_prime);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        if (init_prime != test_init_prime[i])
        {
            ok = false;
        }
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_set_signing_algorithm_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_gsi_proxy_handle_attrs_set_signing_algorithm(NULL, NULL);

    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    result = globus_gsi_proxy_handle_attrs_set_signing_algorithm(NULL, EVP_md5());

    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    return ok;
}

static
bool
attrs_get_signing_algorithm_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    const EVP_MD                       *signing_algorithm = NULL;

    result = globus_gsi_proxy_handle_attrs_get_signing_algorithm(NULL, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_get_signing_algorithm(
            NULL, &signing_algorithm);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    result = globus_gsi_proxy_handle_attrs_get_signing_algorithm(attrs, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_set_get_signing_algorithm_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    const EVP_MD *                      test_alg[] = 
    {
        EVP_md5(),
        EVP_sha1(),
    };
    size_t                              num_tests = ARRAY_SIZE(test_alg);
    const EVP_MD *                      alg = NULL;

    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    for (size_t i = 0; i < num_tests; i++)
    {
        alg = NULL;
        result = globus_gsi_proxy_handle_attrs_set_signing_algorithm(
                attrs, test_alg[i]);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        result = globus_gsi_proxy_handle_attrs_get_signing_algorithm(
                attrs, &alg);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        if (alg != test_alg[i])
        {
            ok = false;
        }
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_set_clock_skew_allowable_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_gsi_proxy_handle_attrs_set_clock_skew_allowable(NULL, 1);

    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    return ok;
}

static
bool
attrs_get_clock_skew_allowable_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    int                                 clock_skew_allowable = 0;

    result = globus_gsi_proxy_handle_attrs_get_clock_skew_allowable(NULL, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_get_clock_skew_allowable(
            NULL, &clock_skew_allowable);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    result = globus_gsi_proxy_handle_attrs_get_clock_skew_allowable(attrs, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_set_get_clock_skew_allowable_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    int                                 test_skew[] = 
    {
        60,
        120,
        600,
    };
    size_t                              num_tests = ARRAY_SIZE(test_skew);
    int                                 skew = 0;

    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    for (size_t i = 0; i < num_tests; i++)
    {
        skew = 0;
        result = globus_gsi_proxy_handle_attrs_set_clock_skew_allowable(
                attrs, test_skew[i]);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        result = globus_gsi_proxy_handle_attrs_get_clock_skew_allowable(
                attrs, &skew);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        if (skew != test_skew[i])
        {
            ok = false;
        }
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static
bool
attrs_set_key_gen_callback_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_gsi_proxy_handle_attrs_set_key_gen_callback(NULL, NULL);

    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    return ok;
}

static
bool
attrs_get_key_gen_callback_null_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    void                              (*callback)(int, int, void *);

    result = globus_gsi_proxy_handle_attrs_get_key_gen_callback(NULL, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_get_key_gen_callback(
            NULL, &callback);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }
    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    result = globus_gsi_proxy_handle_attrs_get_key_gen_callback(attrs, NULL);
    if (result == GLOBUS_SUCCESS)
    {
        ok = false;
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

static void test_key_gen_callback(int a, int b, void *c) {;}

static
bool
attrs_set_get_key_gen_callback_test(void)
{
    bool                                ok = true;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gsi_proxy_handle_attrs_t     attrs = NULL;
    void                              (*test_callbacks[])(int, int, void *) =
    {
        test_key_gen_callback,
        NULL
    };
    size_t                              num_tests = ARRAY_SIZE(test_callbacks);
    void                              (*callback)(int, int, void *) = NULL;

    result = globus_gsi_proxy_handle_attrs_init(&attrs);
    if (result != GLOBUS_SUCCESS)
    {
        ok = false;
        goto no_attrs;
    }
    for (size_t i = 0; i < num_tests; i++)
    {
        callback = NULL;
        result = globus_gsi_proxy_handle_attrs_set_key_gen_callback(
                attrs, test_callbacks[i]);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        result = globus_gsi_proxy_handle_attrs_get_key_gen_callback(
                attrs, &callback);
        if (result != GLOBUS_SUCCESS)
        {
            ok = false;
        }
        if (callback != test_callbacks[i])
        {
            ok = false;
        }
    }

    globus_gsi_proxy_handle_attrs_destroy(attrs);
no_attrs:
    return ok;
}

int
main(int argc, char *argv[])
{
    struct test_case                    test_cases[] =
    {
        TEST_CASE_INITIALIZER(attrs_init_null_test),
        TEST_CASE_INITIALIZER(attrs_destroy_null_test),
        TEST_CASE_INITIALIZER(attrs_init_destroy_test),
        TEST_CASE_INITIALIZER(attrs_copy_null_test),
        TEST_CASE_INITIALIZER(attrs_copy_destroy_test),
        TEST_CASE_INITIALIZER(attrs_set_keybits_null_test),
        TEST_CASE_INITIALIZER(attrs_get_keybits_null_test),
        TEST_CASE_INITIALIZER(attrs_set_get_keybits_test),
        TEST_CASE_INITIALIZER(attrs_set_init_prime_null_test),
        TEST_CASE_INITIALIZER(attrs_get_init_prime_null_test),
        TEST_CASE_INITIALIZER(attrs_set_get_init_prime_test),
        TEST_CASE_INITIALIZER(attrs_set_signing_algorithm_null_test),
        TEST_CASE_INITIALIZER(attrs_get_signing_algorithm_null_test),
        TEST_CASE_INITIALIZER(attrs_set_get_signing_algorithm_test),
        TEST_CASE_INITIALIZER(attrs_set_clock_skew_allowable_null_test),
        TEST_CASE_INITIALIZER(attrs_get_clock_skew_allowable_null_test),
        TEST_CASE_INITIALIZER(attrs_set_get_clock_skew_allowable_test),
        TEST_CASE_INITIALIZER(attrs_set_key_gen_callback_null_test),
        TEST_CASE_INITIALIZER(attrs_get_key_gen_callback_null_test),
        TEST_CASE_INITIALIZER(attrs_set_get_key_gen_callback_test),
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
