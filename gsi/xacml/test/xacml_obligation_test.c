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

#include "xacml.h"

#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define TEST_CASE(a) { #a, a }
#define TEST_ASSERTION(a, message) \
    if (!(a)) \
    { \
        fprintf(stderr, "\nFAILED TEST \"%s\" %s:%d\n   %s\n   Expected: %s\n", \
                __func__, __FILE__, __LINE__, message, #a); \
        return -1; \
    }

typedef struct
{
    const char * name;
    int (*test)(void);
} test_case;


int
init_destroy_test(void)
{
    xacml_result_t                      rc;
    xacml_obligation_t                  obligation;
    const char *                        obligation_id_orig = "id";
    xacml_effect_t                      effect_orig = XACML_EFFECT_Deny;
    const char *                        obligation_id;
    xacml_effect_t                      effect;

    rc = xacml_obligation_init(NULL, obligation_id_orig, effect_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_init");

    rc = xacml_obligation_init(&obligation, NULL, effect_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_init");

    rc = xacml_obligation_init(&obligation, NULL, 1000);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_init");

    rc = xacml_obligation_init(&obligation, obligation_id_orig, effect_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_obligation_init");

    rc = xacml_obligation_get_id(obligation, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_get_id");

    rc = xacml_obligation_get_id(NULL, &obligation_id);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_get_id");

    rc = xacml_obligation_get_id(obligation, &obligation_id);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_get_id");
    TEST_ASSERTION(strcmp(obligation_id, obligation_id_orig) == 0,
                    "xacml_obligation_get_id");

    rc = xacml_obligation_get_effect(NULL, &effect);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_get_effect");

    rc = xacml_obligation_get_effect(obligation, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_get_effect");

    rc = xacml_obligation_get_effect(obligation, &effect);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_get_effect");
    TEST_ASSERTION(effect == effect_orig,
                   "xacml_obligation_get_effect");

    xacml_obligation_destroy(obligation);

    xacml_obligation_destroy(NULL);

    return 0;
}
/* init_destroy_test() */

int
obligation_attribute_test(void)
{
    int                                 rc;
    xacml_obligation_t                  obligation;
    const char *                        obligation_id_orig = "obligation-id";
    xacml_effect_t                      effect_orig = XACML_EFFECT_Deny;
    const char *                        attribute_id_orig = "attribute-id";
    const char *                        data_type_orig = XACML_DATATYPE_STRING;
    const char *                        value_orig = "value";
    size_t                              count;
    const char *                        obligation_id;
    xacml_effect_t                      effect;
    const char *                        attribute_id;
    const char *                        data_type;
    const char *                        value;

    rc = xacml_obligation_init(&obligation, obligation_id_orig, effect_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_obligation_init");
    
    rc = xacml_obligation_get_attribute_count(obligation, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_get_attribute_count");

    rc = xacml_obligation_get_attribute_count(NULL, &count);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_get_attribute_count");

    rc = xacml_obligation_get_attribute_count(obligation, &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_get_attribute_count");
    TEST_ASSERTION(count == 0,
                   "xacml_obligation_get_attribute_count");

    rc = xacml_obligation_add_attribute(
            NULL,
            attribute_id_orig,
            data_type_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_add_attribute");

    rc = xacml_obligation_add_attribute(
            obligation,
            NULL,
            data_type_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_add_attribute");

    rc = xacml_obligation_add_attribute(
            obligation,
            attribute_id_orig,
            NULL,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_add_attribute");

    rc = xacml_obligation_add_attribute(
            obligation,
            attribute_id_orig,
            data_type_orig,
            NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_add_attribute");

    rc = xacml_obligation_add_attribute(
            obligation,
            attribute_id_orig,
            data_type_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_add_attribute");

    rc = xacml_obligation_get_attribute_count(obligation, &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_get_attribute_count");
    TEST_ASSERTION(count == 1,
                   "xacml_obligation_get_attribute_count");

    rc = xacml_obligation_get_attribute(
            obligation,
            100,
            &attribute_id,
            &data_type,
            &value);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_get_attribute");

    rc = xacml_obligation_get_attribute(
            NULL,
            0,
            &attribute_id,
            &data_type,
            &value);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_obligation_get_attribute");

    rc = xacml_obligation_get_attribute(
            obligation,
            0,
            &attribute_id,
            &data_type,
            &value);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_get_attribute");
    TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                   "xacml_obligation_get_attribute");
    TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                   "xacml_obligation_get_attribute");
    TEST_ASSERTION(strcmp(value, value_orig) == 0,
                   "xacml_obligation_get_attribute");

    xacml_obligation_destroy(obligation);

    return 0;
}
/* obligation_attribute_test() */

int main()
{
    int failed = 0, i;
    test_case test_cases[] =
    {
        TEST_CASE(init_destroy_test),
        TEST_CASE(obligation_attribute_test)
    };

    printf("1..%d\n",(int) ARRAY_SIZE(test_cases));

    xacml_init();
    for (i = 0; i < ARRAY_SIZE(test_cases); i++)
    {
        if (test_cases[i].test() != 0)
        {
            printf("not ok # %s\n", test_cases[i].name);
            failed++;
        }
        else
        {
            printf("ok # %s\n", test_cases[i].name);
        }
    }

    return failed;
}
