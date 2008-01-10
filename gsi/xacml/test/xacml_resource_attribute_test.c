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
    int                                 rc;
    xacml_resource_attribute_t          ra;

    rc = xacml_resource_attribute_init(&ra);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "initialize resource attribute");

    rc = xacml_resource_attribute_init(NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "initialize null param");

    xacml_resource_attribute_destroy(ra);
    xacml_resource_attribute_destroy(NULL);

    return 0;
}
/* init_destroy_test() */

int
add_attribute_test(void)
{
    int                                 rc;
    xacml_resource_attribute_t          ra;
    const char *                        attribute_id_orig = "TestAttribute";
    const char *                        data_type_orig = XACML_DATATYPE_STRING;
    const char *                        issuer_orig = "me";
    const char *                        value_orig = "test";
    const char *                        attribute_id;
    const char *                        data_type;
    const char *                        issuer;
    const char *                        value;
    size_t                              count;
    size_t                              i;
    int                                 orig_issuer = 0;
    int                                 no_issuer = 0;


    rc = xacml_resource_attribute_init(&ra);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "initialize resource attribute");

    rc = xacml_resource_attribute_get_count(
            ra,
            &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "get resource attribute count");
    TEST_ASSERTION(count == 0, "check resource attribute count");

    rc = xacml_resource_attribute_add(
            ra,
            attribute_id_orig,
            data_type_orig,
            issuer_orig,
            value_orig);

    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "add resource attribute");

    rc = xacml_resource_attribute_get_count(
            ra,
            &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "get resource attribute count");
    TEST_ASSERTION(count == 1, "check resource attribute count");

    rc = xacml_resource_attribute_add(
            ra,
            attribute_id_orig,
            data_type_orig,
            NULL,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "add resource attribute with NULL issuer");

    rc = xacml_resource_attribute_get_count(
            ra,
            &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "get resource attribute count");
    TEST_ASSERTION(count == 2, "check resource attribute count");

    for (i = 0; i < count; i++)
    {
        rc = xacml_resource_attribute_get_attribute(
                ra,
                i,
                &attribute_id,
                &data_type,
                &issuer,
                &value);

        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "Get resource attribute value");
        TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                       "Attribute ID mismatch");
        TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                       "DataType mismatch");
        TEST_ASSERTION(issuer == NULL || strcmp(issuer, issuer_orig) == 0,
                       "Issuer mismatch");

        if (issuer == NULL)
        {
            no_issuer = 1;
        }
        else
        {
            orig_issuer = 1;
        }
    }
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "add resource attribute");

    TEST_ASSERTION(no_issuer, "Missing resource attribute without issuer");
    TEST_ASSERTION(orig_issuer, "Missing resource attribute without issuer");

    rc = xacml_resource_attribute_get_count(ra, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "NULL count parameter");
    rc = xacml_resource_attribute_get_count(NULL, &count);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "NULL resource attribute parameter");

    rc = xacml_resource_attribute_get_attribute(ra, 3, NULL, NULL, NULL, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "out of bounds attribute number");
    rc = xacml_resource_attribute_get_attribute(NULL, 0, NULL, NULL, NULL, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_resource_attribute_get_attribute(null resource)");

    rc = xacml_resource_attribute_add(
            NULL,
            attribute_id_orig,
            data_type_orig,
            issuer_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "add resource attribute to null attribute set");
    rc = xacml_resource_attribute_add(
            ra,
            NULL,
            data_type_orig,
            issuer_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "add resource attribute with null attribute id");

    rc = xacml_resource_attribute_add(
            ra,
            attribute_id_orig,
            NULL,
            issuer_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "add resource attribute with null datatype");

    rc = xacml_resource_attribute_add(
            ra,
            attribute_id_orig,
            data_type_orig,
            issuer_orig,
            NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "add resource attribute with null value");

    xacml_resource_attribute_destroy(ra);

    return 0;
}
/* add_attribute_test() */

int main()
{
    int failed = 0, i;
    test_case test_cases[] =
    {
        TEST_CASE(init_destroy_test),
        TEST_CASE(add_attribute_test)
    };

    printf("1..%d\n", ARRAY_SIZE(test_cases));

    xacml_init();

    for (i = 0; i < ARRAY_SIZE(test_cases); i++)
    {
        if (test_cases[i].test() != 0)
        {
            printf("not ok #%s\n", test_cases[i].name);
            failed++;
        }
        else
        {
            printf("ok\n");
        }
    }

    return failed;
}
