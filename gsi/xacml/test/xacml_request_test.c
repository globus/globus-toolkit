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
    int                                 rc;
    xacml_request_t                     request;

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "initialize request");

    rc = xacml_request_init(NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "initialize null param");

    xacml_request_destroy(request);

    xacml_request_destroy(NULL);

    return 0;
}
/* init_destroy_test() */

int
action_attribute_test(void)
{
    int                                 rc;
    size_t                              num;
    const char *                        attribute_id_orig = "TestAttribute";
    const char *                        data_type_orig = XACML_DATATYPE_STRING;
    const char *                        issuer_orig = "me";
    const char *                        value_orig = "test";
    const char *                        attribute_id;
    const char *                        data_type;
    const char *                        issuer;
    const char *                        value;
    size_t                              i;
    int                                 orig_issuer = 0;
    int                                 no_issuer = 0;
    xacml_request_t                     request;


    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "initialize a request");

    rc = xacml_request_get_action_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Count Action Attributes");
    TEST_ASSERTION(num == 0, "Count Action Attributes");

    /* Pass NULL parameter to xacml_request_get_action_attribute_count() */
    rc = xacml_request_get_action_attribute_count(NULL, &num);

    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Pass NULL request to xacml_request_get_action_attribute_count()");

    /* Pass NULL parameter to xacml_request_get_action_attribute_count() */
    rc = xacml_request_get_action_attribute_count(request, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                    "Pass NULL count to xacml_request_get_action_attribute_count()");

    /* Add action attribute */
    rc = xacml_request_add_action_attribute(
            request,
            attribute_id_orig,
            data_type_orig,
            issuer_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Add action attribute");

    /* Count action attributes (assert there are 1) */
    rc = xacml_request_get_action_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Count action attributes");
    TEST_ASSERTION(num == 1, "Unexpected number of action attributes");

    rc = xacml_request_get_action_attribute(
                    request,
                    1,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Get out of range action attribute");

    rc = xacml_request_get_action_attribute(
                    NULL,
                    0,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Get action attribute from NULL request");

    rc = xacml_request_get_action_attribute(
                    request,
                    0,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "Get no fields from action attribute");

    rc = xacml_request_get_action_attribute(
                    request,
                    0,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Get first action attribute");
    TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                   "Attribute ID mismatch from retrieved action attribute");
    TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                   "DataType mismatch from retrieved action attribute");
    TEST_ASSERTION(strcmp(issuer, issuer_orig) == 0,
                   "Issuer mismatch from retrieved action attribute");
    TEST_ASSERTION(strcmp(value, value_orig) == 0,
                   "Value mismatch from retrieved action attribute");

    rc = xacml_request_add_action_attribute(
                    request,
                    attribute_id_orig,
                    NULL,
                    issuer_orig,
                    value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                  "Add action attribute without datatype");

    rc = xacml_request_add_action_attribute(
                    request,
                    attribute_id_orig,
                    data_type_orig,
                    issuer_orig,
                    NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                  "Add action attribute without value");

    rc = xacml_request_add_action_attribute(
            request,
            attribute_id_orig,
            data_type_orig,
            NULL,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                  "Add action attribute without issuer");

    rc = xacml_request_get_action_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                  "Count action attributes");
    TEST_ASSERTION(num == 2,
                  "Expect 2 action attributes");

    for (i = 0; i < num; i++)
    {
        rc = xacml_request_get_action_attribute(
                        request,
                        i,
                        &attribute_id,
                        &data_type,
                        &issuer,
                        &value);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Get action attribute");
        TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                       "AttributeID mismatch");
        TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                       "DataType mismatch");
        TEST_ASSERTION(strcmp(value, value_orig) == 0,
                       "Value mismatch");
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

    TEST_ASSERTION(no_issuer, "Missing action attribute without issuer");
    TEST_ASSERTION(orig_issuer, "Missing action attribute with issuer");

    xacml_request_destroy(request);

    return 0;
}
/* action_attribute_test() */

int
environment_attribute_test(void)
{
    int                                 rc;
    size_t                              num;
    const char *                        attribute_id_orig = "TestAttribute";
    const char *                        data_type_orig = XACML_DATATYPE_STRING;
    const char *                        issuer_orig = "me";
    const char *                        value_orig = "test";
    const char *                        attribute_id;
    const char *                        data_type;
    const char *                        issuer;
    const char *                        value;
    size_t                              i;
    int                                 orig_issuer = 0;
    int                                 no_issuer = 0;
    xacml_request_t                     request;

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "initialize a request");

    rc = xacml_request_get_environment_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Count Environment Attributes");
    TEST_ASSERTION(num == 0, "Count Environment Attributes");

    /* Pass NULL parameter to xacml_request_get_environment_attribute_count() */
    rc = xacml_request_get_environment_attribute_count(NULL, &num);

    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Pass NULL request to xacml_request_get_environment_attribute_count()");

    /* Pass NULL parameter to xacml_request_get_environment_attribute_count() */
    rc = xacml_request_get_environment_attribute_count(request, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                    "Pass NULL count to xacml_request_get_environment_attribute_count()");

    /* Add environment attribute */
    rc = xacml_request_add_environment_attribute(
            request,
            attribute_id_orig,
            data_type_orig,
            issuer_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Add environment attribute");

    /* Count environment attributes (assert there are 1) */
    rc = xacml_request_get_environment_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Count environment attributes");
    TEST_ASSERTION(num == 1, "Unexpected number of environment attributes");

    rc = xacml_request_get_environment_attribute(
                    request,
                    1,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Get out of range environment attribute");

    rc = xacml_request_get_environment_attribute(
                    NULL,
                    0,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Get environment attribute from NULL request");

    rc = xacml_request_get_environment_attribute(
                    request,
                    0,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "Get no fields from environment attribute");

    rc = xacml_request_get_environment_attribute(
                    request,
                    0,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Get first environment attribute");
    TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                   "Attribute ID mismatch from retrieved environment attribute");
    TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                   "DataType mismatch from retrieved environment attribute");
    TEST_ASSERTION(strcmp(issuer, issuer_orig) == 0,
                   "Issuer mismatch from retrieved environment attribute");
    TEST_ASSERTION(strcmp(value, value_orig) == 0,
                   "Value mismatch from retrieved environment attribute");

    rc = xacml_request_add_environment_attribute(
                    request,
                    attribute_id_orig,
                    NULL,
                    issuer_orig,
                    value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                  "Add environment attribute without datatype");

    rc = xacml_request_add_environment_attribute(
                    request,
                    attribute_id_orig,
                    data_type_orig,
                    issuer_orig,
                    NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                  "Add environment attribute without value");

    rc = xacml_request_add_environment_attribute(
            request,
            attribute_id_orig,
            data_type_orig,
            NULL,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                  "Add environment attribute without issuer");

    rc = xacml_request_get_environment_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                  "Count environment attributes");
    TEST_ASSERTION(num == 2,
                  "Expect 2 environment attributes");

    for (i = 0; i < num; i++)
    {
        rc = xacml_request_get_environment_attribute(
                        request,
                        i,
                        &attribute_id,
                        &data_type,
                        &issuer,
                        &value);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Get environment attribute");
        TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                       "AttributeID mismatch");
        TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                       "DataType mismatch");
        TEST_ASSERTION(strcmp(value, value_orig) == 0,
                       "Value mismatch");
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

    TEST_ASSERTION(no_issuer, "Missing environment attribute without issuer");
    TEST_ASSERTION(orig_issuer, "Missing environment attribute with issuer");

    xacml_request_destroy(request);

    return 0;
}
/* environment_attribute_test() */

int
subject_attribute_test(void)
{
    int                                 rc;
    size_t                              num;
    const char *                        subject_category_orig
                                        = XACML_SUBJECT_CATEGORY_ACCESS_SUBJECT;
    const char *                        attribute_id_orig = "TestAttribute";
    const char *                        data_type_orig = XACML_DATATYPE_STRING;
    const char *                        issuer_orig = "me";
    const char *                        value_orig = "test";
    const char *                        subject_category;
    const char *                        attribute_id;
    const char *                        data_type;
    const char *                        issuer;
    const char *                        value;
    size_t                              i;
    int                                 orig_issuer = 0;
    int                                 no_issuer = 0;
    xacml_request_t                     request;

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "initialize a request");

    rc = xacml_request_get_subject_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Count Subject Attributes");
    TEST_ASSERTION(num == 0, "Count Subject Attributes");

    /* Pass NULL parameter to xacml_request_get_subject_attribute_count() */
    rc = xacml_request_get_subject_attribute_count(NULL, &num);

    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Pass NULL request to xacml_request_get_subject_attribute_count()");

    /* Pass NULL parameter to xacml_request_get_subject_attribute_count() */
    rc = xacml_request_get_subject_attribute_count(request, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                    "Pass NULL count to xacml_request_get_subject_attribute_count()");

    /* Add subject attribute */
    rc = xacml_request_add_subject_attribute(
            request,
            subject_category_orig,
            attribute_id_orig,
            data_type_orig,
            issuer_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Add subject attribute");

    /* Count subject attributes (assert there are 1) */
    rc = xacml_request_get_subject_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Count subject attributes");
    TEST_ASSERTION(num == 1, "Unexpected number of subject attributes");

    rc = xacml_request_get_subject_attribute(
                    request,
                    1,
                    &subject_category,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Get out of range subject attribute");

    rc = xacml_request_get_subject_attribute(
                    NULL,
                    0,
                    &subject_category,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Get subject attribute from NULL request");

    rc = xacml_request_get_subject_attribute(
                    request,
                    0,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "Get no fields from subject attribute");

    rc = xacml_request_get_subject_attribute(
                    request,
                    0,
                    &subject_category,
                    &attribute_id,
                    &data_type,
                    &issuer,
                    &value);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Get first subject attribute");
    TEST_ASSERTION(strcmp(subject_category, subject_category_orig) == 0,
                   "Subject Category mismatch from retrieved subject attribute");
    TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                   "Attribute ID mismatch from retrieved subject attribute");
    TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                   "DataType mismatch from retrieved subject attribute");
    TEST_ASSERTION(strcmp(issuer, issuer_orig) == 0,
                   "Issuer mismatch from retrieved subject attribute");
    TEST_ASSERTION(strcmp(value, value_orig) == 0,
                   "Value mismatch from retrieved subject attribute");

    rc = xacml_request_add_subject_attribute(
            request,
            NULL,
            attribute_id_orig,
            data_type_orig,
            issuer_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                  "Add subject attribute without category");
    rc = xacml_request_add_subject_attribute(
                    request,
                    subject_category_orig,
                    attribute_id_orig,
                    NULL,
                    issuer_orig,
                    value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                  "Add subject attribute without datatype");

    rc = xacml_request_add_subject_attribute(
                    request,
                    subject_category_orig,
                    attribute_id_orig,
                    data_type_orig,
                    issuer_orig,
                    NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                  "Add subject attribute without value");

    rc = xacml_request_add_subject_attribute(
            request,
            subject_category_orig,
            attribute_id_orig,
            data_type_orig,
            NULL,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                  "Add subject attribute without issuer");

    rc = xacml_request_get_subject_attribute_count(request, &num);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                  "Count subject attributes");
    TEST_ASSERTION(num == 2,
                  "Expect 2 subject attributes");

    for (i = 0; i < num; i++)
    {
        rc = xacml_request_get_subject_attribute(
                        request,
                        i,
                        &subject_category,
                        &attribute_id,
                        &data_type,
                        &issuer,
                        &value);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Get subject attribute");
        TEST_ASSERTION(strcmp(subject_category, subject_category_orig) == 0,
                       "Subject category mismatch");
        TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                       "AttributeID mismatch");
        TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                       "DataType mismatch");
        TEST_ASSERTION(strcmp(value, value_orig) == 0,
                       "Value mismatch");
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

    TEST_ASSERTION(no_issuer, "Missing subject attribute without issuer");
    TEST_ASSERTION(orig_issuer, "Missing subject attribute with issuer");

    xacml_request_destroy(request);

    return 0;
}
/* subject_attribute_test() */

int
subject_test(void)
{
    int                                 rc;
    const char *                        subject_orig = "me";
    const char *                        subject;
    xacml_request_t                     request;

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "initialize a request");

    rc = xacml_request_get_subject(request, &subject);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Get Subject");
    TEST_ASSERTION(subject == NULL, "Get empty subject from request");

    rc = xacml_request_set_subject(request, subject_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Couldn't set subject")

    rc = xacml_request_get_subject(request, &subject);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "Get Subject");
    TEST_ASSERTION(subject, "Got unexpectedly NULL subject");
    TEST_ASSERTION(strcmp(subject, subject_orig) == 0, "Subject mismatch");

    rc = xacml_request_get_subject(request, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Get subject with null subject");

    rc = xacml_request_get_subject(NULL, &subject);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Get subject with null request");

    rc = xacml_request_set_subject(NULL, subject_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "Set subject with null request");

    xacml_request_destroy(request);

    return 0;
}
/* subject_test() */

int
resource_attribute_test(void)
{
    int                                 rc;
    xacml_request_t                     request;
    xacml_resource_attribute_t          resource;
    xacml_resource_attribute_t          resource_copy;
    const char *                        attribute_id_orig = "TestAttribute";
    const char *                        data_type_orig = XACML_DATATYPE_STRING;
    const char *                        issuer_orig = "me";
    const char *                        value_orig = "test";
    const char *                        attribute_id;
    const char *                        data_type;
    const char *                        issuer;
    const char *                        value;
    size_t                              count;
    

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "initialize a request");

    rc = xacml_resource_attribute_init(&resource);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "initialize a resource attribute");

    rc = xacml_request_add_resource_attribute(request, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "add a NULL resource attribute to request");

    rc = xacml_request_add_resource_attribute(NULL, resource);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "add a resource attribute to NULL request");

    rc = xacml_request_get_resource_attribute_count(request, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_get_resource_attribute_count with NULL count");
    rc = xacml_request_get_resource_attribute_count(NULL, &count);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_get_resource_attribute_count with NULL request");

    rc = xacml_request_get_resource_attribute_count(request, &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_resource_attribute_count");
    TEST_ASSERTION(count == 0,
                   "xacml_request_get_resource_attribute_count expect 0 attrs");

    rc = xacml_resource_attribute_add(
            resource,
            attribute_id_orig,
            data_type_orig,
            issuer_orig,
            value_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "add a resource attribute");

    rc = xacml_request_add_resource_attribute(
            request,
            resource);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_add_resource_attribute");

    rc = xacml_request_get_resource_attribute_count(request, &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_resource_attribute_count");
    TEST_ASSERTION(count == 1,
                   "xacml_request_get_resource_attribute_count");

    xacml_resource_attribute_destroy(resource);

    rc = xacml_request_get_resource_attribute(request, 2, &resource);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_get_resource_attribute");

    rc = xacml_request_get_resource_attribute(NULL, 0, &resource);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_get_resource_attribute");
    rc = xacml_request_get_resource_attribute(request, 0, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_get_resource_attribute");

    rc = xacml_request_get_resource_attribute(request, 0, &resource_copy);

    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_resource_attribute");

    rc = xacml_resource_attribute_get_count(resource_copy, &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_resource_attribute_get_count");

    TEST_ASSERTION(count == 1,
                   "xacml_resource_attribute_get_count");

    rc = xacml_resource_attribute_get_attribute(
            resource_copy,
            0,
            &attribute_id,
            &data_type,
            &issuer,
            &value);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_resource_attribute_get_attribute");
    TEST_ASSERTION(strcmp(attribute_id, attribute_id_orig) == 0,
                   "AttributeId mismatch");
    TEST_ASSERTION(strcmp(data_type, data_type_orig) == 0,
                   "DataType mismatch");
    TEST_ASSERTION(strcmp(issuer, issuer_orig) == 0,
                   "Issuer mismatch");
    TEST_ASSERTION(strcmp(value, value_orig) == 0,
                   "Value mismatch");

    xacml_request_destroy(request);

    return 0;
}
/* resource_attribute_test() */

int main()
{
    int failed = 0, i;
    test_case test_cases[] =
    {
        TEST_CASE(init_destroy_test),
        TEST_CASE(action_attribute_test),
        TEST_CASE(environment_attribute_test),
        TEST_CASE(subject_attribute_test),
        TEST_CASE(subject_test),
        TEST_CASE(resource_attribute_test)
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
