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
#include "xacml_server.h"
#include "xacml_client.h"

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
test_obligation_handler(
    void *                              handler_arg,
    const xacml_response_t              response,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on,
    const char *                        attribute_ids[],
    const char *                        datatypes[],
    const char *                        values[])
{
    if (strcmp(obligation_id, handler_arg) == 0)
    {
        return XACML_RESULT_SUCCESS;
    }
    else
    {
        return XACML_RESULT_OBLIGATION_FAILED;
    }
}
/* test_obligation_handler() */

int
test_compare_resource_attribute(
    const xacml_resource_attribute_t    a,
    const xacml_resource_attribute_t    b)
{
    int                                 rc;
    int *                               compared;
    size_t                              i;
    size_t                              j;
    size_t                              count[2];
    const char *                        attribute_id[2];
    const char *                        data_type[2];
    const char *                        issuer[2];
    const char *                        value[2];

    rc = xacml_resource_attribute_get_count(
            a,
            &count[0]);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_resource_attribute_get_count");
    rc = xacml_resource_attribute_get_count(
            b,
            &count[1]);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_resource_attribute_get_count");
    if (count[0] != count[1])
    {
        return -1;
    }

    compared = calloc(count[0], sizeof(int));
    TEST_ASSERTION(compared != NULL, "calloc");

    for (i = 0 ; i < count[0]; i++)
    {
        rc = xacml_resource_attribute_get_attribute(
                a,
                i,
                &attribute_id[0],
                &data_type[0],
                &issuer[0],
                &value[0]);

        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_get_resource_attribute");

        for (j = 0; j < count[0]; j++)
        {
            if (compared[j])
            {
                continue;
            }

            rc = xacml_resource_attribute_get_attribute(
                    a,
                    i,
                    &attribute_id[1],
                    &data_type[1],
                    &issuer[1],
                    &value[1]);

            if (rc != XACML_RESULT_SUCCESS)
            {
                free(compared);

                TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                               "xacml_request_get_resource_attribute");
            }

            if (strcmp(attribute_id[0], attribute_id[1]) != 0)
            {
                continue;
            }
            if (strcmp(data_type[0], data_type[1]) != 0)
            {
                continue;
            }
            if (strcmp(issuer[0], issuer[1]) != 0)
            {
                continue;
            }
            if (strcmp(value[0], value[1]) != 0)
            {
                continue;
            }

            compared[j] = 1;
            break;
        }

        if (j == count[1])
        {
            free(compared);
            rc = -1;
        }
    }
    free(compared);

    return rc;
}
/* test_compare_resource_attribute() */

int
test_compare_resource_attributes(
    const xacml_request_t               a,
    const xacml_request_t               b)
{
    int                                 rc;
    size_t                              i;
    size_t                              j;
    int *                               compared;
    size_t                              count[2];
    xacml_resource_attribute_t          resource_attribute[2];

    rc = xacml_request_get_resource_attribute_count(a, &count[0]);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_resource_attribute_count");
    rc = xacml_request_get_resource_attribute_count(b, &count[1]);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_resource_attribute_count");
    TEST_ASSERTION(count[0] == count[1],
                   "xacml_request_get_resource_attribute_count");

    compared = calloc(count[0], sizeof(int));

    for (i = 0 ; i < count[0]; i++)
    {
        rc = xacml_request_get_resource_attribute(
                a,
                i,
                &resource_attribute[0]);

        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_get_resource_attribute");

        for (j = 0; j < count[0]; j++)
        {
            if (compared[j])
            {
                continue;
            }

            rc = xacml_request_get_resource_attribute(
                    b,
                    j,
                    &resource_attribute[1]);
            if (rc != XACML_RESULT_SUCCESS)
            {
                free(compared);
                TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                               "xacml_request_get_resource_attribute");
            }

            rc = test_compare_resource_attribute(
                    resource_attribute[0],
                    resource_attribute[1]);

            if (rc == XACML_RESULT_SUCCESS)
            {
                compared[j] = 1;
                break;
            }
        }

        if (j == count[1])
        {
            free(compared);
            TEST_ASSERTION(j != count[i],
                           "action attribute mismatch");
        }
    }

    for (i = 0; i < count[0]; i++)
    {
        if (compared[i] == 0)
        {
            free(compared);
            TEST_ASSERTION(compared[i] == 1,
                           "action attribute missing");
        }
    }
    free(compared);

    return XACML_RESULT_SUCCESS;
}
/* test_compare_resource_attributes() */

int
test_compare_subject_attributes(
    const xacml_request_t               a,
    const xacml_request_t               b)
{
    int                                 rc;
    size_t                              i;
    size_t                              j;
    int *                               compared;
    size_t                              count[2];
    const char *                        subject_category[2];
    const char *                        attribute_id[2];
    const char *                        data_type[2];
    const char *                        issuer[2];
    const char *                        value[2];

    rc = xacml_request_get_subject_attribute_count(a, &count[0]);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_subject_attribute_count");
    rc = xacml_request_get_subject_attribute_count(b, &count[1]);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_subject_attribute_count");
    TEST_ASSERTION(count[0] == count[1],
                   "xacml_request_get_subject_attribute_count");

    compared = calloc(count[0], sizeof(int));

    for (i = 0 ; i < count[0]; i++)
    {
        rc = xacml_request_get_subject_attribute(
                a,
                i,
                &subject_category[0],
                &attribute_id[0],
                &data_type[0],
                &issuer[0],
                &value[0]);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_get_subject_attribute");

        for (j = 0; j < count[0]; j++)
        {
            if (compared[j])
            {
                continue;
            }

            rc = xacml_request_get_subject_attribute(
                    b,
                    j,
                    &subject_category[1],
                    &attribute_id[1],
                    &data_type[1],
                    &issuer[1],
                    &value[1]);
            TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                           "xacml_request_get_subject_attribute");

            if (strcmp(subject_category[0], subject_category[1]) != 0)
            {
                continue;
            }
            if (strcmp(attribute_id[0], attribute_id[1]) != 0)
            {
                continue;
            }
            if (strcmp(data_type[0], data_type[1]) != 0)
            {
                continue;
            }
            if (issuer[0] != issuer[1] && strcmp(issuer[0], issuer[1]) != 0)
            {
                continue;
            }
            if (strcmp(value[0], value[1]) != 0)
            {
                continue;
            }

            compared[j] = 1;
            break;
        }

        if (j == count[1])
        {
            free(compared);
            TEST_ASSERTION(j != count[i],
                           "subject attribute mismatch");
        }
    }

    for (i = 0; i < count[0]; i++)
    {
        if (compared[i] == 0)
        {
            free(compared);
            TEST_ASSERTION(compared[i] == 1,
                           "subject attribute missing");
        }
    }
    free(compared);

    return XACML_RESULT_SUCCESS;
}
/* test_compare_subject_attributes() */

int
test_compare_action_attributes(
    const xacml_request_t               a,
    const xacml_request_t               b)
{
    int                                 rc;
    size_t                              i;
    size_t                              j;
    int *                               compared;
    size_t                              count[2];
    const char *                        attribute_id[2];
    const char *                        data_type[2];
    const char *                        issuer[2];
    const char *                        value[2];

    rc = xacml_request_get_action_attribute_count(a, &count[0]);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_action_attribute_count");
    rc = xacml_request_get_action_attribute_count(b, &count[1]);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_action_attribute_count");
    TEST_ASSERTION(count[0] == count[1],
                   "xacml_request_get_action_attribute_count");

    compared = calloc(count[0], sizeof(int));

    for (i = 0 ; i < count[0]; i++)
    {
        rc = xacml_request_get_action_attribute(
                a,
                i,
                &attribute_id[0],
                &data_type[0],
                &issuer[0],
                &value[0]);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_get_action_attribute");

        for (j = 0; j < count[0]; j++)
        {
            if (compared[j])
            {
                continue;
            }

            rc = xacml_request_get_action_attribute(
                    b,
                    j,
                    &attribute_id[1],
                    &data_type[1],
                    &issuer[1],
                    &value[1]);
            TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                           "xacml_request_get_action_attribute");

            if (strcmp(attribute_id[0], attribute_id[1]) != 0)
            {
                continue;
            }
            if (strcmp(data_type[0], data_type[1]) != 0)
            {
                continue;
            }
            if (issuer[0] != issuer[1] && strcmp(issuer[0], issuer[1]) != 0)
            {
                continue;
            }
            if (strcmp(value[0], value[1]) != 0)
            {
                continue;
            }

            compared[j] = 1;
            break;
        }

        if (j == count[1])
        {
            free(compared);
            TEST_ASSERTION(j != count[i],
                           "action attribute mismatch");
        }
    }

    for (i = 0; i < count[0]; i++)
    {
        if (compared[i] == 0)
        {
            free(compared);
            TEST_ASSERTION(compared[i] == 1,
                           "action attribute missing");
        }
    }
    free(compared);

    return XACML_RESULT_SUCCESS;
}
/* test_compare_action_attributes() */

int
test_auth_handler(
    void *                              handler_arg,
    const xacml_request_t               request,
    xacml_response_t                    response)
{
    int                                 rc;
    size_t                              i, count;
    xacml_request_t                     orig_request = handler_arg;

    rc = xacml_response_set_issuer(response, "me");
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_set_issuer");

    /* Compare orig request that the client sent and the one we received
     * from the XML parser
     */
    rc = test_compare_subject_attributes(request, orig_request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "test_compare_subject_attributes");

    rc = test_compare_action_attributes(request, orig_request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "test_compare_action_attributes");

    rc = test_compare_resource_attributes(request, orig_request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "test_compare_resource_attributes");

    /* If there's an obligation handler, add that obligation to the response */
    rc = xacml_request_get_environment_attribute_count(
            request,
            &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_get_environment_attribute_count");

    for (i = 0; i < count; i++)
    {
        xacml_obligation_t              obligation;
        const char *                    attribute_id;
        const char *                    data_type;
        const char *                    issuer;
        const char *                    value;

        rc = xacml_request_get_environment_attribute(
                request,
                i,
                &attribute_id,
                &data_type,
                &issuer,
                &value);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_get_environment_attribute");

        if (strcmp(attribute_id, "supportedObligations") == 0)
        {
            rc = xacml_obligation_init(
                    &obligation,
                    value,
                    XACML_EFFECT_Permit);
            TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                           "xacml_obligation_init");

            rc = xacml_response_add_obligation(response, obligation);
            TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                           "xacml_response_add_obligation");
            xacml_obligation_destroy(obligation);
        }
    }

    return rc;
}
/* test_auth_handler() */

int
query_test(void)
{
    xacml_result_t                      rc;
    xacml_server_t                      server;
    xacml_request_t                     request;
    xacml_response_t                    response;
    unsigned short                      port;
    char                                endpoint[] = "http://localhost:XXXXXX";

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_request_init");

    rc = xacml_server_init(&server, test_auth_handler, request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");

    rc = xacml_server_set_port(server, 0);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

    rc = xacml_server_start(server);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

    rc = xacml_server_get_port(server, &port);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_get_port");

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_query(endpoint, request, response);
    TEST_ASSERTION(rc == XACML_RESULT_SOAP_ERROR, "xacml_query");

    sprintf(endpoint, "http://localhost:%hu", port);

    rc = xacml_query(NULL, request, response);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER, "xacml_query");

    rc = xacml_query(endpoint, NULL, response);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER, "xacml_query");

    rc = xacml_query(endpoint, request, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER, "xacml_query");

    rc = xacml_query(endpoint, request, response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_query");

    xacml_request_destroy(request);
    xacml_response_destroy(response);
    xacml_server_destroy(server);

    return 0;
}
/* query_test() */

int
query_with_attributes_test(void)
{
    xacml_result_t                      rc;
    xacml_server_t                      server;
    xacml_request_t                     request;
    xacml_response_t                    response;
    size_t                              i, j;
    unsigned short                      port;
    xacml_resource_attribute_t          resource_attribute;
    char                                endpoint[] = "http://localhost:XXXXXX";
    char                                action[] = "actionXX";
    char                                subject[] = "subjectXX";
    char                                environment[] = "environmentXX";
    char                                attribute[] = "attribuetXX";
    char                                issuer[] = "me";

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_request_init");

    rc = xacml_server_init(&server, test_auth_handler, request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");

    rc = xacml_server_set_port(server, 0);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

    rc = xacml_server_start(server);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

    rc = xacml_server_get_port(server, &port);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_get_port");

    sprintf(endpoint, "http://localhost:%hu", port);

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    for (i = 0; i < 10; i++)
    {
        sprintf(action, "action%02d", i+1);

        rc = xacml_request_add_action_attribute(
                request,
                action,
                XACML_DATATYPE_STRING,
                NULL,
                action);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_add_action_attribute");
    }

    for (i = 0; i < 10; i++)
    {
        sprintf(subject, "subject%02d", i+1);

        rc = xacml_request_add_subject_attribute(
                request,
                XACML_SUBJECT_CATEGORY_ACCESS_SUBJECT,
                subject,
                XACML_DATATYPE_STRING,
                NULL,
                subject);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_add_subject_attribute");
    }

    for (i = 0; i < 10; i++)
    {
        sprintf(environment, "environment%02d", i+1);

        rc = xacml_request_add_environment_attribute(
                request,
                environment,
                XACML_DATATYPE_STRING,
                issuer,
                environment);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_add_environment_attribute");
    }

    for (i = 0; i < 10; i++)
    {
        rc = xacml_resource_attribute_init(&resource_attribute);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_resource_attribute_init");

        for (j = 0; j < 10; j++)
        {

            sprintf(attribute, "attribute%02d", j);

            rc = xacml_resource_attribute_add(
                    resource_attribute,
                    attribute,
                    XACML_DATATYPE_STRING,
                    issuer,
                    attribute);
            TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                           "xacml_resource_attribute_init");
        }

        rc = xacml_request_add_resource_attribute(
                request,
                resource_attribute);
        TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                       "xacml_request_add_resource_attribute");

        xacml_resource_attribute_destroy(resource_attribute);
    }

    rc = xacml_query(endpoint, request, response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_query");

    xacml_server_destroy(server);

    return 0;
}
/* query_with_attribute_test() */

int
obligation_handler_test(void)
{
    xacml_result_t                      rc;
    xacml_request_t                     request;
    xacml_response_t                    response;
    xacml_server_t                      server;
    unsigned short                      port;
    char                                endpoint[] = "http://localhost:XXXXXX";

    rc = xacml_request_init(&request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_request_init");

    rc = xacml_server_init(&server, test_auth_handler, request);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_init");

    rc = xacml_server_set_port(server, 0);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

    rc = xacml_server_start(server);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_start");

    rc = xacml_server_get_port(server, &port);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_server_get_port");

    sprintf(endpoint, "http://localhost:%hu", port);

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_request_add_obligation_handler(
        request,
        NULL,
        NULL,
        "obligation");
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_add_obligation_handler");

    rc = xacml_request_add_obligation_handler(
        NULL,
        test_obligation_handler,
        NULL,
        "obligation");
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_request_add_obligation_handler");

    rc = xacml_request_add_obligation_handler(
        request,
        test_obligation_handler,
        "obligation",
        "obligation");
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_request_add_obligation_handler");

    rc = xacml_query(endpoint, request, response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_query");

    xacml_server_destroy(server);

    return 0;

}
/* obligation_handler_test() */

int main()
{
    int failed = 0, i;
    test_case test_cases[] =
    {
        TEST_CASE(query_test),
        TEST_CASE(query_with_attributes_test),
        TEST_CASE(obligation_handler_test)
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
