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
    xacml_response_t                    response;

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_response_init(NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "initialize null param");

    xacml_response_destroy(response);

    xacml_response_destroy(NULL);

    return 0;
}
/* init_destroy_test() */

int
issue_instant_test(void)
{
    int                                 rc;
    xacml_response_t                    response;
    time_t                              issue_instant_orig = time(NULL);
    time_t                              issue_instant;

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_response_get_issue_instant(response, &issue_instant);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_issue_instant");

    rc = xacml_response_set_issue_instant(response, issue_instant_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_set_issue_instant");

    rc = xacml_response_get_issue_instant(response, &issue_instant);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_issue_instant");
    TEST_ASSERTION(issue_instant == issue_instant_orig,
                   "xacml_response_get_issue_instant");

    rc = xacml_response_set_issue_instant(NULL, issue_instant_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_issue_instant");

    rc = xacml_response_get_issue_instant(NULL, &issue_instant);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_issue_instant");

    rc = xacml_response_get_issue_instant(response, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_issue_instant");

    xacml_response_destroy(response);

    return 0;
}
/* issue_instant_test() */

int
issuer_test(void)
{
    int                                 rc;
    xacml_response_t                    response;
    char *                              issuer_orig = "me";
    const char *                        issuer;

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_response_get_issuer(response, &issuer);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_issuer");
    TEST_ASSERTION(issuer == NULL,
                   "xacml_response_get_issuer");

    rc = xacml_response_set_issuer(response, issuer_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_set_issuer");

    rc = xacml_response_get_issuer(response, &issuer);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_issuer");
    TEST_ASSERTION(strcmp(issuer, issuer_orig) == 0,
                   "xacml_response_get_issuer");

    rc = xacml_response_set_issuer(NULL, issuer_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_issuer");

    rc = xacml_response_set_issuer(response, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_issuer");

    rc = xacml_response_get_issuer(NULL, &issuer);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_issuer");

    rc = xacml_response_get_issuer(response, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_issuer");

    xacml_response_destroy(response);

    return 0;
}
/* issuer_test() */

int
saml_status_code_test(void)
{
    int                                 rc;
    xacml_response_t                    response;
    saml_status_code_t                  status_code_orig = SAML_STATUS_Responder;
    saml_status_code_t                  status_code = SAML_STATUS_Success;

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_response_set_saml_status_code(response, status_code_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_set_saml_status_code");

    rc = xacml_response_get_saml_status_code(response, &status_code);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_saml_status_code");
    TEST_ASSERTION(status_code == status_code_orig,
                   "xacml_response_set_saml_status_code");

    rc = xacml_response_set_saml_status_code(NULL, status_code_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_saml_status_code");

    rc = xacml_response_set_saml_status_code(response, 10000);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_saml_status_code");

    rc = xacml_response_get_saml_status_code(NULL, &status_code);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_saml_status_code");

    rc = xacml_response_get_saml_status_code(response, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_saml_status_code");

    xacml_response_destroy(response);

    return 0;
}
/* saml_status_code_test() */

int
xacml_decision_test(void)
{
    int                                 rc;
    xacml_response_t                    response;
    xacml_decision_t                    decision_orig = XACML_DECISION_Indeterminate;
    xacml_decision_t                    decision;

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_response_set_xacml_decision(response, decision_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_set_xacml_decision");

    rc = xacml_response_get_xacml_decision(response, &decision);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_xacml_decision");
    TEST_ASSERTION(decision == decision_orig,
                   "xacml_response_get_xacml_decision");

    rc = xacml_response_set_xacml_decision(NULL, decision_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_xacml_decision");

    rc = xacml_response_set_xacml_decision(response, 10000);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_xacml_decision");

    rc = xacml_response_get_xacml_decision(NULL, &decision);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_xacml_decision");

    rc = xacml_response_get_xacml_decision(response, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_xacml_decision");

    xacml_response_destroy(response);

    return 0;
}
/* xacml_decision_test() */

int
xacml_status_code_test(void)
{
    int                                 rc;
    xacml_response_t                    response;
    xacml_status_code_t                 status_orig = XACML_STATUS_syntax_error;
    xacml_status_code_t                 status;

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_response_set_xacml_status_code(response, status_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_set_xacml_status_code");

    rc = xacml_response_get_xacml_status_code(response, &status);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_xacml_status_code");
    TEST_ASSERTION(status == status_orig,
                   "xacml_response_get_xacml_status_code");

    rc = xacml_response_set_xacml_status_code(NULL, status_orig);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_xacml_status_code");

    rc = xacml_response_set_xacml_status_code(response, 10000);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_set_xacml_status_code");

    rc = xacml_response_get_xacml_status_code(NULL, &status);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_xacml_status_code");

    rc = xacml_response_get_xacml_status_code(response, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_xacml_status_code");

    xacml_response_destroy(response);

    return 0;
}
/* xacml_status_code_test() */

int
obligation_test(void)
{
    int                                 rc;
    xacml_response_t                    response;
    xacml_obligation_t                  obligation;
    xacml_effect_t                      effect_orig = XACML_EFFECT_Permit;
    const char *                        obligation_id_orig = "obligation";
    const char *                        obligation_id;
    xacml_effect_t                      effect;
    size_t                              count;

    rc = xacml_response_init(&response);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS, "xacml_response_init");

    rc = xacml_response_get_obligation_count(response, NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_obligation_count");

    rc = xacml_response_get_obligation_count(NULL, &count);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_obligation_count");

    rc = xacml_response_get_obligation_count(response, &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_obligation_count");
    TEST_ASSERTION(count == 0,
                   "xacml_response_get_obligation_count");

    rc = xacml_obligation_init(
            &obligation,
            obligation_id_orig,
            effect_orig);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_init");
    TEST_ASSERTION(obligation != NULL,
                   "xacml_obligation_init");

    rc = xacml_response_add_obligation(
            NULL,
            obligation);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_add_obligation");

    rc = xacml_response_add_obligation(
            response,
            NULL);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_add_obligation");

    rc = xacml_response_add_obligation(
            response,
            obligation);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_add_obligation");

    rc = xacml_response_get_obligation_count(
            response,
            &count);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_obligation_count");
    TEST_ASSERTION(count == 1,
                   "xacml_response_get_obligation_count");

    xacml_obligation_destroy(obligation);

    rc = xacml_response_get_obligation(
            NULL,
            0,
            &obligation);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_obligation");

    rc = xacml_response_get_obligation(
            response,
            100,
            &obligation);
    TEST_ASSERTION(rc == XACML_RESULT_INVALID_PARAMETER,
                   "xacml_response_get_obligation");

    rc = xacml_response_get_obligation(
            response,
            0,
            &obligation);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_response_get_obligation");

    rc = xacml_obligation_get_id(
            obligation,
            &obligation_id);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_get_id");
    TEST_ASSERTION(strcmp(obligation_id, obligation_id_orig) == 0,
                   "xacml_obligation_get_id");

    rc = xacml_obligation_get_effect(
            obligation,
            &effect);
    TEST_ASSERTION(rc == XACML_RESULT_SUCCESS,
                   "xacml_obligation_get_effect");
    TEST_ASSERTION(effect == effect_orig,
                   "xacml_obligation_get_effect");

    xacml_response_destroy(response);

    return 0;
}
/* obligation_test() */

int main()
{
    int failed = 0, i;
    test_case test_cases[] =
    {
        TEST_CASE(init_destroy_test),
        TEST_CASE(issue_instant_test),
        TEST_CASE(issuer_test),
        TEST_CASE(saml_status_code_test),
        TEST_CASE(xacml_decision_test),
        TEST_CASE(xacml_status_code_test),
        TEST_CASE(obligation_test)
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
