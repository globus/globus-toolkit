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

#include "xacml_i.h"

/**
 * @defgroup xacml_response Responses
 * @ingroup xacml_common
 */

/**
 * Initialize an XACML query response
 * @ ingroup xacml_response
 *
 * Creates an XACML response structure which can be used to contain a
 * response with obligations to send to a SAML / XACML client. After the
 * response is no longer needed, the caller must destroy it by calling
 * xacml_response_destroy().
 *
 * @param response
 *     Response to initialize. The value pointed to by this can be passed
 *     to other xacml_response_* functions.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_response_destroy().
 */
xacml_result_t
xacml_response_init(
    xacml_response_t *                  response)
{
    if (response == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    *response = new xacml_response_s;
    (*response)->issue_instant = 0;
    (*response)->saml_status_code = SAML_STATUS_Success;
    (*response)->decision = XACML_DECISION_Permit;
    (*response)->xacml_status_code = XACML_STATUS_ok;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_init() */

/**
 * Destroy an XACML query response
 * @ ingroup xacml_response
 *
 * Frees resources associated with an XACML response structure. After
 * calling this, the @a response value must not be used by the caller.
 *
 * @param response
 *     Response to destroy.
 *
 * @return void
 *
 * @see xacml_response_init().
 */
void
xacml_response_destroy(
    xacml_response_t                    response)
{
    delete response;
}
/* xacml_response_destroy() */

/**
 * Set the issue instant of a response
 * @ ingroup xacml_response
 * Sets the response IssueInstance to the time specified in @a issue_instant.
 * On the server, if this is not set, the XACML library will automatically add
 * one when the response is sent.
 * 
 * @param response
 *     The XACML response to inspect.
 * @param issue_instant
 *     New value of the IssueInstant.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 */
xacml_result_t
xacml_response_set_issue_instant(
    xacml_response_t                    response,
    time_t                              issue_instant)
{
    if (response == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    response->issue_instant = issue_instant;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_set_issue_instant() */

/**
 * Determine when a response was issued
 * @ ingroup xacml_response
 * Checks an SAML protocol response and copies the timestamp when it was issued
 * to the value pointed to by @a issue_instant.
 * 
 * @param response
 *     The XACML response to inspect.
 * @param issue_instant
 *     Pointer to be set to the timestamp when the response was issued.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 */
xacml_result_t
xacml_response_get_issue_instant(
    const xacml_response_t              response,
    time_t *                            issue_instant)
{
    if (response == NULL || issue_instant == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    *issue_instant = response->issue_instant;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_get_issue_instant() */

/**
 * Set the issuer of the response
 * @ ingroup xacml_response
 *
 * @param response
 *     Response to modify.
 * @param issuer
 *     Value of the issuer
 *
 * @retval XACML_RESULT_SUCCESS
 * @retval XACML_RESULT_INVALID_PARAMETER
 */
xacml_result_t
xacml_response_set_issuer(
    xacml_response_t                    response,
    const char *                        issuer)
{
    if (response == NULL || issuer == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    response->issuer = issuer;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_set_issuer() */

/**
 * Determine the name of the issuer of a response
 * @ ingroup xacml_response
 * 
 * @param response
 *     The XACML response to inspect.
 * @param issuer
 *     Pointer to be set to the name of the issuer. The caller must not free
 *     this value or access it after the response has been destroyed.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 */
xacml_result_t
xacml_response_get_issuer(
    const xacml_response_t              response,
    const char **                       issuer)
{
    if (response == NULL || issuer == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    *issuer = response->issuer == "" ? NULL : response->issuer.c_str();

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_get_issuer() */

/**
 * Set the status code of a SAML response
 * @ ingroup xacml_response
 *
 * Set the status code describing the status of a query. The
 * possible values of the status code are defined in @ref saml_status_code_t
 *
 * @param response
 *     Response to modify.
 * @param status_code
 *     New status code value.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_response_get_saml_status_code()
 */
xacml_result_t
xacml_response_set_saml_status_code(
    xacml_response_t                    response,
    saml_status_code_t                  status_code)
{
    if (response == NULL ||
        status_code < SAML_STATUS_Success ||
        status_code > SAML_STATUS_UnsupportedBinding)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    response->saml_status_code = status_code;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_set_saml_status_code() */

/**
 * Get the status code of a SAML response
 * @ ingroup xacml_response
 *
 * Retrieves the status code describing the status of the query. The possible
 * values of the status code are defined in @ref saml_status_code_t
 *
 * @param response
 *     Response to inspect.
 * @param status_code
 *     Pointer to be set to the status code.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_response_set_saml_status_code()
 */
xacml_result_t
xacml_response_get_saml_status_code(
    const xacml_response_t              response,
    saml_status_code_t *                status_code)
{
    if (response == NULL || status_code == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    *status_code = response->saml_status_code;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_get_saml_status_code() */

/**
 * Set the decision of an XACML response
 * @ ingroup xacml_response
 *
 * Set the decision value describing the result of a query. The
 * possible values of the status code are defined in @ref xacml_decision_t
 *
 * @param response
 *     Response to modify.
 * @param decision
 *     New decision value.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_response_get_xacml_decision()
 */
xacml_result_t
xacml_response_set_xacml_decision(
    xacml_response_t                    response,
    xacml_decision_t                    decision)
{
    if (response == NULL ||
        decision < XACML_DECISION_Permit ||
        decision > XACML_DECISION_NotApplicable)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    response->decision = decision;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_set_xacml_decision() */

/**
 * Get the XACML decision from a response
 * @ ingroup xacml_response
 *
 * Retrieves the decision of the response to a query. The possible
 * values of the status code are defined in @ref xacml_decision_t
 *
 * @param response
 *     Response to inspect.
 * @param decision
 *     Pointer to be set to the decision.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_response_set_xacml_decision()
 */
xacml_result_t
xacml_response_get_xacml_decision(
    const xacml_response_t              response,
    xacml_decision_t *                  decision)
{
    if (response == NULL || decision == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    *decision = response->decision;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_get_xacml_decision() */


/**
 * Set the XACML status code of a response
 * @ ingroup xacml_response
 *
 * Set the status code describing the status of a query. The
 * possible values of the status code are defined in @ref xacml_status_code_t
 *
 * @param response
 *     Response to modify.
 * @param status_code
 *     New status code value.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_response_get_xacml_status_code()
 */
xacml_result_t
xacml_response_set_xacml_status_code(
    xacml_response_t                    response,
    xacml_status_code_t                 status_code)
{
    if (response == NULL ||
        status_code < XACML_STATUS_ok ||
        status_code > XACML_STATUS_processing_error)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    response->xacml_status_code = status_code;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_set_xacml_status_code() */

/**
 * Get the XACML status code of a response
 * @ ingroup xacml_response
 *
 * Retrieves the status code describing the status of the XACML query. The
 * possible values of the status code are defined in @ref xacml_status_code_t
 *
 * @param response
 *     Response to inspect.
 * @param status_code
 *     Pointer to be set to the status code.
 * 
 * @retval XACML_RESULT_SUCCESS
 *     Success
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter
 *
 * @see xacml_response_set_xacml_status_code()
 */
xacml_result_t
xacml_response_get_xacml_status_code(
    const xacml_response_t              response,
    xacml_status_code_t *               status_code)
{
    if (response == NULL || status_code == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    *status_code = response->xacml_status_code;

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_get_xacml_status_code() */

/**
 * Add an obligation to a response
 * @ingroup xacml_request
 *
 * @param response
 *     Response to add the obligation to.
 * @param obligation
 *     Value of the obligation, including any attributes associated with it.
 *     The caller may free this obligation after this function returns.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 */
xacml_result_t
xacml_response_add_obligation(
    xacml_response_t                    response,
    const xacml_obligation_t            obligation)
{

    if (response == NULL || obligation == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    response->obligations.push_back(*obligation);

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_add_obligation() */

/**
 * Count the number of obligations in a response
 * @ingroup xacml_request
 * Modifies the value pointed to by @a count to contain the number of
 * obligations in @a response. Values from 0 to the value returned
 * in @a count can be passed to xacml_response_get_obligation() to
 * iterate through the set of obligations.
 *
 * @param response
 *     Response to inspect.
 * @param count
 *     Pointer to be set to the number of subject attributes.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_response_get_obligation()
 */
xacml_result_t
xacml_response_get_obligation_count(
    const xacml_response_t              response,
    size_t *                            count)
{
    if (response == NULL || count == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    *count = response->obligations.size();

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_get_obligation_count() */

/**
 * Get the value of an obligation
 * @ingroup xacml_response
 *
 * Retrieves the obligation based on the its index. The total number of subject
 * obligations can be determined by calling
 * xacml_response_get_obligation_count().
 * 
 * @param response
 *     The response to inspect.
 * @param num
 *     Obligation index.
 * @param obligation
 *     Pointer to be set to the obligation. The caller
 *     must not modify or free this value.
 *
 * @retval XACML_RESULT_SUCCESS
 *     Success.
 * @retval XACML_RESULT_INVALID_PARAMETER
 *     Invalid parameter.
 *
 * @see xacml_response_add_obligation(),
 *      xacml_response_get_obligation_count()
 */
xacml_result_t
xacml_response_get_obligation(
    const xacml_response_t              response,
    size_t                              num,
    xacml_obligation_t *                obligation)
{
    if (response == NULL || 
        obligation == NULL ||
        num > response->obligations.size())
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    *obligation = &response->obligations[num];

    return XACML_RESULT_SUCCESS;
}
/* xacml_response_get_obligation() */
