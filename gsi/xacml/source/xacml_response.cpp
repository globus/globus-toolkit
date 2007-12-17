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

#include "xacml_i.h"

int
xacml_response_init(
    xacml_response_t *                  response)
{
    *response = new xacml_response_s;

    return 0;
}

void
xacml_response_destroy(
    xacml_response_t                    response)
{
    delete response;
}

int
xacml_response_get_issue_instant(
    const xacml_response_t              response,
    time_t *                            issue_instant)
{
    *issue_instant = response->issue_instant;

    return 0;
}

int
xacml_response_set_issuer(
    xacml_response_t                    response,
    const char *                        issuer)
{
    response->issuer = issuer;

    return 0;
}

int
xacml_response_get_issuer(
    const xacml_response_t              response,
    const char **                       issuer)
{
    *issuer = response->issuer.c_str();

    return 0;
}

int
xacml_response_set_saml_status_code(
    xacml_response_t                    response,
    saml_status_code_t                  status_code)
{
    response->saml_status_code = status_code;

    return 0;
}

int
xacml_response_get_saml_status_code(
    const xacml_response_t              response,
    saml_status_code_t *                status_code)
{
    *status_code = response->saml_status_code;

    return 0;
}

int
xacml_response_set_xacml_decision(
    xacml_response_t                      response,
    xacml_decision_t                    decision)
{
    response->decision = decision;

    return 0;
}
int
xacml_response_get_xacml_decision(
    const xacml_response_t              response,
    xacml_decision_t *                  decision)
{
    *decision = response->decision;

    return 0;
}

int
xacml_response_set_xacml_status_code(
    xacml_response_t                    response,
    xacml_status_code_t                 status_code)
{
    response->xacml_status_code = status_code;

    return 0;
}
int
xacml_response_get_xacml_status_code(
    const xacml_response_t              response,
    xacml_status_code_t *               status_code)
{
    *status_code = response->xacml_status_code;

    return 0;
}

int
xacml_obligation_init(
    xacml_obligation_t *                obligation,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on)
{
    xacml_obligation_s *                o;

    o = new xacml_obligation_s();

    o->obligation.obligation_id = obligation_id;
    o->obligation.fulfill_on = fulfill_on;

    *obligation = o;

    return 0;
}

void
xacml_obligation_destroy(
    xacml_obligation_t                  obligation)
{
    delete obligation;
}

int
xacml_obligation_add_attribute(
    xacml_obligation_t                  obligation,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        value)
{
    xacml::obligation                   o = obligation->obligation;
    xacml::attribute                    attribute;

    attribute.attribute_id = attribute_id;
    attribute.data_type = data_type;
    attribute.value = value;

    o.attributes.push_back(attribute);

    return 0;
}

int
xacml_response_add_obligation(
    xacml_response_t                    response,
    const xacml_obligation_t            obligation)
{
    xacml::obligation                   o = obligation->obligation;

    response->obligations.push_back(o);

    return 0;
}
/* xacml_response_add_obligation() */
