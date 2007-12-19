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

#ifndef XACML_H
#define XACML_H

#include "xacml_datatypes.h"

#include <time.h>

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_BEGIN
#endif

/**
 * @mainpage SAML 2.0 profile of XACML v2.0 Implementation
 *
 * This API provides a basic implementation of the SAML 2.0 profile of XACML
 * v2.0, including support for obligations in XACML response messages. It aids
 * in writing XACML clients and servers.
 *
 * - @link xacml_common Common Library Functions @endlink
 * - @link xacml_io XACML I/O handlers @endlink
 * - @link xacml_client Client Library Functions @endlink
 * - @link xacml_server Server Library functions @endlink
 */

/** 
 * @defgroup xacml_common Common Library Functions and Constants
 */

/**
 * @defgroup xacml_server Server Library Functions
 */

int
xacml_init(void);

int
xacml_request_init(
    xacml_request_t *                   request);

void
xacml_request_destroy(
    xacml_request_t                     request);


int
xacml_request_set_io_module(
    xacml_request_t                     request,
    const char *                        module);

int
xacml_request_set_io_descriptor(
    xacml_request_t                     request,
    const xacml_io_descriptor_t        *descriptor);

int
xacml_request_add_subject_attribute(
    xacml_request_t                     request,
    const char *                        subject_category,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value);

int
xacml_request_get_subject_attribute_count(
    const xacml_request_t               request,
    size_t *                            count);

int
xacml_request_get_subject_attribute(
    const xacml_request_t               request,
    size_t                              num,
    const char **                       subject_category,
    const char **                       attribute_id,
    const char **                       data_type,
    const char **                       issuer,
    const char **                       value);

int
xacml_request_add_resource_attribute(
    xacml_request_t                     request,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value);

int
xacml_request_add_resource_attributes(
    xacml_request_t                     request,
    const char *                        attribute_id[],
    const char *                        data_type[],
    const char *                        issuer[],
    const char *                        value[]);

int
xacml_request_add_action_attribute(
    xacml_request_t                     request,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value);

int
xacml_request_add_environment_attribute(
    xacml_request_t                     request,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value);

int
xacml_request_set_subject(
    xacml_request_t                     request,
    const char *                        subject);

/* Client Response */
int
xacml_response_init(
    xacml_response_t *                  response);

void
xacml_response_destroy(
    xacml_response_t                    response);

int
xacml_response_get_issue_instant(
    xacml_response_t                    response,
    time_t *                            issue_instant);

int
xacml_response_set_issuer(
    xacml_response_t                    response,
    const char *                        issuer);

int
xacml_response_get_issuer(
    xacml_response_t                    response,
    const char **                       issuer);

int
xacml_response_set_saml_status_code(
    xacml_response_t                    response,
    saml_status_code_t                  status_code);

int
xacml_response_get_saml_status_code(
    const xacml_response_t              response,
    saml_status_code_t *                status_code);

int
xacml_response_set_xacml_decision(
    xacml_response_t                    response,
    xacml_decision_t                    decision);

int
xacml_response_get_xacml_decision(
    const xacml_response_t              response,
    xacml_decision_t *                  decision);

int
xacml_response_set_xacml_status_code(
    xacml_response_t                    response,
    xacml_status_code_t                 status_code);

int
xacml_response_get_xacml_status_code(
    const xacml_response_t              response,
    xacml_status_code_t *               status_code);

int
xacml_obligation_init(
    xacml_obligation_t *                obligation,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on);

void
xacml_obligation_destroy(
    xacml_obligation_t                  obligation);

int
xacml_obligation_add_attribute(
    xacml_obligation_t                  obligation,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        value);

int
xacml_response_add_obligation(
    xacml_response_t                    response,
    const xacml_obligation_t            obligation);

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_END
#endif

#endif /* XACML_H */
