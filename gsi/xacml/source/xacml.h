#ifndef XACML_H
#define XACML_H

#include "xacml_datatypes.h"

#include <time.h>

EXTERN_C_BEGIN

int
xacml_init(void);

int
xacml_request_init(
    xacml_request_t *                   request);

void
xacml_request_destroy(
    xacml_request_t                     request);

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
xacml_response_add_obligation(
    xacml_response_t                    response,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on,
    const char *                        attribute_id[],
    const char *                        data_type[],
    const char *                        value[]);

EXTERN_C_END

#endif /* XACML_H */
