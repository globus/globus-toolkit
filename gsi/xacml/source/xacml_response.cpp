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
xacml_response_add_obligation(
    xacml_response_t                    response,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on,
    const char *                        attribute_id[],
    const char *                        data_type[],
    const char *                        value[])
{
    xacml::obligation                   obligation;

    obligation.obligation_id = obligation_id;
    obligation.fulfill_on = fulfill_on;

    for (int i = 0; attribute_id[i] != NULL; i++)
    {
        xacml::attribute                attribute;

        attribute.attribute_id = attribute_id[i];
        attribute.data_type = data_type[i];
        attribute.value = value[i];

        obligation.attributes.push_back(attribute);
    }
    response->obligations.push_back(obligation);

    return 0;
}
/* xacml_response_add_obligation() */
