#include "xacml_i.h"
#include "xacml_client.h"
#include "soapStub.h"

#include <cassert>
#include <ctime>
#include <sstream>
#include <iomanip>

namespace xacml
{
XACMLcontext__AttributeType *
xacml_create_attribute(
    const attribute &                   attribute,
    const std::string &                 issuer = "")
{
    XACMLcontext__AttributeType *       attr = new XACMLcontext__AttributeType();
    xsd__anyType *                      val;

    attr->AttributeId = attribute.attribute_id;
    attr->DataType = attribute.data_type;

    if (issuer != "")
    {
        attr->Issuer = new std::string(issuer);
    }

#if 1
    if (attribute.data_type == XACML_DATATYPE_X500_NAME ||
        attribute.data_type == XACML_DATATYPE_RFC822_NAME ||
        attribute.data_type == XACML_DATATYPE_IP_ADDRESS ||
        attribute.data_type == XACML_DATATYPE_DNS_NAME ||
        attribute.data_type == XACML_DATATYPE_STRING)
    {
        xsd__string * s = new  xsd__string();

        s->__item = attribute.value;

        val = s;
    }
    else if (attribute.data_type == XACML_DATATYPE_ANY_URI)
    {
        xsd__anyURI_ * u = new xsd__anyURI_();

        u->__item = attribute.value;
        val = u;
    }
    else if (attribute.data_type == XACML_DATATYPE_BOOLEAN)
    {
        xsd__boolean * b = new xsd__boolean();

        if (attribute.value == "true" || attribute.value == "1")
        {
            b->__item = 1;
        }
        else
        {
            b->__item = 0;
        }
        val = b;
    }
    else if (attribute.data_type == XACML_DATATYPE_INTEGER)
    {
        xsd__integer_ * i = new xsd__integer_();

        i->__item = attribute.value;
        val = i;
    }
    else if (attribute.data_type == XACML_DATATYPE_DATE_TIME)
    {
        xsd__dateTime * d = new xsd__dateTime();
        struct tm tm;

        memset(&tm, 0, sizeof(struct tm));

        sscanf(attribute.value.c_str(), "%d-%d-%dT%d%d%dZ",
               &tm.tm_year,
               &tm.tm_mon,
               &tm.tm_mday,
               &tm.tm_hour,
               &tm.tm_min,
               &tm.tm_sec);

        tm.tm_year -= 1900;
        tm.tm_mon -= 1;

        d->__item = timegm(&tm);
        val = d;
    }
    else
    {
#endif
        val = new xsd__anyType();

        val->__item = new char[attribute.value.length()+1];
        std::strcpy(val->__item, attribute.value.c_str());
    }
    attr->XACMLcontext__AttributeValue.push_back(val);

    return attr;
}
/* xacml_create_attribute() */

XACMLcontext__AttributeType *
xacml_create_current_date_time_attribute(void)
{
    time_t                              now = time(NULL);
    std::ostringstream                  os;
    attribute                           current_dateTime;
    struct tm *                         tm;

    tm = gmtime(&now);

    {
        using namespace std;

        os << setw(4) << setfill('0') << (tm->tm_year+1900) << '-'
           << setw(2) << setfill('0') << (tm->tm_mon+1) << '-'
           << setw(2) << setfill('0') << tm->tm_mday << 'T'
           << setw(2) << setfill('0') << tm->tm_hour << ':'
           << setw(2) << setfill('0') << tm->tm_min << ':'
           << setw(2) << setfill('0') << tm->tm_sec << 'Z';
    }

    current_dateTime.attribute_id = XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_DATE_TIME;
    current_dateTime.data_type = XACML_DATATYPE_DATE_TIME;
    current_dateTime.value = os.str();

    return xacml_create_attribute(current_dateTime);
}

XACMLcontext__RequestType *
create_xacml_request(
    xacml_request_t                     request)
{
    XACMLcontext__RequestType *         req = new XACMLcontext__RequestType();

    for (subject::iterator i = request->subjects.begin();
         i != request->subjects.end();
         i++)
    {
        XACMLcontext__SubjectType *     subject = new XACMLcontext__SubjectType();

        subject->SubjectCategory = i->first;

        for (attribute_set::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            for (attributes::iterator k = j->second.begin();
                 k != j->second.end();
                 k++)
            {
                subject->XACMLcontext__Attribute.push_back(
                        xacml_create_attribute(*k, j->first));
            }
        }
        req->XACMLcontext__Subject.push_back(subject);
    }

    for (resource::iterator i = request->resource_attributes.begin();
         i != request->resource_attributes.end();
         i++)
    {
        XACMLcontext__ResourceType *    resource =
                new XACMLcontext__ResourceType();

        for (attribute_set::iterator j = i->begin(); j != i->end(); j++)
        {
            for (attributes::iterator k = j->second.begin();
                 k != j->second.end();
                 k++)
            {
                resource->XACMLcontext__Attribute.push_back(
                        xacml_create_attribute(*k, j->first));
            }
        }

        req->XACMLcontext__Resource.push_back(resource);
    }

    XACMLcontext__ActionType *          action = new XACMLcontext__ActionType();
    req->XACMLcontext__Action = action;

    for (attribute_set::iterator i = request->action_attributes.begin();
         i != request->action_attributes.end();
         i++)
    {
        for (attributes::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            action->XACMLcontext__Attribute.push_back(
                    xacml_create_attribute(*j, i->first));
        }
    }
    bool env_set = false;
    XACMLcontext__EnvironmentType * env = new XACMLcontext__EnvironmentType();
    req->XACMLcontext__Environment = env;
    for (attribute_set::iterator i = request->environment_attributes.begin();
         i != request->environment_attributes.end();
         i++)
    {
        for (attributes::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            if (j->attribute_id == XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_DATE_TIME
                || j->attribute_id == XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_DATE
                || j->attribute_id == XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_TIME)
            {
                env_set = true;
            }
            env->XACMLcontext__Attribute.push_back(
                    xacml_create_attribute(*j, i->first));
        }
    }
    if (!env_set)
    {
        env->XACMLcontext__Attribute.push_back(
                xacml_create_current_date_time_attribute());
    }

    return req;
}
/* create_xacml_request() */

int
parse_xacml_response(
    samlp__ResponseType *               resp,
    xacml_response_t                    response)
{
    if (resp->saml__Issuer != NULL)
    {
        xacml_response_set_issuer(response, resp->saml__Issuer->__item.c_str());
    }

    for (int i = 0; i < SAML_STATUS_UnsupportedBinding+1; i++)
    {
        if (resp->samlp__Status->samlp__StatusCode->Value ==
                    saml_status_code_strings[i])
        {
            xacml_response_set_saml_status_code(
                    response,
                    (saml_status_code_t) i);
            break;
        }
    }

    assert(resp->__union_32 == SOAP_UNION__samlp__union_32_saml__Assertion);

    std::vector<saml__AssertionType *> * assertions =
        resp->union_32.saml__Assertion;
    XACMLassertion__XACMLAuthzDecisionStatementType * xacml_decision = NULL;

    for (std::vector<saml__AssertionType *>::iterator i = assertions->begin();
         i != assertions->end();
         i++)
    {
        if ((*i)->__union_1 ==
            SOAP_UNION__saml__union_1_XACMLassertion__XACMLAuthzDecisionStatement)
        {
            std::vector<class XACMLassertion__XACMLAuthzDecisionStatementType *>
                    *decisions = (*i)->union_1.
                            XACMLassertion__XACMLAuthzDecisionStatement;

            for (std::vector<class 
                    XACMLassertion__XACMLAuthzDecisionStatementType *>::
                    iterator j = decisions->begin();
                 j != decisions->end();
                 j++)
            {
                xacml_decision = *j;
                break;
            }
        }
    }

    if (xacml_decision == NULL)
    {
        return SOAP_SVR_FAULT;
    }

    for (std::vector<class XACMLcontext__ResultType * >::iterator i =
                xacml_decision->XACMLcontext__Response->XACMLcontext__Result.
                    begin();
        i !=xacml_decision->XACMLcontext__Response->XACMLcontext__Result.end();
        i++)
    {
        switch ((*i)->XACMLcontext__Decision)
        {
        case XACMLcontext__DecisionType__Permit:
            xacml_response_set_xacml_decision(response, XACML_DECISION_Permit);
            break;
        case XACMLcontext__DecisionType__Deny:
            xacml_response_set_xacml_decision(response, XACML_DECISION_Deny);
            break;
        case XACMLcontext__DecisionType__Indeterminate:
            xacml_response_set_xacml_decision(response,
                    XACML_DECISION_Indeterminate);
            break;
        case XACMLcontext__DecisionType__NotApplicable:
            xacml_response_set_xacml_decision(response,
                    XACML_DECISION_NotApplicable);
            break;
        }

        for (int j = 0; j < XACML_STATUS_syntax_error+1; j++)
        {
            if ((*i)->XACMLcontext__Status->XACMLcontext__StatusCode->Value ==
                xacml_status_code_strings[j])
            {
                xacml_response_set_xacml_status_code(response, 
                        (xacml_status_code_t) j);
                break;
            }
        }

        XACMLpolicy__ObligationsType * obligations =
                (*i)->XACMLpolicy__Obligations;
        for (std::vector<class XACMLpolicy__ObligationType *>::iterator j = 
                    obligations->XACMLpolicy__Obligation.begin();
             j != obligations->XACMLpolicy__Obligation.end();
             j++)
        {
            xacml::obligation obligation;

            obligation.obligation_id = (*j)->ObligationId;

            switch ((*j)->FulfillOn)
            {
            case XACMLpolicy__EffectType__Permit:
                obligation.fulfill_on = XACML_EFFECT_Permit;
                break;
            case XACMLpolicy__EffectType__Deny:
                obligation.fulfill_on = XACML_EFFECT_Deny;
                break;
            }

            for (std::vector<class XACMLpolicy__AttributeAssignmentType *>::iterator k =
                    (*j)->XACMLpolicy__AttributeAssignment.begin();
                 k != (*j)->XACMLpolicy__AttributeAssignment.end();
                 k++)
            {
                xacml::attribute attribute;

                attribute.attribute_id = (*k)->AttributeId;
                attribute.data_type = (*k)->DataType;
                attribute.value = (*k)->__mixed;

                obligation.attributes.push_back(attribute);
            }
            response->obligations.push_back(obligation);
        }
    }
    return 0;
}
/* parse_xacml_response() */
}

int
xacml_request_add_obligation_handler(
    xacml_request_t                     request,
    xacml_obligation_handler_t          handler,
    void *                              handler_arg,
    const char *                        obligation_id)
{
    xacml::obligation_handler_info      info;

    info.handler = handler;
    info.handler_arg = handler_arg;

    request->obligation_handlers[obligation_id] = info;

    return 0;
}
/* xacml_request_add_obligation_handler() */

int
xacml_request_use_ssl(
    xacml_request_t                     request,
    const char *                        certificate_path,
    const char *                        key_path,
    const char *                        ca_dir)
{
    if (certificate_path)
    {
        request->certificate_path = certificate_path;
    }
    if (key_path)
    {
        request->key_path = key_path;
    }
    if (ca_dir)
    {
        request->certificate_dir = ca_dir;
    }

    return 0;
}

int
xacml_query(
    const char *                        endpoint,
    xacml_request_t                     request,
    xacml_response_t                    response)
{
    struct soap                         soap;
    XACMLsamlp__XACMLAuthzDecisionQueryType  *
                                        query;
    samlp__ResponseType                 resp;
    int                                 rc;
    std::ostringstream                  ostr;


    query = new XACMLsamlp__XACMLAuthzDecisionQueryType;

    ostr << "ID-" << rand();
    query->ID = ostr.str();
    query->Version = "2.0";
    query->IssueInstant = time(NULL);
    query->InputContextOnly = false;
    query->ReturnContext = true;

    query->saml__Issuer = new saml__NameIDType();
    query->saml__Issuer->Format =
            new std::string(SAML_NAME_ID_FORMAT_X509_SUBJECT_NAME);
    query->saml__Issuer->__item = request->subject;

    query->XACMLcontext__Request = xacml::create_xacml_request(request);

    soap_init(&soap);

    if (strncmp(endpoint, "https:", 5) == 0 ||
        request->certificate_dir != "" ||
        request->certificate_path != "" ||
        request->key_path != "")
    {
        soap_ssl_client_context(&soap, SOAP_SSL_NO_AUTHENTICATION|SOAP_SSL_SKIP_HOST_CHECK,
                                request->certificate_path.c_str(),
                                request->key_path.c_str(),
                                NULL,
                                NULL,
                                request->certificate_dir.c_str(),
                                NULL);
    }

    rc = soap_call___XACMLService__Authorize(&soap, endpoint, NULL, query,
            &resp);

    if (rc == SOAP_OK)
    {
        rc = xacml::parse_xacml_response(&resp, response);
    }

    if (rc != SOAP_OK)
    {
        soap_print_fault(&soap, stderr);

        goto out;
    }
    for (xacml::obligations::iterator i = response->obligations.begin();
         i != response->obligations.end();
         i++)
    {
        if (request->obligation_handlers.find(i->obligation_id) !=
            request->obligation_handlers.end())
        {
            size_t s = i->attributes.size();

            const char *attribute_ids[s+1];
            const char *data_types[s+1];
            const char *values[s+1];

            for (size_t j = 0; j < s; j++)
            {
                attribute_ids[j] = i->attributes[j].attribute_id.c_str();
                data_types[j] = i->attributes[j].data_type.c_str();
                values[j] = i->attributes[j].value.c_str();
            }
            attribute_ids[s] = NULL;
            data_types[s] = NULL;
            values[s] = NULL;

            xacml::obligation_handler_info &info =
                    request->obligation_handlers[i->obligation_id];

            rc = info.handler(info.handler_arg,
                          response,
                          i->obligation_id.c_str(),
                          i->fulfill_on,
                          attribute_ids,
                          data_types,
                          values);
            if (rc != 0)
            {
                goto out;
            }
        }
    }

out:
    return rc;
}
/* query() */
