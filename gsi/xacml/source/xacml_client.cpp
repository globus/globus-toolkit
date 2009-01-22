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
#include "xacml_client.h"
#include "xacml_authz_interop_profile.h"
#include "soapStub.h"
#include "soapH.h"

#include <cassert>
#include <ctime>
#include <sstream>
#include <iomanip>

#ifndef DONT_DOCUMENT_INTERNAL
namespace xacml
{
XACMLcontext__AttributeType *
xacml_create_attribute(
    struct soap *                       soap,
    const attribute &                   attribute,
    const std::string &                 issuer = "")
{
    XACMLcontext__AttributeType *       attr = soap_new_XACMLcontext__AttributeType(soap, -1);
    XACMLcontext__AttributeValueType *  val = soap_new_XACMLcontext__AttributeValueType(soap, -1);

    attr->AttributeId = attribute.attribute_id;
    attr->DataType = attribute.data_type;

    if (issuer != "")
    {
        attr->Issuer = soap_new_std__string(soap, -1);
        attr->Issuer->assign(issuer);
    }

    val = soap_new_XACMLcontext__AttributeValueType(soap, -1);

    val->__mixed = (char *) soap_malloc(soap, attribute.value.length()+1);
    std::strcpy(val->__mixed, attribute.value.c_str());

    attr->XACMLcontext__AttributeValue.push_back(val);

    return attr;
}
/* xacml_create_attribute() */

XACMLcontext__AttributeType *
xacml_create_current_date_time_attribute(struct soap *soap)
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

    return xacml_create_attribute(soap, current_dateTime);
}

XACMLcontext__RequestType *
create_xacml_request(
    struct soap *                       soap,
    xacml_request_t                     request)
{
    XACMLcontext__RequestType *         req = soap_new_XACMLcontext__RequestType(soap, -1);

    for (subject::iterator i = request->subjects.begin();
         i != request->subjects.end();
         i++)
    {
        XACMLcontext__SubjectType *     subject = soap_new_XACMLcontext__SubjectType(soap, -1);

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
                        xacml_create_attribute(soap, *k, j->first));
            }
        }
        req->XACMLcontext__Subject.push_back(subject);
    }

    for (resource::iterator i = request->resource_attributes.begin();
         i != request->resource_attributes.end();
         i++)
    {
        XACMLcontext__ResourceType *    resource =
                soap_new_XACMLcontext__ResourceType(soap, -1);

        for (attribute_set::iterator j = i->attributes.begin();
             j != i->attributes.end();
             j++)
        {
            for (attributes::iterator k = j->second.begin();
                 k != j->second.end();
                 k++)
            {
                resource->XACMLcontext__Attribute.push_back(
                        xacml_create_attribute(soap, *k, j->first));
            }
        }

        req->XACMLcontext__Resource.push_back(resource);
    }

    XACMLcontext__ActionType *          action = soap_new_XACMLcontext__ActionType(soap, -1);
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
                    xacml_create_attribute(soap, *j, i->first));
        }
    }
    bool env_set = false;
    XACMLcontext__EnvironmentType * env = soap_new_XACMLcontext__EnvironmentType(soap, -1);
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
                    xacml_create_attribute(soap, *j, i->first));
        }
    }
    if (!env_set)
    {
        env->XACMLcontext__Attribute.push_back(
                xacml_create_current_date_time_attribute(soap));
    }

    // Add Environment attribute indicating what obligations we understand
    for (xacml::obligation_handlers::iterator i =
                request->obligation_handlers.begin();
         i != request->obligation_handlers.end();
         i++)
    {
        // Ignore default obligation handler
        if (i->first == "")
        {
            continue;
        }

        xacml::attribute a;

        a.attribute_id = xacml_interop_profile_environment_attr_strings[
                XACML_INTEROP_ENV_PEP_OBLIG_SUPPORTED];
        a.data_type = XACML_DATATYPE_STRING;
        a.value = i->first;

        env->XACMLcontext__Attribute.push_back(
                xacml_create_attribute(soap, a));
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

    if (resp->samlp__Status != NULL)
    {
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
    }

    XACMLassertion__XACMLAuthzDecisionStatementType * xacml_decision = NULL;

    for (int i = 0; i < resp->__size_33; i++)
    {
        switch (resp->__union_33[i].__union_33)
        {
        case SOAP_UNION__samlp__union_33_saml__Assertion:
            {
                saml__AssertionType * assertion = 
                        resp->__union_33[i].union_33.saml__Assertion;

                for (int j = 0; j < assertion->__size_1; j++)
                {
                    switch (assertion->__union_1[i].__union_1)
                    {
                    case SOAP_UNION__saml__union_1_saml__Statement:
                        xacml_decision =
                                static_cast<XACMLassertion__XACMLAuthzDecisionStatementType *>(assertion->__union_1[i].union_1.saml__Statement);
                        break;
                    case SOAP_UNION__saml__union_1_saml__AuthnStatement:
                    case SOAP_UNION__saml__union_1_saml__AuthzDecisionStatement:
                    case SOAP_UNION__saml__union_1_saml__AttributeStatement:
                        assert(assertion->__union_1[i].__union_1 ==
                                    SOAP_UNION__saml__union_1_saml__Statement);
                        break;
                    }
                }
            }
        case SOAP_UNION__samlp__union_33_saml__EncryptedAssertion:
            assert(resp->__union_33[i].__union_33 ==
                   SOAP_UNION__samlp__union_33_saml__Assertion);
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

        if (obligations)
        {
            for (std::vector<class XACMLpolicy__ObligationType *>::iterator j = 
                        obligations->XACMLpolicy__Obligation.begin();
                 j != obligations->XACMLpolicy__Obligation.end();
                 j++)
            {
                struct xacml_obligation_s obligation;

                obligation.obligation.obligation_id = (*j)->ObligationId;

                switch ((*j)->FulfillOn)
                {
                case XACMLpolicy__EffectType__Permit:
                    obligation.obligation.fulfill_on = XACML_EFFECT_Permit;
                    break;
                case XACMLpolicy__EffectType__Deny:
                    obligation.obligation.fulfill_on = XACML_EFFECT_Deny;
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

                    obligation.obligation.attributes.push_back(attribute);
                }
                response->obligations.push_back(obligation);
            }
        }
    }
    return 0;
}
/* parse_xacml_response() */
}
#endif /* DONT_DOCUMENT_INTERNAL */

/**
 Add an obligation handler to an XACML request handle
 @ingroup xacml_client

 Creates a new obligation handler for the Obligation named @a obligation_id.
 When an XACML response is sent that includes such an obligation, this
 function will be invoked. See @ref xacml_obligation_handler_t for a
 description of the parameters to the handler. 
 
 @param request
     Client request to add the obligation handler to.
 @param handler
     Callback function to invoke when an obligation matching @a obligation_id
     is encountered while processing an XACML response.
 @param handler_arg
     Application-specific parameter to @a handler.
 @param obligation_id
     If this is NULL, then this handler will be invoked as a default
     obligation handler when no other obligation handler matches the
     @a obligation_id name.
 
 @retval XACML_RESULT_SUCCESS
     XACML handler successfully registered with the request.
 @retval XACML_RESULT_INVALID_PARAMETER
     Invalid parameter.
 */
xacml_result_t
xacml_request_add_obligation_handler(
    xacml_request_t                     request,
    xacml_obligation_handler_t          handler,
    void *                              handler_arg,
    const char *                        obligation_id)
{
    xacml::obligation_handler_info      info;

    if (request == NULL || handler == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    info.handler = handler;
    info.handler_arg = handler_arg;

    request->obligation_handlers[obligation_id == NULL ? "" : obligation_id] =
            info;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_add_obligation_handler() */


/**
 Perform an XACML authorization query
 @ingroup xacml_client

 Contact an XACML server processing requests at the named endpoint and present
 an authorization query. After the server responds, obligation handlers
 registered with @ref xacml_request_add_obligation_handler() will be invoked.
 Any failure returned from the obligation handlers will cause this function
 to return an error value.

 @param endpoint
     Endpoint of the authorization service to contact.
 @param request
     Request handle containing the authorization request information.
 @param response
     Initialized response handle which will be populated with the status values
     from the authorization service.

 @retval XACML_RESULT_SUCCESS
     Success.
 @retval XACML_RESULT_INVALID_PARAMETER
     Invalid parameter.
 @retval XACML_RESULT_OBLIGATION_FAILED
     Failed obligation processing.
 */
xacml_result_t
xacml_query(
    const char *                        endpoint,
    xacml_request_t                     request,
    xacml_response_t                    response)
{
    struct soap                         soap;
    XACMLsamlp__XACMLAuthzDecisionQueryType  *
                                        query = NULL;
    samlp__ResponseType                 resp;
    int                                 r;
    xacml_result_t                      rc = XACML_RESULT_SUCCESS;
    std::ostringstream                  ostr;

    if (endpoint == NULL || request == NULL || response == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    soap_init(&soap);

    query = soap_new_XACMLsamlp__XACMLAuthzDecisionQueryType(&soap, -1);

    ostr << "ID-" << rand();
    query->ID = ostr.str();
    query->Version = "2.0";
    query->IssueInstant = time(NULL);
    query->InputContextOnly = false;
    query->ReturnContext = true;

    query->saml__Issuer = soap_new_saml__NameIDType(&soap, -1);
    query->saml__Issuer->Format =
            soap_new_std__string(&soap, -1);
    query->saml__Issuer->Format->assign(SAML_NAME_ID_FORMAT_X509_SUBJECT_NAME);
    query->saml__Issuer->__item = request->subject;

    query->XACMLcontext__Request = xacml::create_xacml_request(&soap, request);

    if (request->connect_func != NULL)
    {
        /* Use custom I/O handler wrappers */
        soap.user = request;
        soap.fopen = xacml_i_connect;
        soap.fsend = xacml_i_send;
        soap.frecv = xacml_i_recv;
        soap.fclose = xacml_i_close;
    }

    r = soap_call___XACMLService__Authorize(&soap, endpoint, NULL, query,
            &resp);

    if (r == SOAP_OK)
    {
        r = xacml::parse_xacml_response(&resp, response);
    }

    if (r != XACML_RESULT_SUCCESS)
    {
        soap_print_fault(&soap, stderr);
        rc = XACML_RESULT_SOAP_ERROR;

        goto out;
    }
    for (xacml::obligations::iterator i = response->obligations.begin();
         i != response->obligations.end();
         i++)
    {
        xacml::obligation_handlers::iterator ii;

        if (((ii = request->obligation_handlers.find(i->obligation.obligation_id)) !=
            request->obligation_handlers.end()) ||
            ((ii = request->obligation_handlers.find("")) !=
            request->obligation_handlers.end()))
        {
            size_t s = i->obligation.attributes.size();

            const char *attribute_ids[s+1];
            const char *data_types[s+1];
            const char *values[s+1];

            for (size_t j = 0; j < s; j++)
            {
                attribute_ids[j] = i->obligation.attributes[j].attribute_id.c_str();
                data_types[j] = i->obligation.attributes[j].data_type.c_str();
                values[j] = i->obligation.attributes[j].value.c_str();
            }
            attribute_ids[s] = NULL;
            data_types[s] = NULL;
            values[s] = NULL;

            xacml::obligation_handler_info &info = ii->second;

            r = info.handler(info.handler_arg,
                          response,
                          i->obligation.obligation_id.c_str(),
                          i->obligation.fulfill_on,
                          attribute_ids,
                          data_types,
                          values);
            if (r != 0)
            {
                rc = XACML_RESULT_OBLIGATION_FAILED;
                goto out;
            }
        }
    }

out:
    return rc;
}
/* xacml_query() */
