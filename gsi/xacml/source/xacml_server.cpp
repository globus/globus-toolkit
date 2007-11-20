#include "soapH.h"

#include "xacml_server.h"
#include "xacml_i.h"

#include <limits.h>
#include <unistd.h>

#include <cassert>
#include <sstream>
#include <iomanip>

#ifndef _POSIX_HOST_NAME_MAX
#   define _POSIX_HOST_NAME_MAX 255
#endif

namespace xacml
{
void *
service_thread(void * arg)
{
    bool use_ssl = false;
    xacml_server_t server = (xacml_server_t) arg;
    struct soap soap;
    char hostname[_POSIX_HOST_NAME_MAX+1];

    gethostname(hostname, _POSIX_HOST_NAME_MAX);

    pthread_mutex_lock(&server->lock);

    soap_init(&soap);
    soap.send_timeout = 10; 
    soap.recv_timeout = 10;
    soap.accept_timeout = 2; 
    soap.bind_flags = SO_REUSEADDR;
    soap.user = server;

    if (server->cert_path != "" ||
        server->key_path != "" ||
        server->ca_path != "")
    {
        use_ssl = true;
        soap_ssl_server_context(&soap, SOAP_SSL_DEFAULT | SOAP_SSL_SKIP_HOST_CHECK,
                                server->cert_path.c_str(),
                                server->key_path.c_str(),
                                NULL,
                                NULL,
                                server->ca_path.c_str(),
                                NULL,
                                NULL,
                                NULL);
    }

    server->listener = soap_bind(&soap, hostname, server->port, 100);
    if (server->listener < 0)
    {
        server->started = false;
        goto out;
    }

    while (! server->stopped) 
    {
        pthread_mutex_unlock(&server->lock);

        int s;
        int rc;

        s = soap_accept(&soap);
        if (s < 0)
            continue;
        if (use_ssl)
        {
            rc = soap_ssl_accept(&soap);

            if (rc != SOAP_OK)
            {
                soap_print_fault(&soap, stderr);
            }
        }
        soap_serve(&soap);
        soap_destroy(&soap);
        soap_end(&soap);

        pthread_mutex_lock(&server->lock);
    }
out:
    server->started = false;
    soap_done(&soap);
    pthread_cond_signal(&server->cond);
    pthread_mutex_unlock(&server->lock);

    return NULL;
}

void
extract_attribute_value(
    class xsd__anyType *                attribute,
    std::string &                       value)
{
    value = attribute->__item;
}

int
parse_xacml_query(
    const struct XACMLsamlp__XACMLAuthzDecisionQueryType *
                                        query,
    xacml_request_t *                   requestp)
{
    xacml_request_t                     request;
    XACMLcontext__RequestType *         req = query->XACMLcontext__Request;

    xacml_request_init(&request);

    xacml_request_set_subject(
            request,
            query->saml__Issuer->__item.c_str());

    for (std::vector<class XACMLcontext__SubjectType * >::iterator i =
                req->XACMLcontext__Subject.begin();
        i != req->XACMLcontext__Subject.end();
        i++)
    {
        if (*i == NULL)
        {
            continue;
        }

        for (std::vector<class XACMLcontext__AttributeType * >::iterator j =
            (*i)->XACMLcontext__Attribute.begin();
            j != (*i)->XACMLcontext__Attribute.end();
            j++)
        {
            for (std::vector<class XACMLcontext__AttributeValueType *>::iterator k =
                        (*j)->XACMLcontext__AttributeValue.begin();
                 k != (*j)->XACMLcontext__AttributeValue.end();
                 k++)
            {
                std::string aval;

                extract_attribute_value(*k, aval);

                xacml_request_add_subject_attribute(
                    request,
                    (*i)->SubjectCategory.c_str(),
                    (*j)->AttributeId.c_str(),
                    (*j)->DataType.c_str(),
                    (*j)->Issuer ? (*j)->Issuer->c_str() : NULL,
                    aval.c_str());
            }
        }
    }

    for (std::vector<class XACMLcontext__ResourceType * >::iterator i =
                req->XACMLcontext__Resource.begin();
        i != req->XACMLcontext__Resource.end();
        i++)
    {
        size_t attribute_count = 0;

        for (std::vector<class XACMLcontext__AttributeType * >::iterator j =
                (*i)->XACMLcontext__Attribute.begin();
            j != (*i)->XACMLcontext__Attribute.end();
            j++)
        {
            for (std::vector<class XACMLcontext__AttributeValueType *>::iterator k =
                        (*j)->XACMLcontext__AttributeValue.begin();
                 k != (*j)->XACMLcontext__AttributeValue.end();
                 k++)
            {
                attribute_count++;
            }
        }

        const char *attribute_id[attribute_count+1];
        const char *data_type[attribute_count+1];
        const char *issuer[attribute_count+1];
        const char *value[attribute_count+1];
        std::string values[attribute_count+1];

        size_t ind = 0;
        for (std::vector<class XACMLcontext__AttributeType * >::iterator j =
                (*i)->XACMLcontext__Attribute.begin();
            j != (*i)->XACMLcontext__Attribute.end();
            j++)
        {
            for (std::vector<class XACMLcontext__AttributeValueType *>::iterator k =
                        (*j)->XACMLcontext__AttributeValue.begin();
                 k != (*j)->XACMLcontext__AttributeValue.end();
                 k++)
            {
                attribute_id[ind] = (*j)->AttributeId.c_str();
                data_type[ind] = (*j)->DataType.c_str();
                issuer[ind] = (*j)->Issuer ? (*j)->Issuer->c_str() : NULL;
                extract_attribute_value(*k, values[ind]);
                value[ind] = values[ind].c_str();
                ind++;
            }
        }
        attribute_id[ind] = NULL;
        data_type[ind] = NULL;
        issuer[ind] = NULL;
        value[ind] = NULL;
        xacml_request_add_resource_attributes(
                request,
                attribute_id,
                data_type,
                issuer,
                value);
    }
    for (std::vector<class XACMLcontext__AttributeType *>::iterator i =
                req->XACMLcontext__Action->XACMLcontext__Attribute.begin();
         i != req->XACMLcontext__Action->XACMLcontext__Attribute.end();
         i++)
    {
        for (std::vector<class XACMLcontext__AttributeValueType *>::iterator j =
                    (*i)->XACMLcontext__AttributeValue.begin();
             j != (*i)->XACMLcontext__AttributeValue.end();
             j++)
        {
            std::string action;

            extract_attribute_value(*j, action);

            xacml_request_add_action_attribute(
                request,
                (*i)->AttributeId.c_str(),
                (*i)->DataType.c_str(),
                (*i)->Issuer ? (*i)->Issuer->c_str() : NULL,
                action.c_str());
        }
    }
    for (std::vector<class XACMLcontext__AttributeType *>::iterator i =
                req->XACMLcontext__Environment->XACMLcontext__Attribute.begin();
         i != req->XACMLcontext__Environment->XACMLcontext__Attribute.end();
         i++)
    {
        for (std::vector<class XACMLcontext__AttributeValueType *>::iterator j =
                    (*i)->XACMLcontext__AttributeValue.begin();
             j != (*i)->XACMLcontext__AttributeValue.end();
             j++)
        {
            std::string envval;

            extract_attribute_value(*j, envval);

            xacml_request_add_environment_attribute(
                request,
                (*i)->AttributeId.c_str(),
                (*i)->DataType.c_str(),
                (*i)->Issuer ? (*i)->Issuer->c_str() : NULL,
                envval.c_str());
        }
    }
    *requestp = request;

    return 0;
}

int
prepare_response(
    xacml_response_t                    response,
    struct samlp__ResponseType *        samlp__Response)
{
    std::ostringstream                  os;

    samlp__Response->saml__Issuer = new saml__NameIDType();
    samlp__Response->saml__Issuer->Format =
            new std::string("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
    samlp__Response->saml__Issuer->__item = "XACMLService";

    samlp__Response->samlp__Status = new samlp__StatusType();
    samlp__Response->samlp__Status->samlp__StatusCode = new samlp__StatusCodeType();
    samlp__Response->samlp__Status->samlp__StatusCode->Value =
            saml_status_code_strings[response->saml_status_code];

    os << "ID-" << rand();

    samlp__Response->ID = os.str();;

    samlp__Response->Version = "2.0";

    samlp__Response->IssueInstant = time(NULL);
    samlp__Response->__size_32 = 1;
    samlp__Response->__union_32 = new __samlp__union_32();
    
    samlp__Response->__union_32->__union_32 =
            SOAP_UNION__samlp__union_32_saml__Assertion;
    samlp__Response->__union_32->union_32.saml__Assertion =
            new saml__AssertionType();

    samlp__Response->__union_32->union_32.saml__Assertion->IssueInstant =
            time(NULL);

    samlp__Response->__union_32->union_32.saml__Assertion->saml__Issuer =
            new saml__NameIDType();
    samlp__Response->__union_32->union_32.saml__Assertion->saml__Issuer->Format
            =
            new std::string("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");

    const char * issuer;

    if (xacml_response_get_issuer(response, &issuer) != 0)
    {
        return SOAP_SVR_FAULT;
    }
    samlp__Response->__union_32->union_32.saml__Assertion->__item = 
            new char[strlen(issuer)+1];
    strcpy(samlp__Response->__union_32->union_32.saml__Assertion->__item,
           issuer);

    saml__AssertionType * response_assertion =
            samlp__Response->__union_32->union_32.saml__Assertion;

    response_assertion->__size_1 = 1;
    response_assertion->__union_1 = new __saml__union_1();

    response_assertion->__union_1->__union_1 =
            SOAP_UNION__saml__union_1_saml__Statement;
    response_assertion->__union_1->union_1.saml__Statement =
            new XACMLassertion__XACMLAuthzDecisionStatementType();

    XACMLassertion__XACMLAuthzDecisionStatementType * xacml_decision =
            dynamic_cast<XACMLassertion__XACMLAuthzDecisionStatementType *>
                (response_assertion->__union_1->union_1.saml__Statement);

    xacml_decision->XACMLcontext__Response =
            new XACMLcontext__ResponseType();

    XACMLcontext__ResultType * result = new XACMLcontext__ResultType();
    xacml_decision->XACMLcontext__Response->XACMLcontext__Result.push_back(result);

    switch (response->decision)
    {
        case XACML_DECISION_Permit:
            result->XACMLcontext__Decision = XACMLcontext__DecisionType__Permit;
            break;
        case XACML_DECISION_Deny:
            result->XACMLcontext__Decision = XACMLcontext__DecisionType__Deny;
            break;
        case XACML_DECISION_Indeterminate:
        case XACML_DECISION_NotApplicable:
            return SOAP_SVR_FAULT;
    }

    result->XACMLcontext__Status = new XACMLcontext__StatusType();

    result->XACMLcontext__Status->XACMLcontext__StatusCode = 
            new XACMLcontext__StatusCodeType();

    result->XACMLcontext__Status->XACMLcontext__StatusCode->Value =
            xacml_status_code_strings[response->xacml_status_code];

    if (response->obligations.size() != 0)
    {
        result->XACMLpolicy__Obligations =
                new XACMLpolicy__ObligationsType();

        for (xacml::obligations::iterator i = response->obligations.begin();
             i != response->obligations.end();
             i++)
        {
            XACMLpolicy__ObligationType * obligation = new XACMLpolicy__ObligationType();

            result->XACMLpolicy__Obligations->
                    XACMLpolicy__Obligation.push_back(obligation);

            obligation->ObligationId = i->obligation_id;

            switch (i->fulfill_on)
            {
                case XACML_EFFECT_Permit:
                    obligation->FulfillOn = XACMLpolicy__EffectType__Permit;
                    break;
                case XACML_EFFECT_Deny:
                    obligation->FulfillOn = XACMLpolicy__EffectType__Deny;
                    break;
                default:
                    return SOAP_SVR_FAULT;
            }

            for (xacml::attributes::iterator j = i->attributes.begin();
                 j != i->attributes.end();
                 j++)
            {
                XACMLpolicy__AttributeAssignmentType * attr =
                    new XACMLpolicy__AttributeAssignmentType();
                obligation->XACMLpolicy__AttributeAssignment.push_back(attr);

                attr->DataType = j->data_type;
                attr->AttributeId = j->attribute_id;
                attr->__mixed = new char[j->value.length()+1];
                std::strcpy(attr->__mixed, j->value.c_str());
            }
        }
    }
    return SOAP_OK;
}
} // namespace xacml

int
xacml_server_init(
    xacml_server_t *                    server,
    xacml_authorization_handler_t       handler,
    void *                              arg)
{
    (*server) = new xacml_server_s;
    (*server)->port = 8080;
    (*server)->started = false;
    (*server)->stopped = true;
    (*server)->handler = handler;
    (*server)->handler_arg = arg;
    pthread_mutex_init(&(*server)->lock, NULL);
    pthread_cond_init(&(*server)->cond, NULL);

    return 0;
}

int
xacml_server_set_port(
    xacml_server_t                      server,
    unsigned short                      port)
{
    server->port = port;

    return 0;
}

int
xacml_server_get_port(
    const xacml_server_t                server,
    unsigned short *                    port)
{
    *port = server->port;

    return 0;
}

int
xacml_server_use_ssl(
    xacml_server_t                      server,
    const char *                        certificate_path,
    const char *                        key_path,
    const char *                        ca_path)
{
    server->cert_path = certificate_path;
    server->key_path = key_path;
    server->ca_path = ca_path;

    return 0;
}

int
xacml_server_start(
    xacml_server_t                      server)
{
    int rc;

    pthread_mutex_lock(&server->lock);
    if (server->started)
    {
        rc = 0;
        goto out;
    }
    rc = pthread_create(&server->service_thread, NULL, xacml::service_thread, server);
    server->started = true;
    server->stopped = false;
out:
    pthread_mutex_unlock(&server->lock);

    return rc;
}

void
xacml_server_destroy(
    xacml_server_t                      server)
{
    void *arg;

    pthread_mutex_lock(&server->lock);
    server->stopped = true;
    while (server->started)
    {
        pthread_cond_wait(&server->cond, &server->lock);
    }
    server->started = false;
    server->stopped = true;
    pthread_mutex_unlock(&server->lock);

    pthread_join(server->service_thread, &arg);

    pthread_mutex_destroy(&server->lock);
    pthread_cond_destroy(&server->cond);

    delete server;
}



int
__XACMLService__Authorize(
    struct soap *                       soap,
    struct XACMLsamlp__XACMLAuthzDecisionQueryType *
                                        XACMLsamlp__XACMLAuthzDecisionQuery,
    struct samlp__ResponseType *        samlp__Response)
{
    int                                 rc;
    xacml_server_t                      server;
    xacml_request_t                     request;
    xacml_response_t                    response;

    rc = xacml::parse_xacml_query(XACMLsamlp__XACMLAuthzDecisionQuery, &request);

    if (rc != 0)
    {
        return SOAP_CLI_FAULT;
    }

    rc = xacml_response_init(&response);
    if (rc != 0)
    {
        return SOAP_SVR_FAULT;
    }

    server = (xacml_server_t) soap->user;

    rc = server->handler(server->handler_arg, request, response);
    if (rc != 0)
    {
        return SOAP_SVR_FAULT;
    }

    rc = xacml::prepare_response(response, samlp__Response);
    if (rc != 0)
    {
        return SOAP_SVR_FAULT;
    }
    xacml_request_destroy(request);
    xacml_response_destroy(response);

    return SOAP_OK;
}
/* __XACMLService__Authorize() */
