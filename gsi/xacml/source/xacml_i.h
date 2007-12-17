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

#ifndef I_XACML_H
#define I_XACML_H 1

#ifndef DONT_DOCUMENT_INTERNAL
#include "xacml.h"

#include <pthread.h>

#include <map>
#include <vector>
#include <string>

namespace xacml
{
    struct attribute
    {
        std::string                     attribute_id;
        std::string                     data_type;
        std::string                     value;
    };

    typedef std::string issuer;
    typedef std::string subject_type;
    typedef std::string obligation_id;

    typedef std::vector<attribute> attributes;
    typedef std::map<issuer, attributes> attribute_set;
    typedef std::map<subject_type, attribute_set> subject;
    typedef std::vector<attribute_set> resource;

    struct obligation
    {
        std::string                     obligation_id;
        xacml::attributes               attributes;
        xacml_effect_t                  fulfill_on;
    };

    typedef std::vector<obligation> obligations;

    struct obligation_handler_info
    {
        xacml_obligation_handler_t      handler;
        void *                          handler_arg;
    };

    typedef std::map<obligation_id, obligation_handler_info> obligation_handlers;
}

struct xacml_request_s
{
    xacml::subject                      subjects;
    xacml::resource                     resource_attributes;
    xacml::attribute_set                action_attributes;
    xacml::attribute_set                environment_attributes;
    std::string                         certificate_path;
    std::string                         key_path;
    std::string                         certificate_dir;
    xacml::subject_type                 subject;
    std::string                         endpoint;
    xacml::obligation_handlers          obligation_handlers;
};

struct xacml_response_s
{
    xacml::issuer                       issuer;
    std::time_t                         issue_instant;
    saml_status_code_t                  saml_status_code;
    xacml_decision_t                    decision;
    xacml_status_code_t                 xacml_status_code;
    xacml::obligations                  obligations;
};

struct xacml_server_s
{
    unsigned short                      port;
    bool                                started;
    bool                                stopped;
    int                                 listener;
    pthread_t                           service_thread;
    pthread_mutex_t                     lock;
    pthread_cond_t                      cond;
    xacml_authorization_handler_t       handler;
    void *                              handler_arg;

    std::string                         cert_path;
    std::string                         key_path;
    std::string                         ca_path;
};

typedef struct xacml_obligation_s
{
    xacml::obligation                   obligation;
};
#endif /* DONT_DOCUMENT_INTERNAL */

#endif /* I_XACML_H */
