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

#include <dlfcn.h>
#include <iterator>

int
xacml_request_init(
    xacml_request_t *             request)
{
    try
    {
        *request = new xacml_request_s;
        (*request)->io_module = NULL;
        (*request)->io_arg = NULL;
        (*request)->connect_func = NULL;
        (*request)->close_func = NULL;
    }
    catch(...)
    {
        return 1;
    }

    return 0;
}

void
xacml_request_destroy(
    xacml_request_t               request)
{
    if (request->io_module)
    {
        dlclose(request->io_module);
    }
    delete request;
}

int
xacml_request_add_subject_attribute(
    xacml_request_t                     request,
    const char *                        subject_category,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value)
{
    xacml::attribute_set &              set = request->subjects[subject_category];
    xacml::attributes &                 attributes = set[issuer ? issuer : ""];
    xacml::attribute                    attr;

    attr.attribute_id = attribute_id;
    attr.data_type = data_type;
    attr.value = value;

    attributes.push_back(attr);

    return 0;
}
/* xacml_request_add_subject_attribute() */

int
xacml_request_get_subject_attribute_count(
    const xacml_request_t         request,
    size_t *                            count)
{
    size_t                              c = 0;

    for (xacml::subject::iterator i = request->subjects.begin();
         i != request->subjects.end();
         i++)
    {
        for (xacml::attribute_set::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            for (xacml::attributes::iterator k = j->second.begin();
                 k != j->second.end();
                 k++)
            {
                c++;
            }
        }
    }
    *count = c;

    return 0;
}

int
xacml_request_get_subject_attribute(
    const xacml_request_t         request,
    size_t                              num,
    const char **                       subject_category,
    const char **                       attribute_id,
    const char **                       data_type,
    const char **                       issuer,
    const char **                       value)
{
    size_t c = 0;
    
    for (xacml::subject::iterator i = request->subjects.begin();
         i != request->subjects.end();
         i++)
    {
        for (xacml::attribute_set::iterator j = i->second.begin();
             j != i->second.end();
             j++)
        {
            for (xacml::attributes::iterator k = j->second.begin();
                 k != j->second.end();
                 k++)
            {
                if (c == num)
                {
                    *subject_category = i->first.c_str();
                    *issuer = j->first.c_str() == "" ? NULL : j->first.c_str();
                    *attribute_id = k->attribute_id.c_str();
                    *data_type = k->data_type.c_str();
                    *value = k->value.c_str();
                }
                c++;
            }
        }
    }

    return 0;
}
/* xacml_request_get_subject_attribute() */

int
xacml_request_add_resource_attribute(
    xacml_request_t                     request,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value)
{
    const char * aid[] = { attribute_id, NULL };
    const char * dt[] = { data_type, NULL };
    const char * i[] = { issuer, NULL };
    const char * v[] = { value, NULL };

    return xacml_request_add_resource_attributes(request, aid, dt, i, v);
}

int
xacml_request_add_resource_attributes(
    xacml_request_t                     request,
    const char *                        attribute_id[],
    const char *                        data_type[],
    const char *                        issuer[],
    const char *                        value[])
{
    xacml::attribute_set                resource;

    for (int i = 0; attribute_id[i] != NULL; i++)
    {
        xacml::attribute                attr;
        const std::string               iss = issuer[i] ? issuer[i] : "";
        xacml::attributes &             attributes = resource[iss];

        attr.attribute_id = attribute_id[i];
        attr.data_type = data_type[i];
        attr.value = value[i];

        attributes.push_back(attr);
    }
    request->resource_attributes.push_back(resource);

    return 0;
}
/* xacml_request_add_resource_attributes() */

int
xacml_request_add_action_attribute(
    xacml_request_t                     request,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value)
{
    xacml::attribute                    attr;

    attr.attribute_id = attribute_id;
    attr.data_type = data_type;
    attr.value = value;

    request->action_attributes[issuer ? issuer : ""].push_back(attr);

    return 0;
}
/* xacml_request_add_action_attribute() */

int
xacml_request_add_environment_attribute(
    xacml_request_t                     request,
    const char *                        attribute_id,
    const char *                        data_type,
    const char *                        issuer,
    const char *                        value)
{
    xacml::attribute                    attr;

    attr.attribute_id = attribute_id;
    attr.data_type = data_type;
    attr.value = value;

    request->environment_attributes[issuer ? issuer : ""].push_back(attr);

    return 0;
}
/* xacml_request_add_environment_attribute() */

int 
xacml_request_set_subject(  
    xacml_request_t                     request,
    const char *                        subject)
{
    request->subject = subject;

    return 0;
}
