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

#include "xacml_client.h"
#include "xacml_io_example.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
default_handler(
    void *                              handler_arg,
    const xacml_response_t              response,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on,
    const char *                        attribute_ids[],
    const char *                        datatypes[],
    const char *                        values[])
{
    printf("Unknown obligation: %s\n", obligation_id);

    return 1;
}

int
local_user_name_handler(
    void *                              handler_arg,
    const xacml_response_t              response,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on,
    const char *                        attribute_ids[],
    const char *                        datatypes[],
    const char *                        values[])
{
    int i;
    printf("Got obligation %s\n", obligation_id);

    for (i = 0; attribute_ids[i] != NULL; i++)
    {
        printf(" %s [%s] = %s\n", attribute_ids[i], datatypes[i], values[i]);
    }
    return 0;
}


int main(int argc, char *argv[])
{
    xacml_request_t request;
    int ch;
    char * cert = NULL;
    char * key = NULL;
    char * ca_path = NULL;
    char * endpoint = NULL;
    char * use_io_module = NULL;
    xacml_response_t response;
    xacml_resource_attribute_t ra;
    const char *resattr[2];

    xacml_init();
    xacml_request_init(&request);

    while ((ch = getopt(argc, argv, "e:c:k:a:im:h")) != -1)
    {
        switch (ch)
        {
        case 'e':
            endpoint = optarg;
            break;
        case 'c':
            cert = optarg;
            break;
        case 'k':
            key = optarg;
            break;
        case 'a':
            ca_path = optarg;
            break;
        case 'm':
            xacml_request_set_io_module(request, optarg);
            break;
        case 'i':
            xacml_request_set_io_descriptor(request,
                        &xacml_io_example_descriptor);
            break;
        case 'h':
        case '?':
        default:
            printf("Usage %s [-e endpoint] [-c certfile] [-k keyfile] [-a CA-path]\n",
                    argv[0]);
            exit(0);
        }
    }

    xacml_response_init(&response);
    xacml_request_set_subject(
            request,
            "CN=Joseph Bester 912390,OU=People,DC=doegrids,DC=org");
    xacml_request_add_subject_attribute(
            request,
            XACML_SUBJECT_CATEGORY_ACCESS_SUBJECT,
            XACML_SUBJECT_ATTRIBUTE_SUBJECT_ID,
            XACML_DATATYPE_X500_NAME,
            "",
            "CN=Joseph Bester,OU=People,DC=doegrids,DC=org");

    resattr[0] = "https://140.221.36.11:8081/wsrf/services/SecureCounterService";
    xacml_resource_attribute_init(&ra);

    xacml_resource_attribute_add(
            ra,
            XACML_RESOURCE_ATTRIBUTE_RESOURCE_ID,
            XACML_DATATYPE_STRING,
            "",
            resattr[0]);

    xacml_request_add_resource_attribute(request, ra);
    xacml_resource_attribute_destroy(ra);

    xacml_request_add_action_attribute(
            request,
            XACML_ACTION_ATTRIBUTE_ACTION_NAMESPACE,
            XACML_DATATYPE_STRING,
            "",
            "http://www.gridforum.org/namespaces/2003/06/ogsa-authorization/saml/action/operation");
    xacml_request_add_action_attribute(
            request,
            XACML_ACTION_ATTRIBUTE_ACTION_ID,
            XACML_DATATYPE_STRING,
            "",
            "createCounter");

    xacml_request_add_obligation_handler(
            request,
            local_user_name_handler,
            NULL,
            "urn:globus:local-user-name:obj");

    xacml_request_add_obligation_handler(
            request,
            default_handler,
            NULL,
            NULL);

    if (cert != NULL || key != NULL || ca_path != NULL)
    {
        abort();
    }

    if (endpoint == NULL)
    {
        endpoint = "http://localhost:8080/wsrf/services/XACML";
    }

    ch = xacml_query(endpoint,
                request,
                response);

    if (ch != 0)
    {
        printf("Error processing messages\n");
        exit(1);
    }
    saml_status_code_t code;
    xacml_decision_t decision;

    xacml_response_get_saml_status_code(response, &code);
    xacml_response_get_xacml_decision(response, &decision);

    printf("Server said: %s:%d\n", saml_status_code_strings[code], decision);

    return 0;
}
