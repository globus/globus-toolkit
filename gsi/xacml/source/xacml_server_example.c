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

#include "xacml_server.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static int done = 0;

void siginthandler(int sig)
{
    done = 1;
}

static
int
xacml_authorize(
    void *                              handler_arg,
    const xacml_request_t               request,
    xacml_response_t                    response)
{
    size_t i;
    size_t count;

    xacml_response_set_issuer(response, "XACMLservice");

    xacml_request_get_subject_attribute_count(request, &count);

    for (i = 0; i < count; i++)
    {
        const char *category;
        const char *attribute_id;
        const char *data_type;
        const char *issuer;
        const char *value;
        char *userid = "test";

        xacml_request_get_subject_attribute(
                request, i, &category, &attribute_id, &data_type, &issuer, &value);

        if (strcmp(category, XACML_SUBJECT_CATEGORY_ACCESS_SUBJECT))
        {
            continue;
        }
        if (strcmp(attribute_id, XACML_SUBJECT_ATTRIBUTE_SUBJECT_ID))
        {
            continue;
        }

        if (userid)
        {
            xacml_obligation_t          obligation;

            xacml_obligation_init(&obligation, "urn:globus:local-user-name:obj",
                                  XACML_EFFECT_Permit);
            xacml_obligation_add_attribute(obligation,
                                           XACML_SUBJECT_ATTRIBUTE_SUBJECT_ID,
                                           XACML_DATATYPE_STRING,
                                           userid);

            xacml_response_set_saml_status_code(response, SAML_STATUS_Success);
            xacml_response_set_xacml_status_code(response, XACML_STATUS_ok);
            xacml_response_add_obligation(response, obligation);
            xacml_obligation_destroy(obligation);
            xacml_response_set_xacml_decision(response, XACML_DECISION_Permit);
            return 0;
        }
    }
    xacml_response_set_xacml_decision(response, XACML_DECISION_Permit);
    xacml_response_set_saml_status_code(response, SAML_STATUS_Success);
    xacml_response_set_xacml_status_code(response, XACML_STATUS_ok);

    return 0;
}
/* xacml_authorize() */

int main(int argc, char *argv[])
{
    xacml_server_t server;
    int ch;
    unsigned short port = 0;
    char * io_module_name = NULL;

    xacml_init();

    xacml_server_init(&server, xacml_authorize, NULL);

    while ((ch = getopt(argc, argv, "p:i:h")) != -1) 
    {
        switch (ch)
        {
        case 'p':
            port = atoi(optarg);
            xacml_server_set_port(server, port);
            break;
        case 'i':
            io_module_name = optarg;
            break;
        case 'h':
        case '?':
        default:
            printf("Usage: %s [-p PORT] [-i IO MODULE NAME]\n",
                    argv[0]);
            exit(0);
        }
    }

    if (io_module_name)
    {
        xacml_server_set_io_module(server, io_module_name);
    }

    signal(SIGINT, siginthandler);

    xacml_server_start(server);
    xacml_server_get_port(server, &port);
    printf("Server ready... listening on port %hu.\n", port);

    while (!done)
    {
        pause();
    }
    printf("Shutting down...\n");
    fflush(stdout);
    xacml_server_destroy(server);
}
