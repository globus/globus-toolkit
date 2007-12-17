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

#ifndef XACML_SERVER_H
#define XACML_SERVER_H

#include "xacml_datatypes.h"
#include "xacml.h"

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_BEGIN
#endif

/* Server Authz Processing */

typedef struct xacml_server_s * xacml_server_t;

int
xacml_server_init(
    xacml_server_t *                    server,
    xacml_authorization_handler_t       handler,
    void *                              arg);

int
xacml_server_set_port(
    xacml_server_t                      server,
    unsigned short                      port);

int
xacml_server_get_port(
    const xacml_server_t                server,
    unsigned short *                    port);

int
xacml_server_start(
    xacml_server_t                      server);

void
xacml_server_destroy(
    xacml_server_t                      server);

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_END
#endif

#endif /* XACML_SERVER_H */
