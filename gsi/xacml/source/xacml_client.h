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

#ifndef XACML_CLIENT_H
#define XACML_CLIENT_H

#include "xacml_datatypes.h"
#include "xacml.h"

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_BEGIN
#endif

/**
 * @defgroup xacml_client Client Library Functions
 */
int
xacml_request_add_obligation_handler(
    xacml_request_t                     request,
    xacml_obligation_handler_t          handler,
    void *                              handler_arg,
    const char *                        obligation_id);

int
xacml_query(
    const char *                        endpoint,
    xacml_request_t                     request,
    xacml_response_t                    response);

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_END
#endif

#endif /* XACML_CLIENT_H */
