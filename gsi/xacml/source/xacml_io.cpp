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
#include "soapH.h"

#include <dlfcn.h>

int
xacml_request_set_io_module(
    xacml_request_t                     request,
    const char                         *module)
{
    void                               *mod;
    const xacml_io_descriptor_t        *desc;
    std::string                         module_name;

    module_name = module;
    module_name += ".so";

    mod = dlopen(module_name.c_str(), RTLD_NOW|RTLD_LOCAL);
    desc = reinterpret_cast<xacml_io_descriptor_t *>(dlsym(mod,
            XACML_IO_DESCRIPTOR));

    request->io_module = mod;
    request->accept_func = desc->accept_func;
    request->connect_func = desc->connect_func;
    request->send_func = desc->send_func;
    request->recv_func = desc->recv_func;
    request->close_func = desc->close_func;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_set_io_module() */

extern "C"
int
xacml_i_connect(
    struct soap                        *soap,
    const char                         *endpoint,
    const char                         *host,
    int                                 port)
{
    xacml_request_t                     request = (xacml_request_t) soap->user;

    request->io_arg = request->connect_func(endpoint, host, port);

    if (request->io_arg == NULL)
    {
        soap->error = SOAP_ERR;
        return -1;
    }

    return SOAP_OK;
}
/* xacml_i_connect() */

extern "C"
int
xacml_i_send(
    struct soap                        *soap,
    const char                         *data,
    size_t                              size)
{
    xacml_request_t                     request = (xacml_request_t) soap->user;

    if (request->send_func(request->io_arg, data, size)
            != XACML_RESULT_SUCCESS)
    {
        return SOAP_EOF;
    }

    return SOAP_OK;
}
/* xacml_i_send() */

extern "C"
size_t
xacml_i_recv(
    struct soap                        *soap,
    char                               *data,
    size_t                              size)
{
    xacml_request_t                     request = (xacml_request_t) soap->user;

    return request->recv_func(request->io_arg, data, size);
}
/* xacml_i_recv() */

extern "C"
int
xacml_i_close(
    struct soap                        *soap)
{
    xacml_request_t                     request = (xacml_request_t) soap->user;
    int                                 rc;

    if ((!request) || (request->io_arg == NULL))
    {
        return SOAP_OK;
    }
    rc = request->close_func(request->io_arg);
    request->io_arg = NULL;

    return rc;
}
/* xacml_i_close() */
