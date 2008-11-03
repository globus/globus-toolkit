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
#include "soapH.h"

#include <iostream>
#include <sstream>
#include <dlfcn.h>

/**
 * Load and use an I/O module from a shared object for a request
 * @ingroup xacml_io
 * Open the module named by @a module and configures the @a request handle
 * to use the I/O descriptor named "xacml_io_descriptor" in that module.
 *
 * @param request
 *     XACML request handle.
 * @param module
 *     Name of a shared object containing the xacml_io_descriptor_t.
 *
 * @see xacml_request_set_io_descriptor()
 */
xacml_result_t
xacml_request_set_io_module(
    xacml_request_t                     request,
    const char                         *module)
{
    const xacml_io_descriptor_t        *desc;
    xacml_result_t                      rc;

    if (request == NULL || module == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }

    request->io_module = dlopen(module, RTLD_NOW|RTLD_LOCAL);
    if (request->io_module == NULL)
    {
        std::cerr << "Error loading module " << module << " "
             << dlerror() << std::endl;

        rc = XACML_RESULT_INVALID_PARAMETER;
    }
    desc = reinterpret_cast<xacml_io_descriptor_t *>(
            dlsym(request->io_module, XACML_IO_DESCRIPTOR));

    rc = xacml_request_set_io_descriptor(request, desc);

    if (rc != XACML_RESULT_SUCCESS)
    {
        dlclose(request->io_module);
        request->io_module = NULL;
    }
    return rc;
}
/* xacml_request_set_io_module() */


/**
 * Use an I/O module for a request
 * @ingroup xacml_io
 * 
 * Configure a request handle to use the I/O callbacks contained in the
 * descriptor. 
 *
 * @param request
 *     XACML request handle.
 * @param descriptor
 *     Descriptor with the I/O callbacks to be used when processing 
 *     @a request.
 *
 * @see xacml_request_set_io_descriptor()
 */
xacml_result_t
xacml_request_set_io_descriptor(
    xacml_request_t                     request,
    const xacml_io_descriptor_t        *descriptor)
{
    if (request == NULL || descriptor == NULL)
    {
        return XACML_RESULT_INVALID_PARAMETER;
    }
    request->accept_func = descriptor->accept_func;
    request->connect_func = descriptor->connect_func;
    request->send_func = descriptor->send_func;
    request->recv_func = descriptor->recv_func;
    request->close_func = descriptor->close_func;

    return XACML_RESULT_SUCCESS;
}
/* xacml_request_set_io_module() */

#ifndef DONT_DOCUMENT_INTERNAL
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
    std::string                         t(data, size);
    std::ostringstream                  s, namespace_prefixes;
    std::string::size_type              p, q;
    long                                content_length = 0;

    /* This code works around a bug in the java XACML service which lost the
     * namespace definitions in the soap envelope and was thus unable to parse
     * the XACML message body
     */
    /* All namespaces */
    for (int i = 0 ; namespaces[i].ns; i++)
    {
        namespace_prefixes << "xmlns:" << namespaces[i].id
                           << "=\"" << namespaces[i].ns << "\" ";
    }

    /* Find the Content-Length HTTP header */
    p = t.find("Content-Length: ");
    if (p == std::string::npos)
    {
        /* No content-length header, just send the XML with the modifications
         * we make here
         */
        q = p = 0;
    }
    else
    {
        /*
         * Add the new string value to the content length
         */
        s << t.substr(0, p+16);

        content_length = atol(t.substr(p+16, t.find("\r\n")).c_str());
        content_length += namespace_prefixes.str().length();

        p = t.find("\r\n", p+16);
        s << content_length;
        q = p;
    }

    /* Find first element after body */
    p = t.find("<SOAP-ENV:Body");
    p = t.find("<", p);
    p = t.find(" ", p);

    /* Copy all data up to our new namespaces */
    s << t.substr(q, p+1-q);

    /* Add namespace prefixes */
    s << namespace_prefixes.str();

    /* Add rest of message */
    s << t.substr(p+1);

    /* Pass string to send function */
    if (request->send_func(request->io_arg, s.str().c_str(), s.str().length())
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
#endif // DONT_DOCUMENT_INTERNAL
