/*
 * Copyright 1999-2014 University of Chicago
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

#ifndef GLOBUS_NET_MANAGER_PYTHON_H
#define GLOBUS_NET_MANAGER_PYTHON_H 1

#include "globus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup globus_net_manager_python Python Module
 * @ingroup globus_net_manager
 * The Net Manager Python module is an example module that provides basic
 * Python language bindings to the Network Manager callout functionality. 
 * To use this example, define a python module that implements the some
 * subset of the following functions:
@code {.py}
def pre_listen(task_id, transport, attrs):
    # return list of (scope, name, value) tuples or None
def post_listen(task_id, transport, local_contact, attrs):
    # return a tuple containing (local_contact_out, [(scope, name, value),...])
def pre_accept(task_id, transport, local_contact, attrs):
    # return list of (scope, name, value) tuples or None
def post_accept(task_id, transport, local_contact, remote_contact, attrs):
    # return list of (scope, name, value) tuples or None
def pre_connect(task_id, transport, remote_contact, attrs):
    # return a tuple containing (remote_contact_out, [(scope, name, value),...])
def post_connect(task_id, transport, local_contact, remote_contact, attrs):
    # return list of (scope, name, value) tuples or None
def pre_close(task_id, transport, local_contact, remote_contact, attrs):
    # return None
def post_close(task_id, transport, local_contact, remote_contact, attrs):
    # return None
@endcode
 * The <em>task_id</em>, <em>transport</em>, <em>local_contact</em>,
 * and <em>remote_contact</em> parameters to these functions are all string
 * objects.
 * The <em>attrs</em> parameter to these functions are lists of 3-tuples
 * (scope, name, value).
 *
 * To configure the network manager to use this module, set the "pymod"
 * attribute in the "python" scope to the name of the python module to 
 * import and use. For example to use the "netman.py" module, add this
 * attribute: ("python", "pymod", "netman").
 *
 * To use this with the XIO module,
 * set the string options <code>module=python;pymod=netman;</code>
 */
GlobusExtensionDeclareModule(globus_net_manager_python);

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_NET_MANAGER_PYTHON_H */
