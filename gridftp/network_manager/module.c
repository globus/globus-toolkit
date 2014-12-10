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

#include "globus_net_manager.h"
#ifdef ENABLE_PYTHON
#include "globus_net_manager_python.h"
#endif
#include "globus_net_manager_logging.h"
#include "globus_net_manager_exec.h"

#include "version.h"

static
int
globus_l_net_manager_activate(void)
{
    globus_module_activate(GLOBUS_COMMON_MODULE);
#ifdef ENABLE_PYTHON
    globus_extension_register_builtin(
        "globus_net_manager_python",
        &globus_net_manager_python_module);
#endif
    globus_extension_register_builtin(
        "globus_net_manager_logging",
        &globus_net_manager_logging_module);
    globus_extension_register_builtin(
        "globus_net_manager_exec",
        &globus_net_manager_exec_module);
    return GLOBUS_SUCCESS;
}

static
int
globus_l_net_manager_deactivate(void)
{
#ifdef ENABLE_PYTHON
    globus_extension_unregister_builtin("globus_net_manager_python");
#endif
    globus_extension_unregister_builtin("globus_net_manager_logging");
    globus_extension_unregister_builtin("globus_net_manager_exec");

    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

globus_module_descriptor_t              globus_i_net_manager_module =
{
    "globus_net_manager",
    globus_l_net_manager_activate,
    globus_l_net_manager_deactivate,
    NULL,
    NULL,
    &local_version
};
