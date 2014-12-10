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

#include "globus_common.h"
#include "globus_net_manager.h"
#include "version.h"

static int globus_l_net_manager_exec_activate(void);
static int globus_l_net_manager_exec_deactivate(void);

static globus_net_manager_t globus_l_net_manager_exec = {"exec"};

static
void *
globus_l_net_manager_exec_get_manager(void)
{
    return &globus_l_net_manager_exec;
}
/* globus_l_net_manager_exec_get_manager() */

GlobusExtensionDefineModule(globus_net_manager_exec) =
{
    "globus_net_manager_exec",
    globus_l_net_manager_exec_activate,
    globus_l_net_manager_exec_deactivate,
    NULL,
    globus_l_net_manager_exec_get_manager,
    &local_version
};

static
int
globus_l_net_manager_exec_activate(void)
{
    return globus_net_manager_register(&globus_l_net_manager_exec);
}

static
int
globus_l_net_manager_exec_deactivate(void)
{
    return globus_net_manager_unregister(&globus_l_net_manager_exec);
}
