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

/**
 * @file port_plus_one/globus_net_manager_port_plus_one.c
 * @brief Null Network Manager Implementation
 */

#include "globus_common.h"
#include "globus_net_manager.h"
#include "version.h"

static
globus_result_t
globus_l_net_manager_port_plus_one_pre_listen(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 found_port = -1, rc = 0;
    unsigned short                      port_val = 0;
    char                               *new_port_string = NULL;

    for (int i=0; attr_array != NULL && attr_array[i].scope != NULL; i++)
    {
        if ((strcmp(attr_array[i].scope, transport) == 0) &&
            strcmp(attr_array[i].name, "port") == 0)
        {
            found_port = i;
            rc = sscanf(attr_array[i].value, "%hu", &port_val);
            if (rc != GLOBUS_SUCCESS)
            {
                result = GLOBUS_FAILURE;
                goto bad_port;
            }
            new_port_string = globus_common_create_string("%hu", port_val + 1);
            if (new_port_string == NULL)
            {
                result = GLOBUS_FAILURE;
                goto new_port_string_fail;
            }
            break;
        }
    }
    if (found_port != -1)
    {
        result = globus_net_manager_attr_array_copy(attr_array_out, attr_array);
        if (result != GLOBUS_SUCCESS)
        {
            goto attr_array_copy_fail;
        }
        free((*attr_array_out)[found_port].value);
        (*attr_array_out)[found_port].value = new_port_string;
    }

    if (result)
    {
attr_array_copy_fail:
        free(new_port_string);
new_port_string_fail:
bad_port:
        ;
    }
    return result;
}
/* globus_l_net_manager_port_plus_one_pre_listen() */

static
int
globus_l_net_manager_port_plus_one_activate(void);

static
int
globus_l_net_manager_port_plus_one_deactivate(void);

static
globus_net_manager_t                    globus_l_net_manager_port_plus_one = {
    "port_plus_one",
    globus_l_net_manager_port_plus_one_pre_listen
};

static
void *
globus_l_net_manager_port_plus_one_get_pointer(void)
{
    return &globus_l_net_manager_port_plus_one;
}

GlobusExtensionDefineModule(globus_net_manager_port_plus_one) = {
    "globus_net_manager_port_plus_one",
    globus_l_net_manager_port_plus_one_activate,
    globus_l_net_manager_port_plus_one_deactivate,
    NULL,
    globus_l_net_manager_port_plus_one_get_pointer,
    &local_version
};

static
int
globus_l_net_manager_port_plus_one_activate(void)
{
    int rc = globus_module_activate(GLOBUS_NET_MANAGER_MODULE);
    if (rc == 0)
    {
        rc = globus_net_manager_register(&globus_l_net_manager_port_plus_one,
            GlobusExtensionMyModule(globus_net_manager_port_plus_one));
    }
    return rc;
}

static
int
globus_l_net_manager_port_plus_one_deactivate(void)
{
    int rc = globus_net_manager_unregister(&globus_l_net_manager_port_plus_one);
    if (rc == 0)
    {
        rc = globus_module_deactivate(GLOBUS_NET_MANAGER_MODULE);
    }
    return rc;
}
