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
 * @page globus_net_manager_tutorial Net Manager Implementation Tutorial
 * This example uses functionality from globus_common and globus_net_manager
 * modules, so the headers for those must be included:
 @verbatim
#include "globus_common.h"
#include "globus_net_manager.h"
 @endverbatim
 * To implement a network manager, define a struct #globus_net_manager_s
 * containing pointers to the functions in your code that you want invoked
 * during network events, and pass that to globus_net_manager_register().
 * Applications which use the @ref globus_net_manager_context functions or the
 * @ref globus_xio_net_manager_driver will invoke your functions as network
 * operations occur. For this example (and I would imagine most real
 * implementations), the globus_net_manager_t is statically initialized, like
 * this:
 *
 * @snippet globus_net_manager_logging.c Network Manager Definition
 *
 * For the examples provided in this library, the globus_net_manager_s is
 * registered during module activation in a globus_extension module. This
 * method makes it easy to use network managers in a shared library
 * environment.  This is also a good place to initialize any state that
 * you need to retain between calls to the network manager.
 *
 * To implement this, do the following:
 * @snippet globus_net_manager_logging.c Module Descriptor and Activation
 *
 *
 * Finally, the real work of the manager is done in the 
 * functions registered in the #globus_net_manager_s. For brevity, I'll just
 * include the pre_listen function in this tutorial. This function is passed
 * the task-id associated with the operation, the transport ("tcp", "udp",
 * "udt", etc) used by the network, and whatever attributes are associated
 * with the operation. If we wanted to modify things before they were processed
 * by the network, we could create a modified copy of the attributes in the
 * pre_listen function and return them via the attr_array_out parameter. In
 * this case, we simply print out the information we've received from the
 * network stack.
 *
 * @snippet globus_net_manager_logging.c Pre-Listen Implementation
 */

/**
 * @defgroup globus_net_manager_types Data Types
 * @ingroup globus_net_manager
 */
/**
 * @defgroup globus_net_manager_signatures Function Signatures
 * @ingroup globus_net_manager
 */


/**
 * @file logging/globus_net_manager_logging.c
 * @brief Logging Network Manager Implementation
 */

#include "globus_common.h"
#include "globus_net_manager.h"
#include "version.h"

//! [Pre-Listen Implementation]
static
void
globus_l_net_manager_logging_log_attrs(
    const globus_net_manager_attr_t    *attr_array)
{
    for (int i = 0; attr_array[i].scope; i++)
    {
        printf("[%s, %s, %s] ",
            attr_array[i].scope, attr_array[i].name, attr_array[i].value);
    }
}

static
void
globus_l_net_manager_logging_log_header(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *op)
{
    printf("%s:%s: task-id=%s transport=%s", op, manager->name, task_id, transport);
}

static
void
globus_l_net_manager_logging_log_footer(void)
{
    printf("\n");
}

static
void
globus_l_net_manager_logging_log_contacts(
    const char                         *local_contact,
    const char                         *remote_contact)
{
    if (local_contact)
    {
        printf("%s ", local_contact);
    }
    if (remote_contact)
    {
        printf("%s ", remote_contact);
    }
}

static
globus_result_t
globus_l_net_manager_logging_pre_listen(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_l_net_manager_logging_log_header(manager, task_id, transport, "pre_listen");
    globus_l_net_manager_logging_log_attrs(attr_array);
    globus_l_net_manager_logging_log_footer();
    return GLOBUS_SUCCESS;
}
/* globus_l_net_manager_logging_pre_listen() */
//! [Pre-Listen Implementation]

globus_result_t
globus_l_net_manager_logging_post_listen(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const globus_net_manager_attr_t    *attr_array,
    char                              **local_contact_out,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_l_net_manager_logging_log_header(manager, task_id, transport, "post_listen");
    globus_l_net_manager_logging_log_attrs(attr_array);
    globus_l_net_manager_logging_log_contacts(local_contact, NULL);
    globus_l_net_manager_logging_log_footer();
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_net_manager_logging_pre_accept(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_l_net_manager_logging_log_header(manager, task_id, transport, "pre_accept");
    globus_l_net_manager_logging_log_attrs(attr_array);
    globus_l_net_manager_logging_log_contacts(local_contact, NULL);
    globus_l_net_manager_logging_log_footer();
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_net_manager_logging_post_accept(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_l_net_manager_logging_log_header(manager, task_id, transport, "post_accept");
    globus_l_net_manager_logging_log_attrs(attr_array);
    globus_l_net_manager_logging_log_contacts(local_contact, remote_contact);
    globus_l_net_manager_logging_log_footer();
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_net_manager_logging_pre_connect(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array,
    char                              **remote_contact_out,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_l_net_manager_logging_log_header(manager, task_id, transport, "pre_connect");
    globus_l_net_manager_logging_log_attrs(attr_array);
    globus_l_net_manager_logging_log_contacts(NULL, remote_contact);
    globus_l_net_manager_logging_log_footer();
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_net_manager_logging_post_connect(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_l_net_manager_logging_log_header(manager, task_id, transport, "post_connect");
    globus_l_net_manager_logging_log_attrs(attr_array);
    globus_l_net_manager_logging_log_contacts(local_contact, remote_contact);
    globus_l_net_manager_logging_log_footer();
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_net_manager_logging_pre_close(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array)
{
    globus_l_net_manager_logging_log_header(manager, task_id, transport, "pre_close");
    globus_l_net_manager_logging_log_attrs(attr_array);
    globus_l_net_manager_logging_log_contacts(local_contact, remote_contact);
    globus_l_net_manager_logging_log_footer();
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_l_net_manager_logging_post_close(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array)
{
    globus_l_net_manager_logging_log_header(manager, task_id, transport, "post_close");
    globus_l_net_manager_logging_log_attrs(attr_array);
    globus_l_net_manager_logging_log_contacts(local_contact, remote_contact);
    globus_l_net_manager_logging_log_footer();
    return GLOBUS_SUCCESS;
}

#ifdef DOXYGEN
/**
 * Module descriptor
 */
extern globus_module_descriptor_t globus_net_manager_logging_module;
#endif


static
int
globus_l_net_manager_logging_activate(void);

static
int
globus_l_net_manager_logging_deactivate(void);

//! [Network Manager Definition]
static
globus_net_manager_t                    globus_l_net_manager_logging = {
    "logging",
    globus_l_net_manager_logging_pre_listen,
    globus_l_net_manager_logging_post_listen,
    globus_l_net_manager_logging_pre_accept,
    globus_l_net_manager_logging_post_accept,
    globus_l_net_manager_logging_pre_connect,
    globus_l_net_manager_logging_post_connect,
    globus_l_net_manager_logging_pre_close,
    globus_l_net_manager_logging_post_close
};
//! [Network Manager Definition]

//! [Module Descriptor and Activation]
GlobusExtensionDefineModule(globus_net_manager_logging) = {
    "globus_net_manager_logging",
    globus_l_net_manager_logging_activate,
    globus_l_net_manager_logging_deactivate,
    NULL,
    NULL,
    &local_version
};

static
int
globus_l_net_manager_logging_activate(void)
{
    int rc = globus_module_activate(GLOBUS_NET_MANAGER_MODULE);
    if (rc == 0)
    {
        rc = globus_net_manager_register(&globus_l_net_manager_logging);
    }
    return rc;
}

static
int
globus_l_net_manager_logging_deactivate(void)
{
    int rc = globus_net_manager_unregister(&globus_l_net_manager_logging);
    if (rc == 0)
    {
        rc = globus_module_deactivate(GLOBUS_NET_MANAGER_MODULE);
    }
    return rc;
}
//! [Module Descriptor and Activation]
