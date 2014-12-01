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

#ifndef GLOBUS_XIO_NET_MANAGER_DRIVER_H
#define GLOBUS_XIO_NET_MANAGER_DRIVER_H 1

#include "globus_common.h"
#include "globus_net_manager_attr.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file globus_xio_net_manager_driver.h
 * @brief Network Manager XIO Driver
 */

/**
 * @defgroup globus_xio_net_manager_driver Globus XIO Driver
 * @ingroup globus_net_manager
 * @details
 * The Globus XIO Network Manager Driver interfaces with the globus_net_manager
 * library to integrate network manager functionality within the globus_xio
 * network stack. The list of network managers and their options are configured
 * by calling the GLOBUS_XIO_SET_STRING_OPTIONS attr_cntl with a string of
 * attributes. The attribute names "task-id", "service", and "manager"
 * are handled by this driver. Other attributes are interpreted as the
 * attributes to pass on the most recently parsed value of the "manager"
 * attribute. For example:
 *
@verbatim
manager=first;arg=foo;another-arg=bar;manager=second;yet-another=baz
@endverbatim
 * will create a @link globus_net_manager_context context @endlink
 * containing the network managers "first" and "second". It will synthesize
 * @link globus_net_manager_attr network manager attributes @endlink 
 * (scope, name, value) containing:
 *
 * (first, arg, foo)
 *
 * (first, another-arg, bar)
 *
 * (second, yet-another, baz)
 *
 * and pass these, along with transport-specific attributes, to the network
 * managers when their functions are called. 
 *
 * In addition to the string attributes, there is one more attr_cntl which
 * invokes the pre_listen functionality, as this is possible
 * to do automatically by the XIO framework. The
 * GLOBUS_XIO_NET_MANAGER_PRE_LISTEN attr_cntl invokes the pre_listen network
 * management functions and modifies the attribute so that the network managers
 * have an opportunity to modify the transport parameters before the server
 * listener is created.
 */

/** doxygen varargs filter stuff
 * GlobusVarArgDefine(
 *      attr, globus_result_t, globus_xio_attr_cntl, attr, driver)
 */
/**
 * Network driver specific cntls
 * @ingroup globus_xio_net_manager_driver
 */
typedef enum
{
    /** GlobusVarArgEnum(attr)
     * Invoke the pre-listen network manager functions with the attribute
     * which is to be used with globus_xio_server_create().
     * @ingroup globus_xio_net_manager_driver
     */
    /* */
    GLOBUS_XIO_NET_MANAGER_PRE_LISTEN,
    /** GlobusVarArgEnum(attr)
     * Set the task id associated with this XIO handle.
     * @ingroup globus_xio_net_manager_driver
     */
    /* const char * task_id*/
    GLOBUS_XIO_NET_MANAGER_SET_TASK_ID,
    /** GlobusVarArgEnum(attr)
     * Get the task id associated with this XIO handle.
     * @ingroup globus_xio_net_manager_driver
     */
    /* const char ** task_id*/
    GLOBUS_XIO_NET_MANAGER_GET_TASK_ID

} globus_xio_net_manager_cntl_t;

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_XIO_NET_MANAGER_DRIVER_H */
