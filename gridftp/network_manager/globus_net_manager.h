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

#ifndef GLOBUS_NET_MANAGER_H
#define GLOBUS_NET_MANAGER_H 1

#include "globus_common.h"
#include "globus_net_manager_attr.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file globus_net_manager.h
 * @brief Globus Network Manager Interface
 */

#ifndef GLOBUS_GLOBAL_DOCUMENT_SET
/**
 * @mainpage Globus Network Manager
 * @copydoc globus_net_manager
 */
#endif

struct globus_net_manager_s;

/**
 * @defgroup globus_net_manager Globus Network Manager
 * @details
 * The Globus Network Manager library is a plug-in point for network
 * management tasks, such as:
 * - selectively open ports in a firewall and allow these ports to be closed
 *   when transfers are complete
 * - configure a virtual circuit based on a site policy and route traffic
 *   over this circuit
 * - route network traffic related to a task over a particular network
 *
 * For users interested in implementing or using such functionality, 
 * the @link globus_net_manager.h globus_net_manager library @endlink provides a
 * low-level set of 
 * interfaces to implement specific network managers.
 *
 * In addition, the globus_net_manager library includes sample
 * implementations to provide a starting point for implementing alternative
 * network managers.
 * <dl>
 * <dt>Logging Manager</dt>
 * <dd>Logs network operations as they occur. This implementation
 * shows the simplest network manager implementation in C</dd>
 * <dt>Exec Manager</dt>
 * <dd>Launches a command when network operations occur. This implementation
 * enables network managers to be implemented in any external process.</dd>
 * <dt>Python Manager<dt>
 * <dd>Loads a python module, and calls python functions when network
 * operations occur.</dd>
 * </dl>
 *
 * For users interested in using the network manager in their own services,
 * they can use the @ref globus_net_manager_context APIs to configure and
 * invoke network manager plug-ins, or the
 * @link globus_xio_net_manager_driver Globus XIO Network Manager Driver @endlink
 * to plug the network manager interface directly into the globus_xio stack.
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
 * Network Manager Pre-Listen Function Signature
 * @ingroup globus_net_manager_signatures
 *
 * A function of this signature, if included in a network manager
 * implementation, is called before the transport-specific listening port has
 * been created.
 * 
 * The network manager is passed the network transport-specific options 
 * for the listener. It may modify these before the
 * listener is created by the transport.
 *
 * The globus_net_manager library aborts the listen operation 
 * if this function returns a value other than GLOBUS_SUCCESS. In this
 * case, the globus_net_manager will not call any other
 * globus_net_manager_pre_listen functions configured for this listener.
 *
 * @param[in] manager
 *      Pointer to the network manager struct that is being invoked.
 * @param[in] task_id
 *      An application-specific task ID associated with this network operation.
 * @param[in] transport
 *      The name of the transport associated with this listener.
 * @param[in] attr_array
 *      An array of transport attributes associated with the
 *      listener. The end of the array is indicated by
 *      an attribute containing a NULL scope.
 * @param[out] attr_array_out
 *      A pointer to an array of transport options to apply to the 
 *      listener prior to returning it to the service. This may be NULL to
 *      indicate no change in the options. If non-NULL, this array must be
 *      terminated with an attribute having a NULL scope.
 *      The array and the members of the
 *      globus_net_manager_attr_t struct will be freed by the
 *      globus_net_manager library by calling
 *      free().
 */
typedef globus_result_t (*globus_net_manager_pre_listen)(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out);

/**
 * Network Manager Post-Listen Function Signature
 * @ingroup globus_net_manager_signatures
 *
 * A function of this signature, if included in a network manager
 * implementation, is called after the transport-specific listening port has
 * been created.
 * 
 * The network manager is passed the network transport-specific options and
 * contact string for the listener. It may modify either of these before the
 * transport listener is made available to the service which requested
 * the listening port.
 *
 * The globus_net_manager library aborts the listen operation 
 * if this function returns a value other than GLOBUS_SUCCESS. In this
 * case, the globus_net_manager will not call any other
 * globus_net_manager_post_listen functions configured for this listener.
 *
 * @param[in] manager
 *      Pointer to the network manager struct that is being invoked.
 * @param[in] task_id
 *      An application-specific task ID associated with this network operation.
 * @param[in] transport
 *      The name of the transport associated with this listener.
 * @param[in] local_contact
 *      The transport-specific contact string for the listener [in].
 * @param[in] attr_array
 *      An array of transport attributes associated with the
 *      listener. The end of the array is indicated by
 *      an attribute containing a NULL scope.
 * @param[out] local_contact_out
 *      A pointer to the local contact which the network manager wants to
 *      return to the service. This may be NULL to indicate no change in
 *      the contact. This value will be freed() by the globus_net_manager
 *      library.
 * @param[out] attr_array_out
 *      A pointer to an array of transport options to apply to the 
 *      listener prior to returning it to the service. This may be NULL to
 *      indicate no change in the options. If non-NULL, this array must be
 *      terminated with an attribute having a NULL scope.
 *      The array and the members of the
 *      globus_net_manager_attr_t struct will be freed by the
 *      globus_net_manager library by calling
 *      free().
 */
typedef globus_result_t (*globus_net_manager_post_listen)(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const globus_net_manager_attr_t    *attr_array,
    char                              **local_contact_out,
    globus_net_manager_attr_t         **attr_array_out);

/**
 * Network Manager Pre-Accept Function Signature
 * @ingroup globus_net_manager_signatures
 *
 * A function of this signature, if included in a network manager
 * implementation, is called before accepting a connection on a
 * transport-specific listening port.
 * 
 * The network manager is passed the network transport-specific options and
 * contact string for the listener. It may modify the options before the
 * accept operation is complete.
 *
 * The globus_net_manager library aborts the accept operation 
 * if this function returns a value other than GLOBUS_SUCCESS. In this
 * case, the globus_net_manager will not call any other
 * globus_net_manager_pre_accept functions configured for this listener.
 *
 * @param[in] manager
 *      Pointer to the network manager struct that is being invoked.
 * @param[in] task_id
 *      An application-specific task ID associated with this network operation.
 * @param[in] transport
 *      The name of the transport associated with this listener.
 * @param[in] local_contact
 *      The transport-specific contact string for the listener.
 * @param[in] attr_array
 *      A NULL-terminated array of transport attributes associated with the
 *      listener.
 * @param[out] attr_array_out
 *      A pointer to an array of transport options to apply to the 
 *      listener prior to returning it to the service. This may be NULL to
 *      indicate no change in the options. If non-NULL, this array must be
 *      terminated with an attribute having a NULL scope.
 *      The array and the members of the
 *      globus_net_manager_attr_t struct will be freed by the
 *      globus_net_manager library by calling
 *      free().
 */
typedef globus_result_t (*globus_net_manager_pre_accept)(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out);

/**
 * Network Manager Post-Accept Function Signature
 * @ingroup globus_net_manager_signatures
 *
 * A function of this signature, if included in a network manager
 * implementation, is called after accepting a connection on a
 * transport-specific listening port.
 * 
 * The network manager is passed the network transport-specific options and
 * contact string for both ends of the connection. It may modify the attributes
 * of the local side of the connection.
 *
 * The globus_net_manager library aborts the accept operation 
 * if this function returns a value other than GLOBUS_SUCCESS. In this
 * case, the globus_net_manager will not call any other
 * globus_net_manager_post_accept functions configured for this connection.
 *
 * @param[in] manager
 *      Pointer to the network manager struct that is being invoked.
 * @param[in] task_id
 *      An application-specific task ID associated with this network operation.
 * @param[in] transport
 *      The name of the transport associated with this listener.
 * @param[in] local_contact
 *      The transport-specific contact string for the local side of the
 *      connection.
 * @param[in] remote_contact
 *      The transport-specific contact string for the remote side of the 
 *      connection.
 * @param[in] attr_array
 *      An array of transport attributes associated with the
 *      listener. The end of the array is indicated by
 *      an attribute containing a NULL scope.
 * @param[out] attr_array_out
 *      A pointer to an array of transport options to apply to the 
 *      listener prior to returning it to the service. This may be NULL to
 *      indicate no change in the options. If non-NULL, this array must be
 *      terminated with an attribute having a NULL scope.
 *      The array and the members of the
 *      globus_net_manager_attr_t struct will be freed by the
 *      globus_net_manager library by calling
 *      free().
 */
typedef globus_result_t (*globus_net_manager_post_accept)(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out);

/**
 * Network Manager Pre-Connect Function Signature
 * @ingroup globus_net_manager_signatures
 *
 * A function of this signature, if included in a network manager
 * implementation, is called after initiating a connection to a
 * transport-specific listener.
 * 
 * The network manager is passed the network transport-specific options and
 * contact string for both ends of the connection. It may modify the attributes
 * of the local side of the connection.
 *
 * The globus_net_manager library aborts the connect operation 
 * if this function returns a value other than GLOBUS_SUCCESS. In this
 * case, the globus_net_manager will not call any other
 * globus_net_manager_pre_connect functions configured for this connection.
 *
 * @param[in] manager
 *      Pointer to the network manager struct that is being invoked.
 * @param[in] task_id
 *      An application-specific task ID associated with this network operation.
 * @param[in] transport
 *      The name of the transport associated with this listener.
 * @param[in] remote_contact
 *      The transport-specific contact string for the remote side of the 
 *      connection.
 * @param[in] attr_array
 *      An array of transport attributes associated with the
 *      listener. The end of the array is indicated by
 *      an attribute containing a NULL scope.
 * @param[out] remote_contact_out
 *      A pointer to the remote contact which the network manager wants to
 *      connect to. This may be NULL to indicate no change in
 *      the contact. This value will be freed() by the globus_net_manager
 *      library.
 * @param[out] attr_array_out
 *      A pointer to an array of transport options to apply to the 
 *      listener prior to returning it to the service. This may be NULL to
 *      indicate no change in the options. If non-NULL, this array must be
 *      terminated with an attribute having a NULL scope.
 *      The array and the members of the
 *      globus_net_manager_attr_t struct will be freed by the
 *      globus_net_manager library by calling
 *      free().
 */
typedef globus_result_t (*globus_net_manager_pre_connect)(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array,
    char                              **remote_contact_out,
    globus_net_manager_attr_t         **attr_array_out);

/**
 * Network Manager Post-Connect Function Signature
 * @ingroup globus_net_manager_signatures
 *
 * A function of this signature, if included in a network manager
 * implementation, is called after establishing a connection to a
 * transport-specific listener.
 * 
 * The network manager is passed the network transport-specific options and
 * contact string for both ends of the connection. It may modify the attributes
 * of the local side of the connection.
 *
 * The globus_net_manager library aborts the connect operation 
 * if this function returns a value other than GLOBUS_SUCCESS. In this
 * case, the globus_net_manager will not call any other
 * globus_net_manager_post_connect functions configured for this connection.
 *
 * @param[in] manager
 *      Pointer to the network manager struct that is being invoked.
 * @param[in] task_id
 *      An application-specific task ID associated with this network operation.
 * @param[in] transport
 *      The name of the transport associated with this listener.
 * @param[in] remote_contact
 *      The transport-specific contact string for the remote side of the 
 *      connection.
 * @param[in] attr_array
 *      An array of transport attributes associated with the
 *      listener. The end of the array is indicated by
 *      an attribute containing a NULL scope.
 * @param[out] attr_array_out
 *      A pointer to an array of transport options to apply to the 
 *      listener prior to returning it to the service. This may be NULL to
 *      indicate no change in the options. If non-NULL, this array must be
 *      terminated with an attribute having a NULL scope.
 *      The array and the members of the
 *      globus_net_manager_attr_t struct will be freed by the
 *      globus_net_manager library by calling
 *      free().
 */
typedef globus_result_t (*globus_net_manager_post_connect)(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out);

/**
 * Network Manager Pre-Close Function Signature
 * @ingroup globus_net_manager_signatures
 *
 * A function of this signature, if included in a network manager
 * implementation, is called prior to closing a connection.
 * 
 * The network manager is passed the network transport-specific options and
 * contact string for both ends of the connection. 
 *
 * The globus_net_manager library aborts the close operation 
 * if this function returns a value other than GLOBUS_SUCCESS. In this
 * case, the globus_net_manager will not call any other
 * globus_net_manager_pre_close functions configured for this connection.
 *
 * @param[in] manager
 *      Pointer to the network manager struct that is being invoked.
 * @param[in] task_id
 *      An application-specific task ID associated with this network operation.
 * @param[in] transport
 *      The name of the transport associated with this listener.
 * @param[in] local_contact
 *      The transport-specific contact string for the local side of the 
 *      connection.
 * @param[in] remote_contact
 *      The transport-specific contact string for the remote side of the 
 *      connection.
 * @param[in] attr_array
 *      An array of transport attributes associated with the
 *      listener. The end of the array is indicated by
 *      an attribute containing a NULL scope.
 */
typedef globus_result_t (*globus_net_manager_pre_close)(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array);

/**
 * Network Manager Post-Close Function Signature
 * @ingroup globus_net_manager_signatures
 *
 * A function of this signature, if included in a network manager
 * implementation, is called after closing a connection.
 * 
 * The network manager is passed the network transport-specific options and
 * contact string for both ends of the connection. 
 *
 * The globus_net_manager library aborts the close operation 
 * if this function returns a value other than GLOBUS_SUCCESS. In this
 * case, the globus_net_manager will not call any other
 * globus_net_manager_pre_close functions configured for this connection.
 *
 * @param[in] manager
 *      Pointer to the network manager struct that is being invoked.
 * @param[in] task_id
 *      An application-specific task ID associated with this network operation.
 * @param[in] transport
 *      The name of the transport associated with this listener.
 * @param[in] local_contact
 *      The transport-specific contact string for the local side of the 
 *      connection.
 * @param[in] remote_contact
 *      The transport-specific contact string for the remote side of the 
 *      connection.
 * @param[in] attr_array
 *      An array of transport attributes associated with the
 *      listener. The end of the array is indicated by
 *      an attribute containing a NULL scope.
 */
typedef globus_result_t (*globus_net_manager_post_close)(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array);

/**
 * @brief Network Manager Definition
 * @ingroup globus_net_manager_types
 * @details
 */
typedef
struct globus_net_manager_s
{
    /** Name of the network manager */
    const char                         *name;
    /** Pre-listen function implementation */
    globus_net_manager_post_listen      pre_listen;
    /** Post-listen function implementation */
    globus_net_manager_post_listen      post_listen;
    /** Pre-accept function implementation */
    globus_net_manager_pre_accept       pre_accept;
    /** Post-accept function implementation */
    globus_net_manager_post_accept      post_accept;
    /** Pre-connect function implementation */
    globus_net_manager_pre_connect      pre_connect;
    /** Post-connect function implementation */
    globus_net_manager_post_connect     post_connect;
    /** Pre-close function implementation */
    globus_net_manager_pre_close        pre_close;
    /** Post-close function implementation */
    globus_net_manager_post_close       post_close;
    /** Manager specific data */
    void *                              manager_data;
}
globus_net_manager_t;

/**
 * @brief Register a network manager
 * @ingroup globus_net_manager
 * @param[in] manager
 *     Manager information to register.
 *
 * The globus_net_manager_register() function adds this network manager
 * to those which will be called by the network manager interface
 * when network events occur. This is typically called by the network
 * manager when its module is activated.
 */
globus_result_t
globus_net_manager_register(
    globus_net_manager_t               *manager);

/**
 * @brief Unregister a network manager
 * @ingroup globus_net_manager
 * @param[in] manager
 *     Manager information to unregister.
 *
 * The globus_net_manager_unregister() function removes this network manager
 * from those which will be called by the network manager interface
 * when network events occur. This is typically called by the network
 * manager when its module is deactivated.
 */
globus_result_t
globus_net_manager_unregister(
    globus_net_manager_t               *manager);

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_NET_MANAGER_H */
