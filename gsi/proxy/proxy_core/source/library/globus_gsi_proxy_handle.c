#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_proxy_handle.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gsi_proxy.h"

/**
 * @name Initialize
 */
/*@{*/
/**
 * Initialize a GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * Initialize a proxy handle which can be used in subsequent
 * operations. The handle may only be used in one sequence of
 * operations at a time.
 *
 * @param handle
 *        The handle to be initialized.
 * @param handle_attrs
 *        Initial attributes to be used to create this handle.
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_destroy()
 */
globus_result_t
globus_gsi_proxy_handle_init(
    globus_gsi_proxy_handle_t *         handle,
    globus_gsi_proxy_handle_attrs_t     handle_attrs)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_init() */
/*@}*/

/**
 * @name Destroy
 */
/*@{*/
/**
 * Destroy a GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * @param handle
 *        The handle to be destroyed.
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_init()
 */
globus_result_t
globus_gsi_proxy_handle_destroy(
    globus_gsi_proxy_handle_t *         handle)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_destroy */
/*@}*/


/**
 * @name Set Policy
 */
/*@{*/
/**
 * Set the policy to be used in the GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * This function sets the policy to be used in the proxy cert
 * info extension.
 *
 * @param handle
 *        The handle to be modified.
 * @param policy
 *        The policy data.
 * @param policy_NID
 *        The NID of the policy language.
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_get_policy()
 */
globus_result_t
globus_gsi_proxy_handle_set_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char *                     policy,
    int                                 policy_NID)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_set_policy */
/*@}*/


/**
 * @name Get Policy
 */
/*@{*/
/**
 * Get the policy from the GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * This function gets the policy that is being used in the 
 * proxy cert info extension.
 *
 * @param handle
 *        The handle to be interrogated.
 * @param policy
 *        The policy data.
 * @param policy_NID
 *        The NID of the policy language.
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_set_policy()
 */
globus_result_t
globus_gsi_proxy_handle_get_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    policy,
    int *                               policy_NID)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_get_policy */
/*@}*/

/**
 * @name Set Group
 */
/*@{*/
/**
 * Set the group to be used in the GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * This function sets the group to be used in the proxy cert
 * info extension.
 *
 * @param handle
 *        The handle to be modified.
 * @param group
 *        The group identifier.
 * @param attached
 *        The attachment state of the group
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_get_group()
 */
globus_result_t
globus_gsi_proxy_handle_set_group(
    globus_gsi_proxy_handle_t           handle,
    unsigned char *                     group,
    int                                 attached)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_set_group */
/*@}*/


/**
 * @name Get Group
 */
/*@{*/
/**
 * Get the group from the GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * This function gets the group that is being used in the 
 * proxy cert info extension.
 *
 * @param handle
 *        The handle to be interrogated.
 * @param group
 *        The group identifier.
 * @param attached
 *        The attachment state of the group
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_set_group()
 */
globus_result_t
globus_gsi_proxy_handle_get_group(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    group,
    int *                               attached)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_get_group */
/*@}*/


/**
 * @name Set Path Length
 */
/*@{*/
/**
 * Set the path length to be used in the GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * This function sets the path length to be used in the proxy
 * cert info extension.
 *
 * @param handle
 *        The handle to be modified.
 * @param pathlen
 *        The maximum allowable path length
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_get_pathlen()
 */
globus_result_t
globus_gsi_proxy_handle_set_pathlen(
    globus_gsi_proxy_handle_t           handle,
    int                                 pathlen)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_set_pathlen */
/*@}*/


/**
 * @name Get Path Length
 */
/*@{*/
/**
 * Get the path length from the GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * This function gets the path length that is being used in the 
 * proxy cert info extension.
 *
 * @param handle
 *        The handle to be interrogated.
 * @param pathlen
 *        The maximum allowable path length
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_set_pathlen()
 */
globus_result_t
globus_gsi_proxy_handle_get_pathlen(
    globus_gsi_proxy_handle_t           handle,
    int *                               pathlen)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_get_pathlen */
/*@}*/


/**
 * @name Clear Cert Info
 */
/*@{*/
/**
 * Clear the proxy cert info extension stored in the GSI Proxy handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * This function clears proxy cert info extension related setting in
 * the GSI Proxy handle.
 *
 * @param handle
 *        The handle to be interrogated.
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_set_pathlen()
 */
globus_result_t
globus_gsi_proxy_handle_clear_cert_info(
    globus_gsi_proxy_handle_t           handle)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_clear_cert_info */
/*@}*/


