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
/*}@*/


globus_result_t
globus_gsi_proxy_handle_set_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char *                     policy,
    int                                 policy_NID)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gsi_proxy_handle_get_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    policy,
    int *                               policy_NID)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gsi_proxy_handle_set_group(
    globus_gsi_proxy_handle_t           handle,
    unsigned char *                     group,
    int                                 attached)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gsi_proxy_handle_get_group(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    group,
    int *                               attached)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gsi_proxy_handle_set_pathlen(
    globus_gsi_proxy_handle_t           handle,
    int                                 pathlen)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gsi_proxy_handle_get_pathlen(
    globus_gsi_proxy_handle_t           handle,
    int *                               pathlen)
{
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_gsi_proxy_handle_clear_cert_info(
    globus_gsi_proxy_handle_t           handle)
{
    return GLOBUS_SUCCESS;
}


