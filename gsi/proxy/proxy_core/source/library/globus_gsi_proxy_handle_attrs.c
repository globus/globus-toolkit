#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_proxy_handle_attrs.c
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
 * Initialize GSI Proxy Handle Attributes.
 * @ingroup globus_gsi_proxy_handle_attrs
 *
 * Initialize proxy handle attributes, which
 * can (and should) be associated with a proxy handle.
 * For most purposes, these attributes should primarily
 * be used by the proxy handle. 
 *
 * Currently, no attibute values are initialized.
 *
 * @param handle_attrs
 *        The handle attributes structure to be initialized
 * @return
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_attrs_destroy()
 */

globus_result_t
globus_gsi_proxy_handle_attrs_init(
    globus_gsi_proxy_handle_attrs_t *   handle_attrs)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_init() */
/*@}*/

/**
 * @name Destroy
 */
/* @{ */
/**
 * Destroy the GSI Proxy handle attributes
 * @ingroup globus_gsi_proxy_handle_attrs
 *
 * @param handle_attrs
 *        The handle attributes to be destroyed.
 * @return 
 *        GLOBUS_SUCCESS
 *
 * @see globus_gsi_proxy_handle_attrs_init()
 */
globus_result_t
globus_gsi_proxy_handle_attrs_destroy(
    globus_gsi_proxy_handle_attrs_t *   handle_attrs)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_destroy() */
/*@}*/
/**
 * @name Copy Attributes
 */
/*@{*/
/**
 * Make a copy of GSI Proxy handle attributes
 * @ingroup globus_gsi_proxy_handle_attrs
 *
 * @param a 
 *        The handle attributes to copy
 * @param b 
 *        The copy
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_attrs_copy(
    globus_gsi_proxy_handle_attrs_t *   a,
    globus_gsi_proxy_handle_attrs_t *   b)
{
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_attrs_copy() */
/*@}*/

