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

#define DEFAULT_KEY_BITS                1024
#define DEFAULT_PUB_EXPONENT            0x10001  /* 65537 */

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
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_attrs_init";

    globus_gsi_proxy_handle_attrs_t     attrs;

    if(handle_attrs == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE_ATTRS);
    }

    if((*handle_attrs = (globus_gsi_proxy_handle_attrs_t)
       globus_malloc(sizeof(globus_i_gsi_proxy_handle_attrs_t))) == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }

    attrs = *handle_attrs;

    attrs->key_bits = DEFAULT_KEY_BITS;
    attrs->init_prime = DEFAULT_PUB_EXPONENT;
   
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
    globus_gsi_proxy_handle_attrs_t     handle_attrs)
{
    if(handle_attrs != NULL)
    {
        globus_free(handle_attrs);
        handle_attrs = NULL;
    }

    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_destroy() */
/*@}*/

/**
 * @name Set Key Bits
 */
/* @{ */
/**
 * Set the length of the public key pair
 * used by the proxy certificate
 * @ingroup globus_gsi_proxy_handle_attrs
 *
 * @param handle_attrs 
 *        the attributes to set
 * @param bits
 *        the length to set it to (usually 1024)
 *
 * @return 
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_attrs_set_keybits(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    int                                 bits)
{
    handle_attrs->key_bits = bits;
    
    return GLOBUS_SUCCESS;
}
/* @} */


/**
 * @name Get Key Bits
 */
/* @{ */
/**
 * Gets the length of the public key pair used by
 * the proxy certificate
 * @ingroup globus_gsi_proxy_handle_attrs
 *
 * @param handle_attrs
 *        the attributes to get the key length from
 * @param bits
 *        the length of the key pair in bits
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_attrs_get_keybits(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    int *                               bits)
{
    *bits = handle_attrs->key_bits;
    
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * @name Set Initial Prime Number
 */
/* @{ */
/**
 * Set the initial prime number used for
 * generating public key pairs in the RSA
 * algorithm
 * @ingroup globus_gsi_proxy_handle_attrs
 *
 * @param handle_attrs
 *        The attributes to set
 * @param prime
 *        The prime number to set it to
 *        This value needs to be a prime number
 * @return 
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_attrs_set_init_prime(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    int                                 prime)
{
    handle_attrs->init_prime = prime;

    return GLOBUS_SUCCESS;
};
/* @} */


/**
 * @name Get Initial Prime Number
 */
/* @{ */
/**
 * Get the initial prime number used for
 * generating the public key pair in the
 * RSA algorithm
 * @ingroup globus_gsi_proxy_handle_attrs
 *
 * @param handle_attrs
 *        The attributes to get the initial
 *        prime number from
 * @param prime
 *        The initial prime number taken from the
 *        attributes
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_attrs_get_init_prime(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    int *                               prime)
{
    *prime = handle_attrs->init_prime;

    return GLOBUS_SUCCESS;
};
/* @} */


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
    globus_gsi_proxy_handle_attrs_t     a,
    globus_gsi_proxy_handle_attrs_t *   b)
{
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_attrs_copy";
    
    if(a == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE_ATTRS);
    }
    if(b == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NON_NULL_HANDLE_ATTRS);
    }

    if((result = globus_gsi_proxy_handle_attrs_init(b)) != GLOBUS_SUCCESS)
    {
        return result;
    }

    (*b)->key_bits = a->key_bits;
    (*b)->init_prime = a->init_prime;

    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_attrs_copy() */
/*@}*/

