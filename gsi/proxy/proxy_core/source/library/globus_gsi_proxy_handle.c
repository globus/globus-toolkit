#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_proxy_handle.c
 * @file Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#define GLOBUS_GSI_PROXY_HANDLE_MALLOC_ERROR \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_PROXY_MODULE, \
        errno, \
        GLOBUS_GSI_PROXY_ERROR_ERRNO, \
        "%s:%d: Could not allocate enough memory: %d bytes", \
        __FILE__, __LINE__, len))

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
 *        A pointer to the handle to be initialized.  If the
 *        handle is originally NULL, space is allocated for it.
 *        Otherwise, the current values of the handle are overwritten.
 *        
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
    globus_gsi_proxy_handle_t           hand;
    globus_result_t                     result;
    int                                 len;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_init";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    /* setup the handle */
    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    len = sizeof(globus_i_gsi_proxy_handle_t);
    *handle = (globus_gsi_proxy_handle_t) 
        globus_malloc(len);

    if(*handle == NULL)
    {
        result = GLOBUS_GSI_PROXY_HANDLE_MALLOC_ERROR;
        goto exit;
    }

    hand = *handle; 

    /* initialize the private key */
    if((hand->proxy_key = EVP_PKEY_new()) == NULL)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            ("Couldn't create new private key structure for handle"));
        goto free_handle;
    }

    /* initialize the X509 request structure */
    if((hand->req = X509_REQ_new()) == NULL)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Couldn't create new X509_REQ structure for handle"));
        goto free_handle;
    }

    /* initialize the handle attributes */
    if(handle_attrs == NULL)
    {
        result = globus_gsi_proxy_handle_attrs_init(&hand->attrs);
        if(result != GLOBUS_SUCCESS)
        {
            result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
            goto free_handle;
        }
    }
    else
    {
        result = globus_gsi_proxy_handle_attrs_copy(handle_attrs, 
                                                    &hand->attrs);
        if(result != GLOBUS_SUCCESS)
        {
            result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
            goto free_handle;
        }
    }

    hand->is_limited = GLOBUS_FALSE;

    if((hand->proxy_cert_info = PROXYCERTINFO_new()) == NULL)
    {        
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            ("Error initializing new PROXYCERTINFO struct"));
        goto free_handle;
    }

    result = GLOBUS_SUCCESS;
    goto exit;

 free_handle:

    if(hand)
    {
        globus_gsi_proxy_handle_destroy(hand);
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
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
    globus_gsi_proxy_handle_t           handle)
{
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_destroy";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle != NULL)
    {
        /* free each of the pointers in the handle struct */
        X509_REQ_free(handle->req);
        EVP_PKEY_free(handle->proxy_key);
        globus_gsi_proxy_handle_attrs_destroy(handle->attrs);
        PROXYCERTINFO_free(handle->proxy_cert_info);

        /* free the handle struct memory */
        globus_free(handle);
        handle = NULL;
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_destroy */
/*@}*/

/**
 * Copy 
 * @ingroup globus_gsi_proxy_handle
 */
/* @{ */
/**
 * Make a copy of the handle.  There probably shouldn't be multiple
 * copies of a handle lying around, since a handle should only be
 * used for once sequence of operations, so this function should be used
 * sparingly, if at all.
 *
 * @param a
 *        The original handle to copy
 * @param b
 *        The copied handle
 * @return
 *        GLOBUS_SUCCESS if the copy was successful, an error
 *        otherwise
 */
globus_result_t
globus_gsi_proxy_handle_copy(
    globus_gsi_proxy_handle_t           a,
    globus_gsi_proxy_handle_t *         b)
{
    int                                 len;
    unsigned char *                     der_encoded = NULL;
    globus_gsi_proxy_handle_attrs_t     b_attrs;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_copy";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(a == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle parameter passed to function: %s", _function_name_));
        goto exit;
    }
    if(b == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle parameter passed to function: %s", _function_name_));
        goto exit;
    }
    
    result = globus_gsi_proxy_handle_attrs_copy(a->attrs, & b_attrs);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
        goto exit;
    }
        
    result = globus_gsi_proxy_handle_init(b, b_attrs);        
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE);
        goto free_handle;
    }

    if(((*b)->req = X509_REQ_dup(a->req)) == NULL)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Error copying X509_REQ in proxy handle"));
        goto free_handle;
    }

    len = i2d_PrivateKey(a->proxy_key, &der_encoded);

    if(!d2i_PrivateKey(a->proxy_key->type, &(*b)->proxy_key, 
                       &der_encoded, len))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            ("Error converting DER encoded private key to internal form"));
        goto exit;
    }

    result = GLOBUS_SUCCESS;
    goto exit;

 free_handle:
    if(b)
    {
        globus_gsi_proxy_handle_destroy(*b);
    }

 exit:

    if(der_encoded)
    {
        globus_free(der_encoded);
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_proxy_handle_get_req(
    globus_gsi_proxy_handle_t           handle,
    X509_REQ **                         req)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_req";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("Invalid handle (NULL) passed to function"));
        goto exit;
    }

    if(!req)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Invalid req pointer passed to function"));
        goto exit;
    }

    *req = X509_REQ_dup(handle->req);

    if(!(*req))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("X509_REQ could not be copied"));
        goto exit;
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
    
globus_result_t
globus_gsi_proxy_handle_set_req(
    globus_gsi_proxy_handle_t           handle,
    X509_REQ *                          req)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_req";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("Invalid handle (NULL) passed to function"));
        goto exit;
    }
    
    if(handle->req)
    {
        X509_REQ_free(req);
        handle->req = NULL;
    }

    if(req)
    {
        handle->req = X509_REQ_dup(req);
        if(!handle->req)
        {
            GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
                ("Couldn't copy X509_REQ"));
            goto exit;
        }
    }
    
 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_proxy_handle_get_private_key(
    globus_gsi_proxy_handle_t           handle,
    EVP_PKEY **                         proxy_key)
{
    int                                 length;
    unsigned char *                     der_encoded = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_private_key";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("Invalid handle (NULL) passed to function"));
        goto exit;
    }
    
    if(!proxy_key)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            ("Invalid proxy_key (NULL) passed to function"));
        goto exit;
    }

    length = i2d_PrivateKey(handle->proxy_key, &der_encoded);

    if(!d2i_PrivateKey(handle->proxy_key->type, proxy_key, 
                       &der_encoded, length))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            ("Error converting DER encoded private key to internal form"));
        goto exit;
    }
    
 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_proxy_handle_set_private_key(
    globus_gsi_proxy_handle_t           handle,
    EVP_PKEY *                          proxy_key)
{
    int                                 length;
    unsigned char *                     der_encoded = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ = 
        "globus_gsi_proxy_handle_set_private_key";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("Invalid handle (NULL) passed to function"));
        goto exit;
    }

    if(handle->proxy_key)
    {
        EVP_PKEY_free(handle->proxy_key);
        handle->proxy_key = NULL;
    }
    
    if(proxy_key)
    {

        length = i2d_PrivateKey(proxy_key, &der_encoded);
        
        if(!d2i_PrivateKey(proxy_key->type, &handle->proxy_key, 
                           &der_encoded, length))
        {
            GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
                ("Error converting DER encoded private key to internal form"));
            goto exit;
        }
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_proxy_handle_set_is_limited(
    globus_gsi_proxy_handle_t           handle,
    globus_bool_t                       is_limited)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ = 
        "globus_gsi_proxy_handle_set_is_limited";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("Invalid handle (NULL) passed to function"));
        goto exit;
    }

    handle->is_limited = is_limited;

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

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
 *        GLOBUS_SUCCESS if the handle and its associated fields are valid
 *        otherwise an error is returned
 *
 * @see globus_gsi_proxy_handle_get_policy()
 */
globus_result_t
globus_gsi_proxy_handle_set_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char *                     policy,
    int                                 policy_NID)
{
    PROXYRESTRICTION *                  restriction;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_policy";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
    
    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    restriction = PROXYCERTINFO_get_restriction(handle->proxy_cert_info);
    if(!PROXYRESTRICTION_set_policy_language(restriction, 
                                             OBJ_nid2obj(policy_NID)) ||
       !PROXYRESTRICTION_set_policy(restriction, policy, strlen(policy)))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYRESTRICTION,
            ("PROXYRESTRICTION of proxy handle could not be initialized"));
        goto exit;
    }
    
    result = GLOBUS_SUCCESS;

 exit:
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
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
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an error
 *        is returned
 *
 * @see globus_gsi_proxy_handle_set_policy()
 */
globus_result_t
globus_gsi_proxy_handle_get_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    policy,
    int *                               policy_length,
    int *                               policy_NID)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_policy";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    *policy = PROXYRESTRICTION_get_policy(
        PROXYCERTINFO_get_restriction(handle->proxy_cert_info),
        policy_length);
    
    *policy_NID = OBJ_obj2nid(PROXYRESTRICTION_get_policy_language(
        PROXYCERTINFO_get_restriction(handle->proxy_cert_info)));
    
    result = GLOBUS_SUCCESS;

 exit:
    
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
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
 *        GLOBUS_SUCCESS if the handle and its associated fields are valid,
 *        otherwise an error is returned
 *
 * @see globus_gsi_proxy_handle_get_group()
 */
globus_result_t
globus_gsi_proxy_handle_set_group(
    globus_gsi_proxy_handle_t           handle,
    unsigned char *                     group,
    int                                 attached)
{
    globus_result_t                     result;
    PROXYGROUP *                        proxygroup;

    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_group";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
    
    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    proxygroup = PROXYCERTINFO_get_group(handle->proxy_cert_info);
    if(!PROXYGROUP_set_name(proxygroup, group, strlen(group)) ||
       !PROXYGROUP_set_attached(proxygroup, attached))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYGROUP,
            ("Couldn't set PROXYGROUP in proxy handle"));
        goto exit;
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
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
 * @param group_length
 *        The length of the group identifier.
 * @param attached
 *        The attachment state of the group
 * @return
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an
 *        error is returned
 *
 * @see globus_gsi_proxy_handle_set_group()
 */
globus_result_t
globus_gsi_proxy_handle_get_group(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    group,
    long *                              group_length,
    int *                               attached)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_group";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
    
    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    *group = PROXYGROUP_get_name(
        PROXYCERTINFO_get_group(handle->proxy_cert_info), group_length);
    *attached = *PROXYGROUP_get_attached(
        PROXYCERTINFO_get_group(handle->proxy_cert_info));

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
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
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an
 *        error is returned
 *
 * @see globus_gsi_proxy_handle_get_pathlen()
 */
globus_result_t
globus_gsi_proxy_handle_set_pathlen(
    globus_gsi_proxy_handle_t           handle,
    long                                pathlen)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_pathlen";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    if(!PROXYCERTINFO_set_path_length(handle->proxy_cert_info, &pathlen))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PATHLENGTH,
            ("Error setting the path length of the PROXYCERTINFO extension "
             "in the proxy handle"));
        goto exit;
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
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
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an
 *        error is returned
 *
 * @see globus_gsi_proxy_handle_set_pathlen()
 */
globus_result_t
globus_gsi_proxy_handle_get_pathlen(
    globus_gsi_proxy_handle_t           handle,
    int *                               pathlen)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_pathlen";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }
    *pathlen = PROXYCERTINFO_get_path_length(handle->proxy_cert_info);
    result = GLOBUS_SUCCESS;
    
 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
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
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an
 *        error is returned
 *
 * @see globus_gsi_proxy_handle_set_pathlen()
 */
globus_result_t
globus_gsi_proxy_handle_clear_cert_info(
    globus_gsi_proxy_handle_t           handle)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_clear_cert_info";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    PROXYCERTINFO_free(handle->proxy_cert_info);
    handle->proxy_cert_info = PROXYCERTINFO_new();
    if(handle->proxy_cert_info == NULL)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            ("PROXYCERTINFO could not be initialized"));
        goto exit;
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_clear_cert_info */
/*@}*/


globus_result_t
globus_gsi_proxy_handle_get_proxy_cert_info(
    globus_gsi_proxy_handle_t           handle,
    PROXYCERTINFO **                    pci)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_proxy_cert_info";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
    
    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("Invalid handle (NULL) passed to function"));
        goto exit;
    }

    if(!pci)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            ("Invalid PROXYCERTINFO passed to function"));
        goto exit;
    }

    *pci = PROXYCERTINFO_dup(handle->proxy_cert_info);
    if(!*pci)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            ("Couldn't copy PROXYCERTINFO structure"));
        goto exit;
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_proxy_handle_set_proxy_cert_info(
    globus_gsi_proxy_handle_t           handle,
    PROXYCERTINFO *                     pci)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_proxy_cert_info";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("Invalid handle (NULL) passed to function"));
        goto exit;
    }

    if(handle->proxy_cert_info)
    {
        PROXYCERTINFO_free(handle->proxy_cert_info);
        handle->proxy_cert_info = NULL;
    }
    
    if(pci)
    {
        handle->proxy_cert_info = PROXYCERTINFO_dup(pci);
        if(!handle->proxy_cert_info)
        {
            GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
                ("Couldn't copy PROXYCERTINFO"));
            goto exit;
        }
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

/**
 * @name Proxy Is Limited
 */
/* @{ */
/**
 * Check to see if the proxy is a limited proxy (the limited
 * proxy flag in the handle is set)
 *
 * @param handle
 *        the proxy handle to check
 *
 * @param is_limited
 *        boolean value to set depending on the value in the handle
 *
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_is_limited(
    globus_gsi_proxy_handle_t           handle,
    globus_bool_t *                     is_limited)
{    
    static char *                       _function_name_ =
        "globus_gsi_proxy_is_limited";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    *is_limited = handle->is_limited;

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* @} */


/**
 * @name Get Signing Algorithm
 */
/* @{ */
/**
 * Get the signing algorithm used to sign the proxy cert request
 *
 * @param handle
 *        The proxy handle containing the type of signing algorithm used
 * @param time_valid
 *        signing algorithm of the proxy handle
 * 
 * @result
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_get_signing_algorithm(
    globus_gsi_proxy_handle_t           handle,
    EVP_MD **                           signing_algorithm)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_signing_algorithm";
    
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    result = globus_gsi_proxy_handle_attrs_get_signing_algorithm(
        handle->attrs,
        signing_algorithm);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }
        
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Key Bits
 */
/* @{ */
/**
 * Get the key bits used for the pub/private key pair of the proxy
 *
 * @param handle
 *        The proxy handle to get the key bits of
 * @param time_valid
 *        key bits of the proxy handle
 * 
 * @result
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_get_keybits(
    globus_gsi_proxy_handle_t           handle,
    int *                               key_bits)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_key_bits";
    
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    result = globus_gsi_proxy_handle_attrs_get_keybits(handle->attrs,
                                                       key_bits);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }
        
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Init Prime
 */
/* @{ */
/**
 * Get the init prime of the proxy handle
 *
 * @param handle
 *        The handle to get the init prime used in generating the key pair
 * @param skew
 *        The resulting init prime
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case
 *        an error object identifier (in the form of a globus_result_t)
 *        is returned
 */
globus_result_t
globus_gsi_proxy_handle_get_init_prime(
    globus_gsi_proxy_handle_t           handle,
    int *                               init_prime)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_init_prime";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    result = globus_gsi_proxy_handle_attrs_get_init_prime(handle->attrs,
                                                          init_prime);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Time Valid
 */
/* @{ */
/**
 * Get the validity time of the proxy
 *
 * @param handle
 *        The proxy handle to get the expiration date of
 * @param time_valid
 *        expiration date of the proxy handle
 * 
 * @result
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_get_time_valid(
    globus_gsi_proxy_handle_t           handle,
    int *                               time_valid)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_time_valid";
    
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    result = globus_gsi_proxy_handle_attrs_get_time_valid(handle->attrs,
                                                          time_valid);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }
        
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

/**
 * @name Get Clock Skew
 */
/* @{ */
/**
 * Get the clock skew of the proxy handle
 *
 * @param handle
 *        The handle to get the clock skew of
 * @param skew
 *        The resulting clock skew
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case
 *        an error object identifier (in the form of a globus_result_t)
 *        is returned
 */
globus_result_t
globus_gsi_proxy_handle_get_clock_skew_allowable(
    globus_gsi_proxy_handle_t           handle,
    int *                               skew)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_clock_skew_allowable";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    result = globus_gsi_proxy_handle_attrs_get_clock_skew_allowable(
        handle->attrs,
        skew);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Callback for Creating Keys
 */
/* @{ */
/**
 * Get the callback for creating the public/private key pair
 *
 * @param handle
 *        The proxy handle to get the callback from
 * @param callback
 *        The callback to set
 *
 * @result
 *        GLOBUS_SUCCESS or an error object identifier
 */
globus_result_t
globus_gsi_proxy_handle_get_key_gen_callback(
    globus_gsi_proxy_handle_t           handle,
    void                                (**callback)(int, int, void *))
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_key_gen_callback";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    result = globus_gsi_proxy_handle_attrs_get_key_gen_callback(
        handle->attrs,
        callback);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
} 
/* @} */        
