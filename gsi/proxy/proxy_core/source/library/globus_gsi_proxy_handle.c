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

#define DEFAULT_SIGNING_ALGORITHM       EVP_md5()
#define DEFAULT_TIME_VALID              (12*60)   /* actually in minutes */
#define DEFAULT_CLOCK_SKEW              (5*60)    /* actually in seconds */

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
    globus_gsi_proxy_handle_t           hand;
    if(handle != NULL)
    {
        /* ERROR: The handle isn't null - don't want to overwrite it */
        return 
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NON_NULL_HANDLE_ATTRS);
    }

    *handle = (globus_gsi_proxy_handle_t) 
        globus_malloc(sizeof(globus_i_gsi_proxy_handle_t));

    hand = *handle; 

    /* initialize the private key */
    hand->proxy_key = EVP_PKEY_new();
    if(hand->proxy_key == NULL)
    {
        /* ERROR: EVP_PKEY_new() returned an error */
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR(GLOBUS_GSI_PROXY_OPENSSL_ERROR);
    }

    /* initialize the X509 request structure */
    hand->req = X509_REQ_new();
    if(hand->req == NULL)
    {
        /* ERROR: X509_REQ_new returned an error */
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR(GLOBUS_GSI_PROXY_OPENSSL_ERROR);
    }

    /* initialize the handle attributes */
    hand->attrs = handle_attrs;

    hand->proxy_cert_info = PROXYCERTINFO_new();
    if(hand->proxy_cert_info == NULL)
    {        
        /* ERROR: PROXYCERTINFO_new() returned an error */
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR(GLOBUS_GSI_PROXY_OPENSSL_ERROR);
    }

    hand->signing_algorithm = DEFAULT_SIGNING_ALGORITHM;
    hand->time_valid = DEFAULT_TIME_VALID;
    hand->clock_skew = DEFAULT_CLOCK_SKEW;

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
    globus_gsi_proxy_handle_t           handle)
{
    if(handle != NULL)
    {
        /* free each of the pointers in the handle struct */
        X509_REQ_free(handle->req);
        EVP_KEY_free(handle->proxy_key);
        globus_gsi_proxy_handle_attrs_destroy(handle->attrs);
        PROXYCERTINFO_free(handle->proxy_cert_info);

        /* free the handle struct memory */
        globus_free(handle);
        handle = NULL;
    }

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
    
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }

    restriction = PROXYCERTINFO_get_restriction(handle->proxy_cert_info);
    if(!PROXYRESTRICTION_set_policy_language(restriction, 
                                             OBJ_nid2obj(policy_NID)) ||
       !PROXYRESTRICTION_set_policy(restriction, policy, strlen(policy)))
    {
        return 
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_PROXYRESTRICTION);
    }
    
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
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }

    *policy = PROXYRESTRICTION_get_policy(
        PROXYCERTINFO_get_restriction(handle->proxy_cert_info),
        policy_length);
    
    *policy_NID = OBJ_obj2nid(PROXYRESTRICTION_get_policy_language(
        PROXYCERTINFO_get_restriction(handle->proxy_cert_info)));
    
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
    PROXYGROUP *                        proxygroup;
    
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    proxygroup = PROXYCERTINFO_get_group(handle->proxy_cert_info);
    if(!PROXYGROUP_set_name(proxygroup, group, strlen(group)) ||
       !PROXYGROUP_set_attached(proxygroup, attached))
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_PROXYGROUP);
    }

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
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an
 *        error is returned
 *
 * @see globus_gsi_proxy_handle_set_group()
 */
globus_result_t
globus_gsi_proxy_handle_get_group(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    group,
    int *                               attached)
{
    long                                group_length;

    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }

    *group = PROXYGROUP_get_name(
        PROXYCERTINFO_get_group(handle->proxy_cert_info), & group_length);
    *attached = *PROXYGROUP_get_attached(
        PROXYCERTINFO_get_group(handle->proxy_cert_info));

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
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    if(!PROXYCERTINFO_set_path_length(handle->proxy_cert_info, &pathlen))
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_PATHLENGTH);
    }
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
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    *pathlen = PROXYCERTINFO_get_path_length(handle->proxy_cert_info);
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
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an
 *        error is returned
 *
 * @see globus_gsi_proxy_handle_set_pathlen()
 */
globus_result_t
globus_gsi_proxy_handle_clear_cert_info(
    globus_gsi_proxy_handle_t           handle)
{
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    PROXYCERTINFO_free(handle->proxy_cert_info);
    handle->proxy_cert_info = PROXYCERTINFO_new();
    if(handle->proxy_cert_info == NULL)
    {
        return GLOBUS_GSI_OPENSSL_ERROR;
    }
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_clear_cert_info */
/*@}*/

/**
 * @name Set Signing Algorithm
 */
/* @{ */
/**
 * Sets the Signing Algorithm to be used to sign
 * the certificate request.  In most cases, the
 * signing party will ignore this value, and sign
 * with an algorithm of its choice.
 * @ingroup globus_gsi_proxy_handle
 *
 * @param handle
 *        The proxy handle to set the signing algorithm of
 * @param algorithm
 *        The signing algorithm to set 
 * @return
 *        Returns 
 *        GLOBUS_SUCCESS if the handle is valid, otherwise
 *        an error object is returned.
 */
globus_result_t
globus_gsi_proxy_handle_set_signing_algorithm(
    globus_gsi_proxy_handle_t           handle,
    EVP_MD *                            algorithm)
{
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    handle->signing_algorithm = algorithm;
    return GLOBUS_SUCCESS;
};
/* @} */


/**
 * @name Set Signing Algorithm
 */
/* @{ */
/**
 * Sets the Signing Algorithm to be used to sign
 * the certificate request.  In most cases, the
 * signing party will ignore this value, and sign
 * with an algorithm of its choice.
 * @ingroup globus_gsi_proxy_handle
 *
 * @param handle
 *        The proxy handle to set the signing algorithm of
 * @param algorithm
 *        The signing algorithm to set 
 * @return
 *        Returns 
 *        GLOBUS_SUCCESS if the handle is valid, otherwise
 *        an error object is returned.
 */
globus_result_t
globus_gsi_proxy_handle_get_signing_algorithm(
    globus_gsi_proxy_handle_t           handle,
    EVP_MD **                           algorithm)
{
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }

    *algorithm = handle->signing_algorithm;
    return GLOBUS_SUCCESS;
};
/* @} */


/**
 * @name Set Minutes Valid
 */
/* @{ */
/**
 * Set the number of minutes the proxy certificate
 * is valid for.  This is only a suggestion
 * for the signer, who can accept or reject
 * @ingroup globus_gsi_proxy_handle
 *
 * @param handle
 *        The handle containing the minutes valid field to be set
 * @param minutes
 *        The valid minutes the proxy cert has before expiring.
 * @return 
 *        GLOBUS_SUCCESS if the handle is valid, otherwise 
 *        an error is returned.
 */
globus_result_t
globus_gsi_proxy_handle_set_time_valid(
    globus_gsi_proxy_handle_t           handle,
    int                                 time_valid)
{
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    handle->time_valid = time_valid;
    return GLOBUS_SUCCESS;
};
/* @} */


/**
 * @name Get Minutes Valid
 */
/* @{ */
/**
 * Get the number of minutes this proxy certificate
 * will be valid for when signed, assuming the
 * signer accepts that length of time.
 * @ingroup globus_gsi_proxy_handle
 *
 * @param handle
 *        The handle containing the valid minutes to get
 * @param minutes
 *        The number of minutes this certificate will be
 *        valid for when signed
 * @return
 *        GLOBUS_SUCCESS if handle is valid, otherwise
 *        an error is returned
 */
globus_result_t
globus_gsi_proxy_handle_get_time_valid(
    globus_gsi_proxy_handle_t           handle,
    int *                               time_valid)
{
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR(GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    *time_valid = handle->time_valid;
    return GLOBUS_SUCCESS;
}
/* @} */


/**
 * @name Set Clock Skew Allowable
 */
/* @{ */
/**
 * Sets the clock skew in minutes of the proxy cert request
 * so that time differences between hosts won't
 * cause problems.  This value defaults to 5 minutes.
 * @ingroup globus_gsi_proxy_handle
 *
 * @param handle
 *        the handle containing the clock skew to be set
 * @param skew
 *        the amount to skew by (in seconds)
 * @return 
 *        GLOBUS_SUCCESS if the handle is valid - otherwise an
 *        error is returned.
 */
globus_result_t
globus_gsi_proxy_handle_set_clock_skew_allowable(
    globus_gsi_proxy_handle_t           handle,
    int                                 skew)
{
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR(GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    handle->clock_skew = skew;
    return GLOBUS_SUCCESS;
};
/* @} */


/**
 * @name Get Clock Skew Allowable
 */
/* @{ */
/**
 * Get the allowable clock skew for the proxy certificate
 * @ingroup globus_gsi_proxy_handle
 *
 * @param handle
 *        The handle to get the clock skew from
 * @param skew
 *        The allowable clock skew (in seconds)
 *        to get from the proxy certificate
 *        request.  This value gets set by the function, so it needs
 *        to be a pointer.
 * @return
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an error
 *        is returned
 */
globus_result_t
globus_gsi_proxy_handle_get_clock_skew_allowable(
    globus_gsi_proxy_handle_t           handle,
    int *                               skew)
{
    if(handle == NULL)
    {
        return GLOBUS_GSI_PROXY_ERROR(GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
    }
    *skew = handle->clock_skew;
    return GLOBUS_SUCCESS;
};
/* @} */

