/*
 * Copyright 1999-2006 University of Chicago
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_proxy_handle.c
 * @file Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#define GLOBUS_GSI_PROXY_HANDLE_MALLOC_ERROR(_LENGTH_) \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_PROXY_MODULE, \
        errno, \
        GLOBUS_GSI_PROXY_ERROR_ERRNO, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        "Could not allocate enough memory: %d bytes", \
        _LENGTH_))
#endif

#include "globus_i_gsi_proxy.h"

/**
 * @name Initialize and Destroy
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Initialize a GSI Proxy handle.
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
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 *
 * @see globus_gsi_proxy_handle_destroy()
 */
globus_result_t
globus_gsi_proxy_handle_init(
    globus_gsi_proxy_handle_t *         handle,
    globus_gsi_proxy_handle_attrs_t     handle_attrs)
{
    globus_gsi_proxy_handle_t           handle_i;
    globus_result_t                     result = GLOBUS_SUCCESS;
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
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }

    len = sizeof(globus_i_gsi_proxy_handle_t);
    *handle = (globus_gsi_proxy_handle_t) 
        malloc(len);

    if(*handle == NULL)
    {
        result = GLOBUS_GSI_PROXY_HANDLE_MALLOC_ERROR(len);
        goto exit;
    }

    memset(*handle, (int) NULL, len);

    handle_i = *handle; 

    /* initialize the X509 request structure */
    if((handle_i->req = X509_REQ_new()) == NULL)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            (_PCSL("Couldn't create new X509_REQ structure for handle")));
        goto free_handle;
    }

    /* create a new PCI extension */
    if((handle_i->proxy_cert_info = PROXYCERTINFO_new()) == NULL)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            (_PCSL("Error initializing new PROXYCERTINFO struct")));
        goto free_handle;
    }
    
    /* initialize the handle attributes */
    if(handle_attrs == NULL)
    {
        result = globus_gsi_proxy_handle_attrs_init(&handle_i->attrs);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
            goto free_handle;
        }
    }
    else
    {
        result = globus_gsi_proxy_handle_attrs_copy(handle_attrs, 
                                                    &handle_i->attrs);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
            goto free_handle;
        }
    }

    handle_i->type = GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY;

    handle_i->extensions = NULL;
    
    goto exit;

 free_handle:

    if(handle_i)
    {
        globus_gsi_proxy_handle_destroy(handle_i);
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_init() */

/**
 * Destroy a GSI Proxy handle.
 *
 * @param handle
 *        The handle to be destroyed.
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
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
        
        if (handle->extensions != NULL)
        {
            sk_X509_EXTENSION_free(handle->extensions);
        }
        
        /* free the handle struct memory */
        globus_libc_free(handle);
        handle = NULL;
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_handle_destroy */
/*@}*/


/**
 * @name Get/Set Request
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Get the certificate request from a GSI Proxy handle.
 *
 * @param handle
 *        The handle from which to get the certificate request
 * @param req
 *        Parameter used to return the request. It is the users responsibility
 *        to free the returned request.
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 *
 * @see globus_gsi_proxy_handle_set_req()
 */
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
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }

    if(!req)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            (_PCSL("Invalid req pointer passed to function")));
        goto exit;
    }

    *req = X509_REQ_dup(handle->req);

    if(!(*req))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            (_PCSL("X509_REQ could not be copied")));
        goto exit;
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_get_req */

/**
 * Set the certificate request in a GSI Proxy handle.
 *
 * @param handle
 *        The handle for which to set the certificate request
 * @param req
 *        Request to be copied to handle.
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 *
 * @see globus_gsi_proxy_handle_get_req()
 */
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
            (_PCSL("Invalid handle (NULL) passed to function")));
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
                (_PCSL("Couldn't copy X509_REQ")));
            goto exit;
        }
    }
    
 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_set_req */
/*@}*/


/**
 * @name Get/Set Private Key
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Get the private key from a GSI Proxy handle.
 *
 * @param handle
 *        The handle from which to get the private key
 * @param proxy_key
 *        Parameter used to return the key. It is the users responsibility to
 *        free the returned key.
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 *
 * @see globus_gsi_proxy_handle_set_private_key()
 */
globus_result_t
globus_gsi_proxy_handle_get_private_key(
    globus_gsi_proxy_handle_t           handle,
    EVP_PKEY **                         proxy_key)
{
    int                                 length;
    unsigned char *                     der_encoded = NULL;
    unsigned char *                     tmp;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_private_key";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }
    
    if(!proxy_key)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            (_PCSL("Invalid proxy_key (NULL) passed to function")));
        goto exit;
    }

    if(!handle->proxy_key)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            (_PCSL("handle's proxy key hasn't been initialized")));
        goto exit;
    }

    *proxy_key = NULL;

    length = i2d_PrivateKey(handle->proxy_key, NULL);

    if(length < 0)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            (_PCSL("Couldn't convert private key from internal"
             "to DER encoded form")));
        goto exit;
        
    }
    
    der_encoded = malloc(length);

    if(!der_encoded)
    {
        GLOBUS_GSI_PROXY_HANDLE_MALLOC_ERROR(length);
        goto exit;
    }

    tmp = der_encoded;

    length = i2d_PrivateKey(handle->proxy_key, &tmp);

    if(length < 0)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            (_PCSL("Couldn't convert private key from internal"
             "to DER encoded form")));
        goto exit;
        
    }

    tmp = der_encoded;
    
    if(!d2i_PrivateKey(handle->proxy_key->type, proxy_key, 
                       &tmp, length))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            (_PCSL("Error converting DER encoded private key to internal form")));
        goto exit;
    }
    
 exit:

    if(der_encoded)
    {
        free(der_encoded);
    }
    
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_get_private_key */

/**
 * Set the private key in a GSI Proxy handle.
 *
 * @param handle
 *        The handle for which to set the private key
 * @param proxy_key
 *        Parameter used to pass the key
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 *
 * @see globus_gsi_proxy_handle_get_private_key()
 */
globus_result_t
globus_gsi_proxy_handle_set_private_key(
    globus_gsi_proxy_handle_t           handle,
    EVP_PKEY *                          proxy_key)
{
    int                                 length;
    unsigned char *                     der_encoded = NULL;
    unsigned char *                     tmp;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ = 
        "globus_gsi_proxy_handle_set_private_key";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }

    if(handle->proxy_key)
    {
        EVP_PKEY_free(handle->proxy_key);
        handle->proxy_key = NULL;
    }
    
    if(proxy_key)
    {

        length = i2d_PrivateKey(proxy_key, NULL);
        
        if(length < 0)
        {
            GLOBUS_GSI_PROXY_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
                (_PCSL("Couldn't convert private key from internal"
                 "to DER encoded form")));
            goto exit;
            
        }
        
        der_encoded = malloc(length);
        
        if(!der_encoded)
        {
            GLOBUS_GSI_PROXY_HANDLE_MALLOC_ERROR(length);
            goto exit;
        }
        
        tmp = der_encoded;
        
        length = i2d_PrivateKey(handle->proxy_key, &tmp);
        
        if(length < 0)
        {
            GLOBUS_GSI_PROXY_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
                (_PCSL("Couldn't convert private key from internal"
                 "to DER encoded form")));
            goto exit;
            
        }

        tmp = der_encoded;
        
        if(!d2i_PrivateKey(proxy_key->type, &handle->proxy_key, 
                           &tmp, length))
        {
            GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
                (_PCSL("Error converting DER encoded private key to internal form")));
            goto exit;
        }
    }

 exit:

    if(der_encoded)
    {
        free(der_encoded);
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_set_private_key */
/*@}*/

/**
 * @name Get/Set Proxy Type
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Determine the type of proxy that will be generated when using this handle. 
 *
 * @param handle
 *        The handle from which to get the type
 * @param type
 *        Parameter used to return the type.
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 *
 * @see globus_gsi_proxy_handle_set_type()
 */
globus_result_t
globus_gsi_proxy_handle_get_type(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cert_utils_cert_type_t * type)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ = 
        "globus_gsi_proxy_handle_get_type";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }

    *type = handle->type;

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_get_type */

/**
 * Set the type of proxy that will be generated when using this handle. Note
 * that this will have no effect when generating a proxy from a proxy. In that
 * case the generated proxy will inherit the type of the parent.
 *
 * @param handle
 *        The handle for which to set the type
 * @param type
 *        Parameter used to pass the type.
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 *
 * @see globus_gsi_proxy_handle_set_type()
 */
globus_result_t
globus_gsi_proxy_handle_set_type(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cert_utils_cert_type_t   type)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ = 
        "globus_gsi_proxy_handle_set_type";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }

    handle->type = type;

    switch(type)
    {
      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY:
      case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_IMPERSONATION_PROXY:
        result = globus_gsi_proxy_handle_set_policy(
            handle, NULL, 0, OBJ_sn2nid(IMPERSONATION_PROXY_SN));
        break;

      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_INDEPENDENT_PROXY:
      case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_INDEPENDENT_PROXY:
        result = globus_gsi_proxy_handle_set_policy(
            handle, NULL, 0, OBJ_sn2nid(INDEPENDENT_PROXY_SN));
        break;

      case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY:
      case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY:
        result = globus_gsi_proxy_handle_set_policy(
            handle, NULL, 0, OBJ_sn2nid(LIMITED_PROXY_SN));
        break;
      default:
        break;
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_set_type */
/*@}*/

/**
 * @name Get/Set Policy
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Set the policy to be used in the GSI Proxy handle.
 *
 * This function sets the policy to be used in the proxy cert
 * info extension.
 *
 * @param handle
 *        The handle to be modified.
 * @param policy_data
 *        The policy data.
 * @param policy_length
 *        The length of the policy data
 * @param policy_language_NID
 *        The NID of the policy language.
 *
 * @return
 *        GLOBUS_SUCCESS if the handle and its associated fields are valid
 *        otherwise an error is returned
 *
 * @see globus_gsi_proxy_handle_get_policy()
 */
globus_result_t
globus_gsi_proxy_handle_set_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char *                     policy_data,
    int                                 policy_length,
    int                                 policy_language_NID)
{
    PROXYPOLICY *                       policy;
    ASN1_OBJECT *                       policy_object;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_policy";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
    
    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }
    
    policy = PROXYCERTINFO_get_policy(handle->proxy_cert_info);
    if(!policy)
    {
        policy = PROXYPOLICY_new();
    }

    policy_object = OBJ_nid2obj(policy_language_NID);
    if(!policy_object)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYPOLICY,
            (_PCSL("Invalid numeric ID: %d"), policy_language_NID));
        goto exit;
    }

    if(!PROXYPOLICY_set_policy_language(policy, policy_object))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYPOLICY,
            (_PCSL("PROXYPOLICY of proxy handle could not be initialized")));
        goto exit;
    }

    if(!PROXYPOLICY_set_policy(policy, policy_data, policy_length) &&
       policy_data)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYPOLICY,
            (_PCSL("PROXYPOLICY of proxy handle could not be initialized")));
        goto exit;
    }
       
    result = GLOBUS_SUCCESS;

 exit:
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_set_policy */

/**
 * Get the policy from the GSI Proxy handle.
 *
 * This function gets the policy that is being used in the 
 * proxy cert info extension.
 *
 * @param handle
 *        The handle to be interrogated.
 * @param policy_data
 *        The policy data.
 * @param policy_length
 *        The length of the returned policy
 * @param policy_NID
 *        The NID of the policy language.
 *
 * @return
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an error
 *        is returned
 *
 * @see globus_gsi_proxy_handle_set_policy()
 */
globus_result_t
globus_gsi_proxy_handle_get_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    policy_data,
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
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }

    *policy_data = PROXYPOLICY_get_policy(
        PROXYCERTINFO_get_policy(handle->proxy_cert_info),
        policy_length);
    
    *policy_NID = OBJ_obj2nid(PROXYPOLICY_get_policy_language(
        PROXYCERTINFO_get_policy(handle->proxy_cert_info)));
    
    result = GLOBUS_SUCCESS;

 exit:
    
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_get_policy */
/*@}*/

/**
 * @name Get/Set X509 Extensions
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Add an X509 extension to the GSI Proxy handle to be added to certificate
 *
 * This function adds a X509 extension to the proxy certificate.
 *
 * @param handle
 *        The handle for the proxy to which the extension should be added.
 * @param extension
 *        The extension to be added.
 *
 * @return
 *        GLOBUS_SUCCESS if the addition was successful, otherwise an
 *        error is returned.
 *
 * @see globus_gsi_proxy_hande_get_extensions()
 * @see globus_gsi_proxy_hande_set_extensions()
 */
globus_result_t
globus_gsi_proxy_handle_add_extension(
    globus_gsi_proxy_handle_t           handle,
    X509_EXTENSION *                    ext)
{
   globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_add_extension";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }

    if (ext == NULL)
    {
        /* Nothing to do */
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    if (handle->extensions == NULL)
    {
        handle->extensions = sk_X509_EXTENSION_new_null();

        if (handle->extensions == NULL)
        {
            GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
                (_PCSL("Failed to allocation new X509 Extension stack: %s"), _function_name_));
            goto exit;
        }
    }
    
    sk_X509_EXTENSION_push(handle->extensions,
                           X509_EXTENSION_dup(ext));
    result = GLOBUS_SUCCESS;

  exit:
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

/* globus_gsi_proxy_handle_add_extension */

/**
 * Set the X509 extensions from a GSI Proxy handle
 *
 * This function sets the X509 extensions for a proxy certificate.
 *
 * @param handle
 *        The handle for the proxy from which the extension should be set.
 * @param extensions
 *        The extensions to be set. Can be NULL to clear extensions.
 *
 * @return
 *        GLOBUS_SUCCESS if the addition was successful, otherwise an
 *        error is returned.
 *
 * @see globus_gsi_proxy_hande_add_extension()
 * @see globus_gsi_proxy_hande_get_extensions()
 */
globus_result_t
globus_gsi_proxy_handle_set_extensions(
    globus_gsi_proxy_handle_t           handle,
    STACK_OF(X509_EXTENSION)*           exts)
{
   globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_extensions";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }

    if (handle->extensions != NULL)
    {
        sk_X509_EXTENSION_free(handle->extensions);
    }
    
    if (exts == NULL)
    {
        handle->extensions = NULL;
    }
    else
    {
        handle->extensions = sk_X509_EXTENSION_dup(exts);
        
        if (handle->extensions == NULL)
        {
            GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
                (_PCSL("Failed to duplicate X509 Extension stack: %s"), _function_name_));
            goto exit;
        }
    }

    result = GLOBUS_SUCCESS;

  exit:
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

/* globus_gsi_proxy_handle_set_extensions */

/**
 * Get the X509 extensions from a GSI Proxy handle
 *
 * This function returns the X509 extensions from the proxy certificate.
 *
 * @param handle
 *        The handle for the proxy from which the extensions should be
 *        retrieved.
 * @param extensions
 *        The variable to hold the extensions. The caller is responsible
 *        for freeing the extensions with sk_X509_EXTENSION_free()
 *        when they are done with them.
 *
 * @return
 *        GLOBUS_SUCCESS if the retrieval was successful, otherwise an
 *        error is returned.
 *
 * @see globus_gsi_proxy_hande_add_extension()
 * @see globus_gsi_proxy_hande_set_extensions()
 */
globus_result_t
globus_gsi_proxy_handle_get_extensions(
    globus_gsi_proxy_handle_t           handle,
    STACK_OF(X509_EXTENSION)**          exts)
{
   globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_add_extension";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }
    
    if (handle->extensions == NULL)
    {
        *exts = sk_X509_EXTENSION_new_null();
    }
    else
    {
        *exts = sk_X509_EXTENSION_dup(handle->extensions);
    }
    
    if (handle->extensions == NULL)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("Failed to duplicate X509 Extension stack: %s"), _function_name_));
        goto exit;
    }

    result = GLOBUS_SUCCESS;

  exit:
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

/* globus_gsi_proxy_handle_get_extensions */
/*@}*/

/**
 * @name Get/Set Path Length
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Set the path length to be used in the GSI Proxy handle.
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
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }

    if(!PROXYCERTINFO_set_path_length(handle->proxy_cert_info, pathlen))
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PATHLENGTH,
            (_PCSL("Error setting the path length of the PROXYCERTINFO extension "
             "in the proxy handle")));
        goto exit;
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_set_pathlen */

/**
 * Get the path length from the GSI Proxy handle.
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
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
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
 * @name Get/Set Time Valid
 * @ingroup globus_gsi_proxy_handle
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
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_proxy_handle_get_time_valid(
    globus_gsi_proxy_handle_t           handle,
    int *                               time_valid)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_time_valid";
    
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }

    *time_valid = handle->time_valid;

 exit:        
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_get_time_valid */

/**
 * Set the validity time of the proxy
 *
 * @param handle
 *        The proxy handle to set the expiration date for
 * @param time_valid
 *        desired expiration date of the proxy
 * 
 * @result
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_handle_set_time_valid(
    globus_gsi_proxy_handle_t           handle,
    int                                 time_valid)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_time_valid";
    
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }

    handle->time_valid = time_valid;

 exit:
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_set_time_valid */
/*@}*/

/**
 * @name Clear Cert Info
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Clear the proxy cert info extension stored in the GSI Proxy handle.
 *
 * This function clears proxy cert info extension related setting in
 * the GSI Proxy handle.
 *
 * @param handle
 *        The handle for which to clear the proxy cert info extension.
 * @return
 *        GLOBUS_SUCCESS if the handle is valid, otherwise an
 *        error is returned
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
            (_PCSL("NULL handle passed to function: %s"), _function_name_));
        goto exit;
    }

    PROXYCERTINFO_free(handle->proxy_cert_info);
    handle->proxy_cert_info = PROXYCERTINFO_new();
    if(handle->proxy_cert_info == NULL)
    {
        GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            (_PCSL("PROXYCERTINFO could not be initialized")));
        goto exit;
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_clear_cert_info */
/*@}*/

/**
 * @name Get/Set Cert Info
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Get the proxy cert info extension stored in the GSI Proxy handle.
 *
 * This function retrieves the proxy cert info extension from the GSI Proxy
 * handle. 
 *
 * @param handle
 *        The handle from which to get the proxy cert info extension.
 * @param pci
 *        Contains the proxy cert info extension upon successful return. If the
 *        handle does not contain a pci extension, this parameter will be NULL
 *        upon return.
 * @return
 *        GLOBUS_SUCCESS upon success
 *        GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE if handle is invalid
 *        GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO if the pci
 *        pointer is invalid or if the get failed.
 */
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
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }

    if(!pci)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            (_PCSL("Invalid PROXYCERTINFO passed to function")));
        goto exit;
    }

    if(handle->proxy_cert_info)
    { 
        *pci = PROXYCERTINFO_dup(handle->proxy_cert_info);
        if(!*pci)
        {
            GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
                (_PCSL("Couldn't copy PROXYCERTINFO structure")));
            goto exit;
        }
    }
    else
    {
        *pci = NULL;
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_get_proxy_cert_info */

/**
 * Set the proxy cert info extension stored in the GSI Proxy handle.
 *
 * This function sets the proxy cert info extension in the GSI Proxy handle.
 *
 * @param handle
 *        The handle for which to set the proxy cert info extension.
 * @param pci
 *        The proxy cert info extension to set.
 * @return
 *        GLOBUS_SUCCESS upon success
 *        GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE if handle is invalid
 *        GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO if the pci
 *        pointer is invalid or if the set failed.
 */
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
            (_PCSL("Invalid handle (NULL) passed to function")));
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
                (_PCSL("Couldn't copy PROXYCERTINFO")));
            goto exit;
        }
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_set_proxy_cert_info */
/*@}*/

/**
 * @name Get Signing Algorithm
 * @ingroup globus_gsi_proxy_handle
 */
/* @{ */
/**
 * Get the signing algorithm used to sign the proxy cert request
 *
 * @param handle
 *        The proxy handle containing the type of signing algorithm used
 * @param signing_algorithm
 *        signing algorithm of the proxy handle
 * 
 * @result
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
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
        GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }
        
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Key Bits
 * @ingroup globus_gsi_proxy_handle
 */
/* @{ */
/**
 * Get the key bits used for the pub/private key pair of the proxy
 *
 * @param handle
 *        The proxy handle to get the key bits of
 * @param key_bits
 *        key bits of the proxy handle
 * 
 * @result
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
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
        GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }
        
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Init Prime
 * @ingroup globus_gsi_proxy_handle 
 */
/* @{ */
/**
 * Get the init prime of the proxy handle
 *
 * @param handle
 *        The handle to get the init prime used in generating the key pair
 * @param init_prime
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
        GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* @} */


/**
 * @name Get Clock Skew
 * @ingroup globus_gsi_proxy_handle  
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
        GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Callback for Creating Keys
 * @ingroup globus_gsi_proxy_handle 
 */
/* @{ */
/**
 * Get the callback for creating the public/private key pair
 *
 * @param handle
 *        The proxy handle to get the callback from
 * @param callback
 *        Parameter used for returning the callback
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
        GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE_ATTRS);
    }

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
} 
/* @} */        


/**
 * @name Get/Set Proxy Common Name
 * @ingroup globus_gsi_proxy_handle
 */
/*@{*/
/**
 * Get the proxy common name stored in the GSI Proxy handle.
 *
 * This function retrieves the proxy common name from the GSI Proxy
 * handle. The common name only impacts draft compliant proxies.
 *
 * @param handle
 *        The handle from which to get the proxy common name.
 * @param common_name
 *        Contains the proxy common name upon successful return. If the
 *        handle does not contain a common name, this parameter will be NULL
 *        upon return.
 * @return
 *        GLOBUS_SUCCESS upon success
 *        GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE if handle is invalid
 */
globus_result_t
globus_gsi_proxy_handle_get_common_name(
    globus_gsi_proxy_handle_t           handle,
    char **                             common_name)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_get_proxy_common_name";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
    
    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }

    if(!common_name)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_INVALID_PARAMETER,
            (_PCSL("Invalid common name passed to function")));
        goto exit;
    }

    if(handle->common_name)
    { 
        *common_name = strdup(handle->common_name);
        if(!*common_name)
        {
            result = GLOBUS_GSI_PROXY_HANDLE_MALLOC_ERROR(
                strlen(handle->common_name));
            goto exit;
        }
    }
    else
    {
        *common_name = NULL;
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_get_common_name */

/**
 * Set the proxy common name stored in the GSI Proxy handle.
 *
 * This function sets the proxy common name in the GSI Proxy handle. Note
 * that the common name is only used for draft compliant proxies.
 *
 * @param handle
 *        The handle for which to set the proxy common name.
 * @param common_name
 *        The proxy common name to set.
 * @return
 *        GLOBUS_SUCCESS upon success
 *        GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE if handle is invalid
 */
globus_result_t
globus_gsi_proxy_handle_set_common_name(
    globus_gsi_proxy_handle_t           handle,
    char *                              common_name)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_proxy_handle_set_common_name";
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(!handle)
    {
        GLOBUS_GSI_PROXY_ERROR_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }

    if(handle->common_name)
    {
        free(handle->common_name);
        handle->common_name = NULL;
    }
    
    if(common_name)
    {
        handle->common_name = strdup(common_name);
        if(!handle->common_name)
        {
            result = GLOBUS_GSI_PROXY_HANDLE_MALLOC_ERROR(
                strlen(handle->common_name));
            goto exit;
        }
    } 

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}
/* globus_gsi_proxy_handle_set_common_name */
/*@}*/


/**
 * @name Set/Check Proxy Is Limited
 * @ingroup globus_gsi_proxy_handle
 */
/* @{ */
/**
 * Set the limited proxy flag on the proxy handle
 *
 * @param handle
 *        the proxy handle
 * @param is_limited
 *        boolean value to set on the proxy handle
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
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
            (_PCSL("Invalid handle (NULL) passed to function")));
        goto exit;
    }

    if(is_limited == GLOBUS_TRUE)
    {
        if(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY(handle->type))
        {
            result = globus_gsi_proxy_handle_set_type(
                handle,
                GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY);
        }
        else
        {
            result = globus_gsi_proxy_handle_set_type(
                handle,
                GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY);
        }
    }
    else
    {
        if(GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY(handle->type))
        {
            result = globus_gsi_proxy_handle_set_type(
                handle,
                GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY);
        }
        else
        {
            result = globus_gsi_proxy_handle_set_type(
                handle,
                GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY);
        }        
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}


/**
 * Check to see if the proxy is a limited proxy 
 *
 * @param handle
 *        the proxy handle to check
 * @param is_limited
 *        boolean value to set depending on the type of proxy 
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_proxy_is_limited(
    globus_gsi_proxy_handle_t           handle,
    globus_bool_t *                     is_limited)
{    
    static char *                       _function_name_ =
        "globus_gsi_proxy_is_limited";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    *is_limited = GLOBUS_GSI_CERT_UTILS_IS_LIMITED_PROXY(handle->type);

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* @} */
