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
 * @file globus_gsi_callback_data.c
 * Globus GSI Callback Data
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif


#include "globus_i_gsi_callback.h"
#include "globus_gsi_callback_constants.h"
#include "openssl/x509.h"

/**
 * @name Initializing and destroying a callback data structure
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function initializes a globus_gsi_callback_data_t.
 *
 * @param callback_data
 *        Reference to the structure to be initialized
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_data_init(
    globus_gsi_callback_data_t *        callback_data)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_data_init";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(callback_data == NULL)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL pointer to callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *callback_data = malloc(sizeof(globus_i_gsi_callback_data_t));
    if(*callback_data == NULL)
    {
        result = globus_error_put(
            globus_error_wrap_errno_error(
                GLOBUS_GSI_CALLBACK_MODULE,
                errno,
                GLOBUS_GSI_CALLBACK_ERROR_ERRNO,
                __FILE__,
                _function_name_,
                __LINE__,
                "Error allocating space (malloc) for callback data"));
        goto exit;
    }

    memset(*callback_data, (int) NULL, sizeof(globus_i_gsi_callback_data_t));

    (*callback_data)->max_proxy_depth = -1;
    
    (*callback_data)->cert_type = GLOBUS_GSI_CERT_UTILS_TYPE_EEC;

    (*callback_data)->cert_chain = sk_X509_new_null();

    (*callback_data)->error = GLOBUS_SUCCESS;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function destroys a globus_gsi_callback_data_t.
 *
 * @param callback_data
 *        The structure to be destroyed
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_data_destroy(
    globus_gsi_callback_data_t          callback_data)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_data_destroy";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        goto exit;
    }

    if(callback_data->cert_chain)
    { 
        sk_X509_pop_free(callback_data->cert_chain, X509_free); 
    } 
    
    if(callback_data->cert_dir)
    {
        globus_libc_free(callback_data->cert_dir);
    }

    /* extension_oids have to be free independantly */

    globus_object_free(globus_error_get(callback_data->error));

    globus_libc_free(callback_data);

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}   
/* @} */


/**
 * @name Copying a callback data structure
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function copies a globus_gsi_callback_data_t.
 *
 * @param source
 *        The structure to be copied
 * @param dest
 *        The destination of the copy
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_data_copy(
    globus_gsi_callback_data_t     source,
    globus_gsi_callback_data_t *   dest)
{
    int                                 index;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_callback_data_copy";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!source)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL callback data source parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!dest)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL callback data dest parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }        

    globus_gsi_callback_data_init(dest);

    (*dest)->cert_depth = source->cert_depth;
    (*dest)->proxy_depth = source->proxy_depth;
    (*dest)->cert_type = source->cert_type;
    (*dest)->cert_chain = sk_X509_new_null();

    for(index = 0; index < sk_X509_num(source->cert_chain); ++index)
    {
        if(!sk_X509_insert((*dest)->cert_chain,
                           X509_dup(sk_X509_value(source->cert_chain, index)),
                           index))
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_CERT_CHAIN,
                (_CLS("Couldn't copy cert chain from callback data")));
            goto exit;
        }
    }

    (*dest)->cert_dir = strdup(source->cert_dir);
    (*dest)->extension_cb = source->extension_cb;

    /* just copy the pointer location - these get created
     * and destroyed in gss code
     */
    (*dest)->extension_oids = source->extension_oids;

    (*dest)->error = source->error;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting and setting the certificate chain depth
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function returns the certificate chain depth
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to retrieve the depth from
 * @param cert_depth
 *        The returned certificate chain depth
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_cert_depth(
    globus_gsi_callback_data_t          callback_data,
    int *                               cert_depth)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_cert_depth";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!cert_depth)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter cert_depth passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *cert_depth = callback_data->cert_depth;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets the certificate chain depth
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to retrieve the depth from
 * @param cert_depth
 *        The certificate chain depth
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_set_cert_depth(
    globus_gsi_callback_data_t          callback_data,
    int                                 cert_depth)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_cert_depth";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    callback_data->cert_depth = cert_depth;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting and setting the "proxy chain" depth
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function returns the number of proxies in the certificate chain.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to retrieve the depth from
 * @param proxy_depth
 *        The returned "proxy chain" depth
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_proxy_depth(
    globus_gsi_callback_data_t          callback_data,
    int *                               proxy_depth)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_proxy_depth";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!proxy_depth)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter proxy_depth passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *proxy_depth = callback_data->proxy_depth;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets the number of proxies in the certificate chain.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to retrieve the depth from
 * @param proxy_depth
 *        The "proxy chain" depth
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_set_proxy_depth(
    globus_gsi_callback_data_t          callback_data,
    int                                 proxy_depth)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_proxy_depth";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    callback_data->proxy_depth = proxy_depth;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting and setting the certificate type
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function returns the certificate type of the certificate currently
 * being processed
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to retrieve the certificate type from
 * @param cert_type
 *        Variable containing the certificate type on return
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_cert_type(
    globus_gsi_callback_data_t          callback_data,
    globus_gsi_cert_utils_cert_type_t * cert_type)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_cert_type";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!cert_type)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter cert_type passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *cert_type = callback_data->cert_type;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets the certificate type of the certificate currently being
 * processed
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to set the certificate type on
 *
 * @param cert_type
 *        The certificate type
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_set_cert_type(
    globus_gsi_callback_data_t          callback_data,
    globus_gsi_cert_utils_cert_type_t   cert_type)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_cert_type";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    callback_data->cert_type = cert_type;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting and setting the certificate chain
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function returns the certificate chain associated with the callback
 * data.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to retreive the certificate chain
 *        from.
 * @param cert_chain
 *        Contains the certificate chain upon successful return
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_cert_chain(
    globus_gsi_callback_data_t          callback_data,
    STACK_OF(X509) **                   cert_chain)
{
    int                                 index;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_cert_chain";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!cert_chain)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter cert_chain passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *cert_chain = sk_X509_new_null();

    for(index = 0; index < sk_X509_num(callback_data->cert_chain); ++index)
    {
        if(!sk_X509_insert(
            *cert_chain,
            X509_dup(sk_X509_value(callback_data->cert_chain, index)),
            index))
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
                (_CLS("Couldn't copy cert chain in callback data")));
            goto exit;
        }
    }

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets the certificate chain associated with the callback
 * data.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to set the certificate chain
 *        on
 * @param cert_chain
 *        The certificate chain
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_set_cert_chain(
    globus_gsi_callback_data_t          callback_data,
    STACK_OF(X509) *                    cert_chain)
{
    int                                 index;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_cert_chain";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }
    
    if(callback_data->cert_chain) 
    { 
        sk_X509_pop_free(callback_data->cert_chain, X509_free); 
        callback_data->cert_chain = NULL; 
    } 

    callback_data->cert_chain = sk_X509_new_null();
    
    for(index = 0; index < sk_X509_num(cert_chain); ++index)
    {
        if(!sk_X509_insert(callback_data->cert_chain,
                           X509_dup(sk_X509_value(cert_chain, index)),
                           index))
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
                (_CLS("Couldn't set the cert chain in the callback_data")));
            goto exit;
        }
    }

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting and setting the limited proxy handling setting
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function gets the value of the limited proxy handling setting. This
 * setting determines whether path validation will accept limited proxies that
 * have been further delegated, ie certificate chains with a limited proxy
 * followed by further proxies. 
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to get the limited proxy setting
 *        from
 * @param multiple_limited_proxy_ok
 *        Contains the value of the setting upon successful return.
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 * @deprecated This function always returns true now. It will be removed
 *             in the next release.
 */
globus_result_t
globus_gsi_callback_get_multiple_limited_proxy_ok(
    globus_gsi_callback_data_t          callback_data,
    int *                               multiple_limited_proxy_ok)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_multiple_limited_proxy_ok";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!multiple_limited_proxy_ok)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter peer_cert_chain passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *multiple_limited_proxy_ok = GLOBUS_TRUE;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets the value of the limited proxy handling setting. This
 * setting determines whether path validation will accept limited proxies that
 * have been further delegated, ie certificate chains with a limited proxy
 * followed by further proxies. 
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to set the limited proxy setting
 *        on
 * @param multiple_limited_proxy_ok
 *        The value of the setting
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 * @deprecated This function has been turned into a no-op. It will be removed
 *             in the next release.
 */
globus_result_t
globus_gsi_callback_set_multiple_limited_proxy_ok(
    globus_gsi_callback_data_t          callback_data,
    int                                 multiple_limited_proxy_ok)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_multiple_limited_proxy_ok";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting and setting a set of X.509 extension OIDs.
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function gets a list of X.509 extension OIDs that may be used by the
 * extensions callback to allow or disallow certain extensions.   
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to get the array of extension OIDs
 *        from.
 * @param extension_oids
 *        Contains the list of extension OIDs upon successful return.
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_extension_oids(
    globus_gsi_callback_data_t          callback_data,
    void **                             extension_oids)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_extension_oids";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!extension_oids)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter extension_oids passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *extension_oids = callback_data->extension_oids;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets a list of X.509 extension OIDs that may be used by the
 * extensions callback to allow or disallow certain extensions.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to get the array of extension OIDs
 *        from.
 * @param extension_oids
 *        The list of extension OIDs
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_set_extension_oids(
    globus_gsi_callback_data_t          callback_data,
    void *                              extension_oids)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_extension_oids";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    callback_data->extension_oids = extension_oids;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting and setting the trusted certificate directory
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function gets the trusted certificate directory from the callback
 * data.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to get the trusted certificates
 *        directory from.
 * @param cert_dir
 *        Contains the path to the trusted certificate directory upon
 *        successful return. 
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_cert_dir(
    globus_gsi_callback_data_t          callback_data,
    char **                             cert_dir)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_cert_dir";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!cert_dir)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter cert_dir passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *cert_dir = strdup(callback_data->cert_dir);

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets the trusted certificate directory on the callback
 * data.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to set the trusted certificates
 *        directory on.
 * @param cert_dir
 *        The path to the trusted certificate directory
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_set_cert_dir(
    globus_gsi_callback_data_t          callback_data,
    char *                              cert_dir)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_cert_dir";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }


    if(callback_data->cert_dir != NULL)
    {
        free(callback_data->cert_dir);
    }
    
    callback_data->cert_dir = strdup(cert_dir);

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting and setting the callback to be called for unknown X.509 extensions
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function gets the callback that is called for unknown X.509 extensions
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to get the callback information from
 * @param extension_cb
 *        Contains the extension callback upon successful return. 
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_extension_cb(
    globus_gsi_callback_data_t          callback_data,
    globus_gsi_extension_callback_t *   extension_cb)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_goodtill";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(!extension_cb)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter extension_cb passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *extension_cb = callback_data->extension_cb;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets the callback that is called for unknown X.509 extensions
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to set the callback information on
 * @param extension_cb
 *        The extension callback
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_set_extension_cb(
    globus_gsi_callback_data_t          callback_data,
    globus_gsi_extension_callback_t     extension_cb)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_extension_cb";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    callback_data->extension_cb = extension_cb;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */


/**
 * @name Getting and setting the error status
 * @ingroup globus_gsi_callback_data
 */
/* @{ */
/**
 * This function gets the error status stored in the callback data.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to get the error from
 * @param error
 *        Contains the error upon successful return. 
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_error(
    globus_gsi_callback_data_t          callback_data,
    globus_result_t *                   error)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_error";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
 
    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    *error = callback_data->error;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/**
 * This function sets the error status stored in the callback data.
 *
 * @param callback_data
 *        The globus_gsi_callback_data_t to set the error on
 * @param error
 *        The error
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_set_error(
    globus_gsi_callback_data_t          callback_data,
    globus_result_t                     error)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_set_error";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(!callback_data)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_CALLBACK_DATA,
            (_CLS("NULL parameter callback_data passed to function: %s"),
             _function_name_));
        goto exit;
    }

    callback_data->error = error;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */
