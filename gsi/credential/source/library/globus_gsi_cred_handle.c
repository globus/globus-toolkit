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
 * @file globus_gsi_cred_handle.c
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gsi_credential.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_callback.h"
#include "globus_gsi_callback_constants.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/err.h"
#include <math.h>

#define GLOBUS_GSI_CRED_HANDLE_MALLOC_ERROR(_LENGTH_) \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_CREDENTIAL_MODULE, \
        errno, \
        GLOBUS_GSI_CRED_ERROR_ERRNO, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        "Could not allocate enough memory: %d bytes", \
        _LENGTH_))

/**
 * @name Initializing and Destroying a Handle
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Initializes a credential handle to be used credential
 * handling functions.  Takes a set of handle attributes
 * that are immutable to the handle.  The handle attributes
 * are only pointed to by the handle, so the lifetime of the
 * attributes needs to be as long as that of the handle.
 *
 * @param handle
 *        The handle to be initialized
 * @param handle_attrs 
 *        The immutable attributes of the handle
 *
 * @return
 *        GLOBUS_SUCCESS or an error captured in a globus_result_t
 */
globus_result_t
globus_gsi_cred_handle_init(
    globus_gsi_cred_handle_t *          handle,
    globus_gsi_cred_handle_attrs_t      handle_attrs)
{
    globus_result_t                     result;
    static char *                       _function_name_ = 
        "globus_gsi_cred_handle_init";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER,
            (_GCRSL("NULL handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    *handle = (globus_gsi_cred_handle_t)
        malloc(sizeof(globus_i_gsi_cred_handle_t));

    if(*handle == NULL)
    {
        result = globus_error_put(
            globus_error_wrap_errno_error(
                GLOBUS_GSI_CREDENTIAL_MODULE,
                errno,
                GLOBUS_GSI_CRED_ERROR_ERRNO,
                __FILE__,
                _function_name_,
                __LINE__,
                _GCRSL("Error allocating space (malloc) for credential handle")));
        goto error_exit;
    }

    /* initialize everything to NULL */
    memset(*handle, (int) NULL, sizeof(globus_i_gsi_cred_handle_t));

    if(handle_attrs == NULL)
    {
        result = globus_gsi_cred_handle_attrs_init(&(*handle)->attrs);        
    }
    else
    {
        result = globus_gsi_cred_handle_attrs_copy(
            handle_attrs, 
            & (*handle)->attrs);    
    }

    if(result != GLOBUS_SUCCESS)
    {
        free(*handle);
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    (*handle)->goodtill = 0;

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* globus_gsi_cred_handle_init */

/**
 * Destroys the credential handle
 *
 * @param handle
 *        The credential handle to be destroyed
 * @return 
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_cred_handle_destroy(
    globus_gsi_cred_handle_t            handle)
{
    static char *                       _function_name_ =
        "globus_gsi_cred_handle_destroy";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle != NULL)
    {
        if(handle->cert != NULL)
        {
            X509_free(handle->cert);
        }
        if(handle->key != NULL)
        {
            EVP_PKEY_free(handle->key);
        }
        if(handle->cert_chain != NULL)
        {
            sk_X509_pop_free(handle->cert_chain, X509_free);
        }
        if(handle->attrs != NULL)
        {
            globus_gsi_cred_handle_attrs_destroy(handle->attrs);
        }

        globus_libc_free(handle);
    }
    
    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return GLOBUS_SUCCESS;
}
/* globus_gsi_cred_handle_destroy */
/* @} */

/**
 * @name Copying a Handle
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Copies a credential handle.
 *
 * @param source
 *        The handle to be copied
 * @param dest
 *        The destination of the copy
 *
 * @return
 *        GLOBUS_SUCCESS or an error captured in a globus_result_t
 */
globus_result_t
globus_gsi_cred_handle_copy(
    globus_gsi_cred_handle_t            source,
    globus_gsi_cred_handle_t *          dest)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_cred_handle_copy";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(!dest)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("Null parameter passed to function")));
        goto exit;
    }
    
    if(source->attrs)
    {
        result = globus_gsi_cred_handle_init(dest, source->attrs);
    }
    else
    {
        result = globus_gsi_cred_handle_init(dest, NULL);
    }

    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto exit;
    }

    if(source->cert)
    {
        (*dest)->cert = X509_dup(source->cert);
        if(!(*dest)->cert)
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED,
                (_GCRSL("Error copying X509 cert in handle")));
            goto exit;
        }
    }

    if(source->key)
    {
        BIO *                           pk_mem_bio;
        int                             len;

        pk_mem_bio = BIO_new(BIO_s_mem());
        len = i2d_PrivateKey_bio(pk_mem_bio, source->key);
        if(len <= 0)
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED,
                (_GCRSL("Error converting private key to DER encoded form.")));
            BIO_free(pk_mem_bio);
            goto exit;
        }

        (*dest)->key = d2i_PrivateKey_bio(pk_mem_bio, &(*dest)->key);
        BIO_free(pk_mem_bio);
    }

    if(source->cert_chain)
    {
        int                             chain_index = 0;
        (*dest)->cert_chain = sk_X509_new_null();
        for(chain_index = 0; 
            chain_index < sk_X509_num(source->cert_chain); 
            ++chain_index)
        {
            sk_X509_insert((*dest)->cert_chain, 
                           X509_dup(sk_X509_value(source->cert_chain,
                                                  chain_index)), 
                           chain_index);
        }
    }

    (*dest)->goodtill = source->goodtill;

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */
        
/**
 * @name Getting the Handle Attributes
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * This function retreives a copy of the credential handle attributes
 *
 * @param handle
 *        The credential handle to retrieve the attributes from
 * @param attrs
 *        Contains the credential attributes on return
 *
 * @return
 *        GLOBUS_SUCCESS or an error captured in a globus_result_t
 */
globus_result_t
globus_gsi_cred_get_handle_attrs(
    globus_gsi_cred_handle_t            handle,
    globus_gsi_cred_handle_attrs_t *    attrs)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_handle_attrs";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }

    if(attrs == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle attrs parameter passed to function: %s"),
             _function_name_));
        goto exit;
    }

    result = globus_gsi_cred_handle_attrs_copy(handle->attrs, attrs);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto exit;
    }

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Getting the Credential Expiration
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * This function retreives the expiration time of the credential contained
 * in the handle
 *
 * @param cred_handle
 *        The credential handle to retrieve the expiration time from
 * @param goodtill
 *        Contains the expiration time on return
 *
 * @return
 *        GLOBUS_SUCCESS or an error captured in a globus_result_t
 */
globus_result_t
globus_gsi_cred_get_goodtill(
    globus_gsi_cred_handle_t            cred_handle,
    time_t *                            goodtill)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_goodtill";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(cred_handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle parameter passed to function: %s"), 
             _function_name_));
        goto error_exit;
    }

    *goodtill = cred_handle->goodtill;

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* }@ */

/**
 * @name Getting the Credential Lifetime
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * This function retreives the lifetime of the credential contained
 * in a handle
 *
 * @param cred_handle
 *        The credential handle to retrieve the lifetime from
 * @param lifetime
 *        Contains the lifetime on return
 *
 * @return
 *        GLOBUS_SUCCESS or an error captured in a globus_result_t
 */
globus_result_t
globus_gsi_cred_get_lifetime(
    globus_gsi_cred_handle_t            cred_handle,
    time_t *                            lifetime)
{
    time_t                              time_now;
    ASN1_UTCTIME *                      asn1_time;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_lifetime";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(cred_handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL credential handle passed to function: %s"), 
             _function_name_));
        goto error_exit;
    }

    asn1_time = ASN1_UTCTIME_new();
    X509_gmtime_adj(asn1_time, 0);
    globus_gsi_cert_utils_make_time(asn1_time, &time_now);

    *lifetime = cred_handle->goodtill - time_now;
    ASN1_UTCTIME_free(asn1_time);

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* }@ */

/**
 * @name Getting the Credential Strength
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * This function retreives the key strength of the credential contained
 * in a handle
 *
 * @param cred_handle
 *        The credential handle to retrieve the strength from
 * @param key_bits
 *        Contains the number of bits in the key on return
 *
 * @return
 *        GLOBUS_SUCCESS or an error captured in a globus_result_t
 */
globus_result_t 
globus_gsi_cred_get_key_bits(
    globus_gsi_cred_handle_t            cred_handle,
    int *                               key_bits)
{
    EVP_PKEY *                          pkey;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_key_bits";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(cred_handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle parameter passed to function: %s"), 
             _function_name_));
        goto error_exit;
    }
    
    if(key_bits == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL key_bits parameter passed to function: %s"), 
             _function_name_));
        goto error_exit;
    }
    
    if(cred_handle->cert == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT,
            (_GCRSL("The credential's cert is NULL")));
        goto error_exit;
    }
    
    pkey = X509_get_pubkey(cred_handle->cert);
    if(pkey == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("The credential's public key is NULL")));
        goto error_exit;
    }
    *key_bits = EVP_PKEY_bits(pkey);
    EVP_PKEY_free(pkey);
    if (*key_bits <= 0)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("Couldn't get length of credential's public key")));
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}


/**
 * @name Setting and Getting the Certificate
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Set the Credential's Certificate.  The X509 cert
 * that is passed in should be a valid X509 certificate
 * object
 *
 * @param handle
 *        The credential handle to set the certificate on
 * @param cert
 *        The X509 cert to set in the cred handle.  The cert
 *        passed in can be NULL which will set the cert in
 *        the handle to NULL, freeing the current cert in the
 *        handle.
 * @return 
 *        GLOBUS_SUCCESS or an error object id if an error
 */
globus_result_t
globus_gsi_cred_set_cert(
    globus_gsi_cred_handle_t            handle,
    X509 *                              cert)
{
    globus_result_t                     result;
    static char *                       _function_name_ = 
        "globus_gsi_cred_set_cert";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL credential handle passed to function: %s"), 
             _function_name_));
        goto error_exit;
    }

    if(handle->cert != NULL)
    {
        X509_free(handle->cert);
        handle->cert = NULL;
    }

    if(cert != NULL && (handle->cert = X509_dup(cert)) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT,
            (_GCRSL("Could not make copy of X509 cert")));
        goto error_exit;
    }

    /* resetting goodtill */
    result = globus_i_gsi_cred_goodtill(handle, &handle->goodtill);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}

/**
 * Get the certificate of a credential 
 *
 * @param handle
 *        The credential handle to get the certificate from
 * @param cert
 *        The resulting X509 certificate, a duplicate of the
 *        certificate in the credential handle.  This variable
 *        should be freed when the user is finished with it using
 *        the function X509_free.
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object id
 *        is returned
 */
globus_result_t
globus_gsi_cred_get_cert(
    globus_gsi_cred_handle_t            handle,
    X509 **                             cert)
{
    globus_result_t                     result;
    static char *                       _function_name_ = 
        "globus_gsi_cred_get_cert";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(cert == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL X509 cert passed to function: %s"), _function_name_));
        goto error_exit;
    }

    *cert = X509_dup(handle->cert);

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Setting and Getting the Credential Key
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Set the private key of the credential handle
 *
 * @param handle
 *        The handle on which to set the key.
 * @param key 
 *        The private key to set the handle's key to.  This
 *        value can be NULL, in which case the current handle's
 *        key is freed.       
 */
globus_result_t
globus_gsi_cred_set_key(
    globus_gsi_cred_handle_t            handle,
    EVP_PKEY *                          key)
{
    int                                 len;
    globus_result_t                     result;
    BIO *                               inout_bio = NULL;

    static char *                       _function_name_ =
        "globus_gsi_cred_set_key";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(key == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL key parameter passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(handle->key != NULL)
    {
        EVP_PKEY_free(handle->key);
        handle->key = NULL;
    }

    inout_bio = BIO_new(BIO_s_mem());
    if(!inout_bio)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("Couldn't create memory BIO")));
    }

    len = i2d_PrivateKey_bio(inout_bio, key);
    if(len <= 0)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("Couldn't get length of DER encoding for private key")));
        goto error_exit;
    }

    handle->key = d2i_PrivateKey_bio(inout_bio, &handle->key);
    result = GLOBUS_SUCCESS;

 error_exit:

    if(inout_bio)
    {
        BIO_free(inout_bio);
    }

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}    

/**
 * Get the credential handle's private key
 *
 * @param handle
 *        The credential handle containing the private key to get
 * @param key
 *        The private key which after this function returns is set
 *        to a duplicate of the private key of the credential 
 *        handle.  This variable needs to be freed by the user when
 *        it is no longer used via the function EVP_PKEY_free. 
 *
 * @return
 *        GLOBUS_SUCCESS or an error object identifier
 */
globus_result_t
globus_gsi_cred_get_key(
    globus_gsi_cred_handle_t            handle,
    EVP_PKEY **                         key)
{
    globus_result_t                     result;
    int                                 len;
    BIO *                               pk_mem_bio = NULL;
    static char *                       _function_name_ = 
        "globus_gsi_cred_get_key";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(key == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL key parameter passed to function: %s"), _function_name_));
        goto error_exit;
    }

    pk_mem_bio = BIO_new(BIO_s_mem());
    len = i2d_PrivateKey_bio(pk_mem_bio, handle->key);
    if(len <= 0)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("Couldn't convert private key to DER encoded form")));
        goto error_exit;
    }

    *key = d2i_PrivateKey_bio(pk_mem_bio, key);
    BIO_free(pk_mem_bio);

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */
    
/**
 * @name Setting and Getting the Certificate Chain
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Set the certificate chain of the credential handle
 *
 * @param handle
 *        The handle containing the certificate chain field to set
 * @param cert_chain
 *        The certificate chain to set the handle's certificate chain
 *        to
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object id
 *        is returned
 */
globus_result_t
globus_gsi_cred_set_cert_chain(
    globus_gsi_cred_handle_t            handle,
    STACK_OF(X509) *                    cert_chain)
{
    int                                 i = 0;
    int                                 numcerts;
    X509 *                              tmp_cert  = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ = 
        "globus_gsi_cred_set_cert_chain";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(handle->cert_chain != NULL)
    {
        sk_X509_pop_free(handle->cert_chain, X509_free);
        handle->cert_chain = NULL;
    }

    if(!cert_chain)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            (_GCRSL("Null cert chain passed in to function")));
        goto error_exit;
    }

    numcerts = sk_X509_num(cert_chain);

    handle->cert_chain = sk_X509_new_null();

    if(!handle->cert_chain)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            (_GCRSL("Couldn't initialize credential's cert chain")));
        goto error_exit;
    }
    
    for(i = 0; i < numcerts; ++i)
    {
        if((tmp_cert = X509_dup(sk_X509_value(cert_chain, i))) == NULL)
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                (_GCRSL("Couldn't copy X509 cert from credential's cert chain")));
            goto error_exit;
        }
        sk_X509_insert(handle->cert_chain, tmp_cert, i);
    }

    /* resetting goodtill */
    result = globus_i_gsi_cred_goodtill(handle, &handle->goodtill);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}

/**
 * Get the certificate chain of the credential handle
 *
 * @param handle
 *        The credential handle containing the certificate
 *        chain to get
 * @param cert_chain
 *        The certificate chain to set as a duplicate of
 *        the cert chain in the credential handle.  This variable
 *        (or the variable it points to) needs to be freed when
 *        the user is finished with it using sk_X509_free.
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object
 *        id is returned
 */
globus_result_t
globus_gsi_cred_get_cert_chain(
    globus_gsi_cred_handle_t            handle,
    STACK_OF(X509) **                   cert_chain)
{
    globus_result_t                     result;
    int                                 i;
    X509 *                              tmp_cert;
    static char *                       _function_name_ = 
        "globus_gsi_cred_get_cert_chain";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(cert_chain == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cert chain parameter passed to function: %s"), 
             _function_name_));
        goto error_exit;
    }

    if(!handle->cert_chain)
    {
        *cert_chain = NULL;
    }
    else
    {
        *cert_chain = sk_X509_new_null();
        for(i = 0; i < sk_X509_num(handle->cert_chain); ++i)
        {
            if((tmp_cert = X509_dup(sk_X509_value(handle->cert_chain, i)))
               == NULL)
            {
                GLOBUS_GSI_CRED_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                    (_GCRSL("Error copying cert from cred's cert chain")));
                goto error_exit;
            }
            sk_X509_push(*cert_chain, tmp_cert);
        }
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Cred Cert X509 Subject Name object
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the credential handle's certificate subject name
 *
 * @param handle
 *        The credential handle containing the certificate
 *        to get the subject name of
 * @param subject_name
 *        The subject name as an X509_NAME object.  This should be freed
 *        using X509_NAME_free when the user is finished with it
 * @return 
 *        GLOBUS_SUCCESS if no error, a error object id otherwise
 */
globus_result_t globus_gsi_cred_get_X509_subject_name(
    globus_gsi_cred_handle_t            handle,
    X509_NAME **                        subject_name)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_subject_name";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(subject_name == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL subject name parameter passed to function: %s"), 
             _function_name_));
        goto error_exit;
    }

    if((*subject_name = 
        X509_NAME_dup(X509_get_subject_name(handle->cert))) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT,
            (_GCRSL("Couldn't get subject name of credential's cert")));
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get X509 Identity Name
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the identity's X509 subject name from the credential handle
 *
 * @param handle
 *        The credential handle containing the certificate to
 *        get the identity from
 * @param identity_name
 *        The identity certificate's X509 subject name
 *
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object
 *        identifier is returned
 */
globus_result_t globus_gsi_cred_get_X509_identity_name(
    globus_gsi_cred_handle_t            handle,
    X509_NAME **                        identity_name)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    X509_NAME *                         identity = NULL;
    STACK_OF(X509) *                    cert_chain = NULL;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_X509_identity_name";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;
    
    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(identity_name == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL identity name passed to function: %s"), _function_name_));
        goto error_exit;
    }
    
    identity = X509_NAME_dup(X509_get_subject_name(handle->cert));

    if(handle->cert_chain == NULL)
    {
        cert_chain = sk_X509_new_null();
    }
    else
    {
        cert_chain = sk_X509_dup(handle->cert_chain);
    }

    sk_X509_unshift(cert_chain, handle->cert);

    result = globus_gsi_cert_utils_get_base_name(identity, cert_chain);

    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    *identity_name = identity;
    identity = NULL;

 error_exit:

    if(identity)
    {
        X509_NAME_free(identity);
    }

    if(cert_chain)
    {
        sk_X509_free(cert_chain);
    }
    
    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Cred Cert Subject Name
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the credential handle's certificate subject name
 *
 * @param handle
 *        The credential handle containing the certificate
 *        to get the subject name of
 * @param subject_name
 *        The subject name as a string.  This should be freed
 *        using free() when the user is finished with it
 * @return 
 *        GLOBUS_SUCCESS if no error, a error object id otherwise
 */
globus_result_t globus_gsi_cred_get_subject_name(
    globus_gsi_cred_handle_t            handle,
    char **                             subject_name)
{
    X509_NAME *                         x509_subject = NULL;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_subject_name";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if((result = globus_gsi_cred_get_X509_subject_name(handle, &x509_subject))
       != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    /* ToDo: This logic needs fixing. The subject_name is passed up and is
             freed by the caller - but it must be freed with OPENSSL_free(), 
             not free() and the caller cant be expected to know that */
    if((*subject_name = X509_NAME_oneline(x509_subject, NULL, 0)) == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("Couldn't get subject name from X509_NAME "
             "struct of cred's cert")));
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    if(x509_subject)
    {
        X509_NAME_free(x509_subject);
    }

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Policies from Cert Chain 
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the Policies from the Cert Chain in the handle.  The policies
 * will be null-terminated as they are added to the handle.
 * If a policy for a cert in the chain doesn't exist, the string
 * in the stack will be set to the static string GLOBUS_NULL_POLICIES
 *
 * @param handle
 *        the handle to get the cert chain containing the policies
 * @param policies
 *        the stack of policies retrieved from the handle's cert chain
 * @return
 *        GLOBUS_SUCCESS or an error object if an error occurred
 */ 
globus_result_t
globus_gsi_cred_get_policies(
    globus_gsi_cred_handle_t            handle,
    STACK **                            policies)
{
    int                                 index;
    char *                              policy_string = NULL;
    char *                              final_policy_string = NULL;
    int                                 policy_string_length = 0;
    PROXYPOLICY *                       policy;
    PROXYCERTINFO *                     pci;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_policies";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto exit;
    }

    if((*policies = sk_new_null()) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("Couldn't create stack of strings for policies in cert chain")));
        goto exit;
    }

    if(handle->cert_chain == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            (_GCRSL("The credential's cert chain is NULL")));
        goto exit;
    }

    for(index = 0; index < sk_X509_num(handle->cert_chain); ++index)
    {

        if((result = globus_i_gsi_cred_get_proxycertinfo(
            sk_X509_value(handle->cert_chain, index),
            &pci))
           != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN);
            goto exit;
        }

        if(pci == NULL || 
           (policy = PROXYCERTINFO_get_policy(pci)) == NULL)
        {
            /* no proxycertinfo extension = so no policy for this cert */
            policy_string = GLOBUS_NULL_POLICY;
            policy_string_length = strlen(GLOBUS_NULL_POLICY);            
        }
        else
        {
            policy_string = PROXYPOLICY_get_policy(policy, 
                                                        &policy_string_length);
        }

        if((final_policy_string = malloc(policy_string_length + 1)) == NULL)
        {
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_CREDENTIAL_MODULE,
                    errno,
                    GLOBUS_GSI_CRED_ERROR_ERRNO,
                    __FILE__,
                    _function_name_,
                    __LINE__,
                    _GCRSL("Couldn't allocate space"
                    "for the policy string")));
            goto error_exit;
        }

        if(globus_libc_snprintf(final_policy_string,
                                (policy_string_length + 1),
                                "%s", policy_string) < 0)
        {
            GLOBUS_GSI_CRED_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                (_GCRSL("Couldn't create policy string "
                 "of cert in cred's cert chain")));
            goto error_exit;
        }

        if(sk_push(*policies, final_policy_string) == 0)
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED,
                (_GCRSL("Couldn't add policy string "
                 "to stack of cert chain's policies")));
            goto error_exit;
        }

        final_policy_string = NULL;    

        PROXYCERTINFO_free(pci);
        pci = NULL;
    }

    result = GLOBUS_SUCCESS;
    goto exit;

 error_exit:

    if(final_policy_string != NULL)
    {
        free(final_policy_string);
    }

    if(*policies != NULL)
    {
        sk_pop_free(*policies, free);
    }
    *policies = NULL;
    
 exit:
    
    if(pci != NULL)
    {
        PROXYCERTINFO_free(pci);
    }

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */


/**
 * @name Get Policy Languages from Cert Chain 
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the policy languages from the cert chain in the handle.
 *
 * @param handle
 *        the handle to get the cert chain containing the policies
 * @param policy_languages
 *        the stack of policies retrieved from the handle's cert chain
 * @return
 *        GLOBUS_SUCCESS or an error object if an error occurred
 */ 
globus_result_t
globus_gsi_cred_get_policy_languages(
    globus_gsi_cred_handle_t            handle,
    STACK_OF(ASN1_OBJECT) **            policy_languages)
{
    int                                 index = 0;
    ASN1_OBJECT *                       policy_language = NULL;
    PROXYPOLICY *                       policy;
    PROXYCERTINFO *                     pci;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_policy_languages";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto exit;
    }

    if((*policy_languages = sk_new_null()) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("Couldn't create stack of strings for policy languages")));
        goto exit;
    }

    if(handle->cert_chain == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("The handle's cert chain is NULL")));
        goto exit;
    }

    for(index = 0; index < sk_X509_num(handle->cert_chain); ++index)
    {

        if((result = globus_i_gsi_cred_get_proxycertinfo(
            sk_X509_value(handle->cert_chain, index),
            &pci))
           != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN);
            goto exit;
        }

        if(pci == NULL || 
           (policy = PROXYCERTINFO_get_policy(pci)) == NULL)
        {
            /* no proxycertinfo extension, so no policy 
             * language for this cert */
            policy_language = GLOBUS_NULL;
        }
        else
        {
            policy_language = PROXYPOLICY_get_policy_language(policy);
        }

        if(sk_ASN1_OBJECT_push(*policy_languages, 
                               OBJ_dup(policy_language)) == 0)
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                (_GCRSL("Error adding policy language string "
                 "to list of policy languages")));
            goto error_exit;
        }

        PROXYCERTINFO_free(pci);
        pci = NULL;
    }

    result = GLOBUS_SUCCESS;
    goto exit;

 error_exit:

    if(*policy_languages != NULL)
    {
        sk_ASN1_OBJECT_pop_free(*policy_languages, ASN1_OBJECT_free);
    }

    *policy_languages = NULL;
    
 exit:
    

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Issuer Name
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the issuer's subject name from the credential handle
 *
 * @param handle
 *        The credential handle containing the certificate to
 *        get the issuer of
 * @param issuer_name
 *        The issuer certificate's subject name
 *
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object
 *        identifier is returned
 */
globus_result_t globus_gsi_cred_get_issuer_name(
    globus_gsi_cred_handle_t            handle,
    char **                             issuer_name)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_issuer_name";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(issuer_name == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL issuer name passed to function: %s"), _function_name_));
        goto error_exit;
    }
    
    /* ToDo: This logic needs fixing. The issuer_name is passed up and is
             freed by the caller - but it must be freed with OPENSSL_free(), 
             not free() and the caller cant be expected to know that */
    if((*issuer_name = X509_NAME_oneline(
        X509_get_issuer_name(handle->cert), NULL, 0)) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT,
            (_GCRSL("Couldn't get subject name of credential's cert")));
        goto error_exit;
    }
    
    result = GLOBUS_SUCCESS;
    
 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get Identity Name
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the identity's subject name from the credential handle
 *
 * @param handle
 *        The credential handle containing the certificate to
 *        get the identity of
 * @param identity_name
 *        The identity certificate's subject name
 *
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object
 *        identifier is returned
 */
globus_result_t globus_gsi_cred_get_identity_name(
    globus_gsi_cred_handle_t            handle,
    char **                             identity_name)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    X509_NAME *                         identity = NULL;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_identity_name";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL cred handle passed to function: %s"), _function_name_));
        goto error_exit;
    }

    if(identity_name == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            (_GCRSL("NULL identity name passed to function: %s"), _function_name_));
        goto error_exit;
    }

    result = globus_gsi_cred_get_X509_identity_name(handle, &identity);
    
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    /* ToDo: This logic needs fixing. The identity_name is passed up and is
             freed by the caller - but it must be freed with OPENSSL_free(), 
             not free() and the caller cant be expected to know that */
    *identity_name = X509_NAME_oneline(identity, NULL, 0);

    if(*identity_name == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_NAME,
            (_GCRSL("Unable to convert X509_NAME to string")));
    }
    
 error_exit:

    if(identity)
    {
        X509_NAME_free(identity);
    }

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Credential validation functions
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * This function performs path valiadtion on the certificate chain contained in
 * the credential handle.
 *
 * @param cred_handle
 *        The credential handle containing the certificate chain to
 *        be validated
 * @param callback_data
 *        A initialized callback data structure
 *
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object
 *        identifier is returned
 */
globus_result_t
globus_gsi_cred_verify_cert_chain(
    globus_gsi_cred_handle_t            cred_handle,
    globus_gsi_callback_data_t          callback_data)
{
    X509 *                              cert = NULL;
    char *                              cert_dir = NULL;
    X509_STORE *                        cert_store = NULL;
    X509 *                              tmp_cert = NULL;
    X509_STORE_CTX *                    store_context = NULL;
    int                                 callback_data_index;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_cred_verify_cert_chain";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;
    
    cert_store = X509_STORE_new();
    X509_STORE_set_verify_cb_func(cert_store, 
                                  globus_gsi_callback_create_proxy_callback);
    X509_STORE_set_depth(cert_store, GLOBUS_GSI_CALLBACK_VERIFY_DEPTH);

    result = globus_gsi_callback_get_cert_dir(callback_data, &cert_dir);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
                GLOBUS_GSI_CRED_ERROR_WITH_CALLBACK_DATA);
        goto exit;
    }

    tmp_cert = cred_handle->cert;
    cert = tmp_cert;
    
    if (X509_STORE_load_locations(cert_store, NULL, cert_dir))
    {
        store_context = X509_STORE_CTX_new();
        X509_STORE_CTX_init(store_context, cert_store, cert,
                            cred_handle->cert_chain);
        X509_STORE_CTX_set_depth(store_context,
                                 GLOBUS_GSI_CALLBACK_VERIFY_DEPTH);

        /* override the check_issued with our version */
        store_context->check_issued = globus_gsi_callback_check_issued;

        globus_gsi_callback_get_X509_STORE_callback_data_index(
            &callback_data_index);

        X509_STORE_CTX_set_ex_data(
            store_context,
            callback_data_index, 
            (void *)callback_data);
                 
        if(!X509_verify_cert(store_context))
        {
            globus_result_t             callback_error;
            globus_result_t             local_result;

            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_VERIFYING_CRED,
                (_GCRSL("Failed to verify credential")));

            local_result = globus_gsi_callback_get_error(callback_data,
                                                         &callback_error);
            if(local_result != GLOBUS_SUCCESS)
            {
                GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                    local_result,
                    GLOBUS_GSI_CRED_ERROR_VERIFYING_CRED);
                goto exit;
            }
            else
            {
                local_result = callback_error;
            }
            
            result = globus_i_gsi_cred_error_join_chains_result(
                result,
                local_result);

            goto exit;
        }
    }
    
 exit:

    if(cert_store)
    {
        X509_STORE_free(cert_store);
    }

    if(store_context)
    {
        X509_STORE_CTX_free(store_context);
    }

    if(cert_dir)
    {
        free(cert_dir);
    }

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}

/**
 * This function ensures that the certificate and private key in the credential
 * handle match.
 *
 * @param handle
 *        The credential handle containing the certificate and key to
 *        be validated
 *
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object
 *        identifier is returned
 */
globus_result_t
globus_gsi_cred_verify(
    globus_gsi_cred_handle_t            handle)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    EVP_PKEY *                          issuer_pkey;
    X509 *                              issuer_cert;
    static char *                       _function_name_ =
        "globus_gsi_cred_verify_cert";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    issuer_cert = sk_X509_value(handle->cert_chain,0);

    if(issuer_cert == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            (_GCRSL("Error getting issuer certificate from cert chain")));
        goto error;
    }

    issuer_pkey = X509_get_pubkey(issuer_cert);

    if(issuer_pkey == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            (_GCRSL("Error getting public key from issuer certificate")));
        goto error;
    }
    
    if(!X509_verify(handle->cert,issuer_pkey))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_VERIFYING_CRED,
            (_GCRSL("Failed to verify credential")));
    }

    EVP_PKEY_free(issuer_pkey);

 error:
    
    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @name Good Till
 * @ingroup globus_gsi_cred_operations
 */
/* @{ */
/**
 * Get the amount of time this credential is good for (time at
 * which it expires.  Each of the certs in the cert chain as well
 * as the cert associated with the cred are checked.  Whichever
 * expires first defines the goodtill of the entire credential.
 *
 * @param cred_handle
 *        The credential handle to get the expiration date of
 * @param goodtill
 *        The resulting expiration date
 */
globus_result_t
globus_i_gsi_cred_goodtill(
    globus_gsi_cred_handle_t            cred_handle,
    time_t *                            goodtill)
{
    X509 *                              current_cert = NULL;
    int                                 cert_count  = 0;
    time_t                              tmp_goodtill;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_i_gsi_cred_goodtill";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    current_cert = cred_handle->cert;

    *goodtill = 0;
    tmp_goodtill = 0;

    if(cred_handle->cert_chain)
    {
        cert_count = sk_X509_num(cred_handle->cert_chain);
    }
        
    while(current_cert)
    {
        result = globus_gsi_cert_utils_make_time(
            X509_get_notAfter(current_cert), 
            &tmp_goodtill);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED);
            goto exit;
        }

        if (*goodtill == 0 || tmp_goodtill < *goodtill)
        {
            *goodtill = tmp_goodtill;
        }
        
        if(cred_handle->cert_chain && cert_count)
        {
            cert_count--;
            current_cert = sk_X509_value(
                cred_handle->cert_chain,
                cert_count);
        }
        else
        {
            current_cert = NULL;
        }
    }

 exit:
    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

#endif
