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
#include "globus_gsi_proxy.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <math.h>

/**
 * the numeric id of the proxycertinfo extension
 * defined in proxy_ssl code
 */
extern int pci_NID;

/**
 * Initialize Handle
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
 */
globus_result_t globus_gsi_cred_handle_init(
    globus_gsi_cred_handle_t *          handle,
    globus_gsi_cred_handle_attrs_t      handle_attrs)
{
    globus_result_t                     result;
    static char *                       _function_name_ = 
        "globus_gsi_cred_handle_init";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL handle passed to function: %s", _function_name_));
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
                "Error allocating space (malloc) for credential handle"));
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
        result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    result = globus_i_gsi_cred_goodtill(*handle, &(*handle)->goodtill);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* globus_gsi_cred_handle_init */
/* @} */

globus_result_t globus_gsi_cred_get_goodtill(
    globus_gsi_cred_handle_t            cred_handle,
    time_t *                            goodtill)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_goodtill";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(cred_handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle parameter passed to function: %s", 
             _function_name_));
        goto error_exit;
    }

    *goodtill = cred_handle->goodtill;

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */


globus_result_t globus_gsi_cred_get_lifetime(
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
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL credential handle passed to function: %s", 
             _function_name_));
        goto error_exit;
    }

    asn1_time = ASN1_UTCTIME_new();
    X509_gmtime_adj(asn1_time,0);
    globus_i_gsi_cred_make_time(asn1_time, &time_now);

   *lifetime = cred_handle->goodtill - time_now;
    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * Destroy Credential Handle
 * @ingroup globus_gsi_cred_handle_attrs
 */
/* @{ */
/**
 * Destroys the credential handle
 *
 * @param handle
 *        The credential handle to be destroyed
 * @return 
 *        GLOBUS_SUCCESS
 */
globus_result_t globus_gsi_cred_handle_destroy(
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

        globus_free(handle);
    }
    
    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return GLOBUS_SUCCESS;
}
/* globus_gsi_cred_handle_destroy */
/* @} */

/**
 * Set Cert
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Set the Credential's Certificate.  The X509 cert
 * that is passed in should be a valid X509 certificate
 * object
 *
 * @param handle
 *        The credential containing the certificate to be set
 * @param cert
 *        The X509 cert to set in the cred handle.  The cert
 *        passed in can be NULL, and will set the cert in
 *        the handle to NULL, freeing the current cert in the
 *        handle.
 * @return 
 *        GLOBUS_SUCCESS or an error object id if an error
 */
globus_result_t globus_gsi_cred_set_cert(
    globus_gsi_cred_handle_t            handle,
    X509 *                              cert)
{
    globus_result_t                     result;
    static char *                       _function_name_ = 
        "globus_gsi_cred_set_cert";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL credential handle passed to function: %s", 
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
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT,
            ("Could not make copy of X509 cert"));
        goto error_exit;
    }

    /* resetting goodtill */
    result = globus_i_gsi_cred_goodtill(handle, &handle->goodtill);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * Set Cred Key
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Set the private key of the credential handle
 *
 * @param handle
 *        The handle containing the key to be set
 * @param key 
 *        The private key to set the handle's key to.  This
 *        value can be NULL, in which case the current handle's
 *        key is freed.       
 */
globus_result_t globus_gsi_cred_set_key(
    globus_gsi_cred_handle_t            handle,
    EVP_PKEY *                          key)
{
    unsigned char *                     der_encoded;
    int                                 len;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_cred_set_key";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto error_exit;
    }

    if(key == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL key parameter passed to function: %s", _function_name_));
        goto error_exit;
    }

    if(handle->key != NULL)
    {
        EVP_PKEY_free(handle->key);
        handle->key = NULL;
    }

    len = i2d_PrivateKey(handle->key, &der_encoded);

    if(!d2i_PrivateKey(handle->key->type, 
                       &key, 
                       &der_encoded, len))
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_PRIVATE_KEY,
            ("Error converting DER encoded private key to internal form"));
        goto error_exit;
    }

    globus_free(der_encoded);

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}    
/* @} */
/**
 * Set Cert Chain
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Set the certificate chain of the credential
 *
 * @param handle
 *        The handle containing the certificate chain to set
 * @param cert_chain
 *        The certificate chain to set the handle's certificate chain
 *        to
 * @return
 *        GLOBUS_SUCCESS if no error, otherwise an error object id
 *        is returned
 */
globus_result_t globus_gsi_cred_set_cert_chain(
    globus_gsi_cred_handle_t            handle,
    STACK_OF(X509) *                    cert_chain)
{
    int                                 i;
    int                                 numcerts;
    X509 *                              tmp_cert  = NULL;
    X509 *                              prev_cert = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ = 
        "globus_gsi_cred_set_cert_chain";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto error_exit;
    }

    if(handle->cert_chain != NULL)
    {
        sk_X509_pop_free(handle->cert_chain, X509_free);
        handle->cert_chain = NULL;
    }

    if(cert_chain != NULL && 
       (handle->cert_chain = sk_X509_dup(cert_chain)) == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            ("Couldn't copy cert chain to cred handle"));
        goto error_exit;
    }

    numcerts = sk_X509_num(cert_chain);

    if(handle->cert != NULL)
    {
        prev_cert = handle->cert;
        tmp_cert  = sk_X509_value(cert_chain, 0);
        i = 1;
    }
    else
    {
        if(numcerts > 1)
        {
            prev_cert = sk_X509_value(cert_chain, 0);
            tmp_cert = sk_X509_value(cert_chain, 1);
        }
        i = 2;
    }

    if(numcerts > 1)
    {
        do
        {
            if(prev_cert != NULL)
            {
                if(!X509_verify(prev_cert, X509_get_pubkey(tmp_cert)))
                {
                    result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                        GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                        ("Error verifying X509 cert in cert chain"));
                    goto error_exit;
                }
            }
            
            prev_cert = tmp_cert;
            tmp_cert = sk_X509_value(cert_chain, i); 
        } while(++i < numcerts);
    }

    for(i = 0; i < sk_X509_num(cert_chain); ++i)
    {
        if((tmp_cert = X509_dup(sk_X509_value(cert_chain, i))) == NULL)
        {
            result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                ("Couldn't copy X509 cert from credential's cert chain"));
            goto error_exit;
        }
        sk_X509_push(handle->cert_chain, tmp_cert);
    }

    /* resetting goodtill */
    result = globus_i_gsi_cred_goodtill(handle, &handle->goodtill);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Get Cred Cert
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
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
globus_result_t globus_gsi_cred_get_cert(
    globus_gsi_cred_handle_t            handle,
    X509 **                             cert)
{
    globus_result_t                     result;
    static char *                       _function_name_ = 
        "globus_gsi_cred_get_cert";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto error_exit;
    }

    if(cert == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL X509 cert passed to function: %s", _function_name_));
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
 * Get Cred Key
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
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
globus_result_t globus_gsi_cred_get_key(
    globus_gsi_cred_handle_t            handle,
    EVP_PKEY **                         key)
{
    int                                 len;
    unsigned char *                     der_encoded;
    globus_result_t                     result;

    static char *                       _function_name_ = 
        "globus_gsi_cred_get_key";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto error_exit;
    }

    if(key == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL key parameter passed to function: %s", _function_name_));
        goto error_exit;
    }

    len = i2d_PrivateKey(handle->key, & der_encoded);

    if(!d2i_PrivateKey(handle->key->type, 
                       key, 
                       & der_encoded, len))
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_PRIVATE_KEY,
            ("Error converting DER encoded private key to internal form"));
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* @} */
    
/**
 * Get Cert Chain
 * @ingroup globus_gsi_cert_handle
 */
/* @{ */
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
globus_result_t globus_gsi_cred_get_cert_chain(
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
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto error_exit;
    }

    if(cert_chain == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cert chain parameter passed to function: %s", 
             _function_name_));
        goto error_exit;
    }

    *cert_chain = sk_X509_dup(handle->cert_chain);
    for(i = 0; i < sk_X509_num(handle->cert_chain); ++i)
    {
        if((tmp_cert = X509_dup(sk_X509_value(handle->cert_chain, i)))
           == NULL)
        {
            result = GLOBUS_GSI_CRED_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                ("Error copying cert from cred's cert chain"));
            goto error_exit;
        }
        sk_X509_push(*cert_chain, tmp_cert);
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * Get SSL Context
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the ssl context structure SSL_CTX from the
 * credential handle
 *
 * @param handle
 *        The credential handle containing the ssl context to get
 * @param ssl_ctx
 *        The resulting ssl context
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case 
 *        a globus error object identifier is returned
 */
globus_result_t
globus_gsi_cred_get_ssl_context(
    globus_gsi_cred_handle_t            handle,
    SSL_CTX **                          ssl_ctx)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_ssl_context";
    
    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL || ssl_ctx == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto exit;
    }

    *ssl_ctx = handle->ssl_context;

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */


/**
 * Set SSL Context
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Set the SSL Context structure in the credential handle
 * 
 * @param handle
 *        The handle containing the SSL Context to set
 * @param ssl_ctx
 *        The SSL Context to set the handle's context to
 * @return
 *        GLOBUS_SUCCESS or a globus error object identifier
 */
globus_result_t
globus_gsi_cred_set_ssl_context(
    globus_gsi_cred_handle_t            handle,
    SSL_CTX *                           ssl_ctx)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_set_ssl_context";
    
    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto exit;
    }

    handle->ssl_context = ssl_ctx;

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/**
 * Get Cred Cert X509 Subject Name object
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
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto error_exit;
    }

    if(subject_name == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL subject name parameter passed to function: %s", 
             _function_name_));
        goto error_exit;
    }

    if((*subject_name = 
        X509_get_subject_name(handle->cert)) == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT,
            ("Couldn't get subject name of credential's cert"));
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */
    
/**
 * Get Cred Cert Subject Name
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
    X509_NAME *                         x509_subject;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_subject_name";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if((result = globus_gsi_cred_get_X509_subject_name(handle, &x509_subject))
       != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED);
        goto error_exit;
    }

    if((*subject_name = X509_NAME_oneline(x509_subject, NULL, 0)) == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("Couldn't get subject name from X509_NAME "
             "struct of cred's cert"));
        goto error_exit;
    }

    result = GLOBUS_SUCCESS;

 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * Get Group Name
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the group names of each cert in the cert chain of the handle.
 * If the cert doesn't have the PROXYCERTINFO extension, or if the 
 * extension doesn't have the optional PROXYGROUP, the string for
 * that cert will be set to the static string GLOBUS_NULL_GROUP
 *
 * @param handle 
 *        the handle containing the cert chain to get the group names of
 * @param sub_groups
 *        the strings of cert's group
 * @param sub_group_types
 *        the types of the groups in the cert's
 *
 * @return 
 *        GLOBUS_SUCCESS or an erro object identifier
 */
globus_result_t globus_gsi_cred_get_group_names(
    globus_gsi_cred_handle_t            handle,
    STACK **                            sub_groups,
    ASN1_BIT_STRING **                  sub_group_types)
{
    char *                              group_name = NULL;
    char *                              final_group_name = NULL;
    long                                group_name_length = 0;
    int                                 attached = 0;
    char *                              data_string = NULL;
    int                                 data_string_length = 0;
    int                                 index = 0;
    PROXYCERTINFO *                     pci = NULL;
    PROXYGROUP *                        pgroup = NULL;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_group_names";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;
    
    if(handle == NULL || handle->cert_chain == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL handle or cert chain passed to function: %s", 
             _function_name_));
        goto exit;
    }

    if((*sub_groups = sk_new_null()) == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            ("Couldn't create new openssl stack for "
             "group names of cert chain"));
        goto exit;
    }

    if((*sub_group_types = ASN1_BIT_STRING_new()) == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            ("Couldn't create new bit string for group types in cert chain"));
        goto error_exit;
    }

    data_string_length = 
        (int) ceil(((float)sk_X509_num(handle->cert_chain)) / 8);
    if((data_string = malloc(data_string_length)) == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_CREDENTIAL_MODULE,
                    errno,
                    GLOBUS_GSI_CRED_ERROR_ERRNO,
                    "Couldn't allocate space for data string")),
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN);
        goto exit;
    }
            
    memset(data_string, 0, data_string_length);

    if(!ASN1_BIT_STRING_set(*sub_group_types, data_string, data_string_length))
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            ("Couldn't intialize group types bit string"));
        goto error_exit;
    }

    free(data_string);
    data_string = NULL;

    if((result = globus_i_gsi_cred_get_proxycertinfo(
        handle->cert,
        &pci))
       != GLOBUS_SUCCESS)
    {
        result= GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT);
        goto error_exit;
    }

    /* The first group name (at index 0 of the stack)
     * will be from the certificate in this
     * credential, and the following group names in the stack will
     * be 
     */
    
    index = sk_X509_num(handle->cert_chain) - 1;
    do
    {
        if(pci == NULL || (pgroup = PROXYCERTINFO_get_group(pci)) == NULL)
        {
            /* no proxycertinfo extension - so no group name for this cert */
            group_name = GLOBUS_NULL_GROUP;
            group_name_length = strlen(GLOBUS_NULL_GROUP);
            attached = 0;
        }
        else
        {
            group_name = PROXYGROUP_get_name(pgroup, &group_name_length);
            attached   = *PROXYGROUP_get_attached(pgroup);
        }

        if((final_group_name = malloc(group_name_length + 1)) == NULL)
        {
            result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                globus_error_put(
                    globus_error_wrap_errno_error(
                        GLOBUS_GSI_CREDENTIAL_MODULE,
                        errno,
                        GLOBUS_GSI_CRED_ERROR_ERRNO,
                        "Couldn't allocate space"
                        "for the group name")),
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN);
            goto error_exit;
        }

        /* adding null-terminator to group name */
        if(snprintf(final_group_name, (group_name_length + 1),
                    "%s", group_name) < 0)
        {
            result = GLOBUS_GSI_CRED_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                ("Couldn't create group name string for cert"));
            goto error_exit;
        }

        if(sk_unshift(*sub_groups, final_group_name) == 0)
        {
            result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                ("Couldn't add group name string to stack of group names"));
            goto error_exit;
        }

        /* the push doesn't copy the group name, just makes
         * a reference to it - so it gets freed with sk_pop_free
         */
        final_group_name = NULL;

        if(!ASN1_BIT_STRING_set_bit(
            *sub_group_types, 
            index,
            attached))
        {
            result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                ("Couldn't add group type bit to bit string of group types"));
            goto error_exit;
        }

        PROXYCERTINFO_free(pci);

        if((result = globus_i_gsi_cred_get_proxycertinfo(
            sk_X509_value(handle->cert_chain, index), 
            &pci)) 
           != GLOBUS_SUCCESS)
        {
            result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN);
            goto error_exit;
        }

    } while(--index >= 0);
    
    result = GLOBUS_SUCCESS;
    goto exit;

 error_exit:

    if(final_group_name != NULL)
    {
        free(final_group_name);
    }
    if(*sub_groups != NULL)
    {
        sk_pop_free(*sub_groups, free);
    }
    *sub_groups = NULL;

    if(*sub_group_types != NULL)
    {
        ASN1_BIT_STRING_free(*sub_group_types);
    }
    *sub_group_types = NULL;

 exit:

    if(pci != NULL)
    {
        PROXYCERTINFO_free(pci);
    }

    if(data_string != NULL)
    {
        free(data_string);
    }

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * Get Policies of Cert Chain 
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the Policies of the Cert Chain in the handle.  The policies
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
    PROXYRESTRICTION *                  restriction;
    PROXYCERTINFO *                     pci;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_policies";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto exit;
    }

    if((*policies = sk_new_null()) == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("Couldn't create stack of strings for policies in cert chain"));
        goto exit;
    }

    if(handle->cert_chain == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
            ("The credential's cert chain is NULL"));
        goto exit;
    }

    for(index = 0; index < sk_X509_num(handle->cert_chain); ++index)
    {

        if((result = globus_i_gsi_cred_get_proxycertinfo(
            sk_X509_value(handle->cert_chain, index),
            &pci))
           != GLOBUS_SUCCESS)
        {
            result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN);
            goto exit;
        }

        if(pci == NULL || 
           (restriction = PROXYCERTINFO_get_restriction(pci)) == NULL)
        {
            /* no proxycertinfo extension = so no policy for this cert */
            policy_string = GLOBUS_NULL_POLICY;
            policy_string_length = strlen(GLOBUS_NULL_POLICY);            
        }
        else
        {
            policy_string = PROXYRESTRICTION_get_policy(restriction, 
                                                        &policy_string_length);
        }

        if((final_policy_string = malloc(policy_string_length + 1)) == NULL)
        {
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_GSI_CREDENTIAL_MODULE,
                    errno,
                    GLOBUS_GSI_CRED_ERROR_ERRNO,
                    "Couldn't allocate space"
                    "for the policy string"));
            goto error_exit;
        }

        if(snprintf(final_policy_string, (policy_string_length + 1),
                    "%s", policy_string) < 0)
        {
            result = GLOBUS_GSI_CRED_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                ("Couldn't create policy string "
                 "of cert in cred's cert chain"));
            goto error_exit;
        }

        if(sk_push(*policies, final_policy_string) == 0)
        {
            result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_CRED,
                ("Couldn't add policy string "
                 "to stack of cert chain's policies"));
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
 * Get Policy Languages of Cert Chain 
 * @ingroup globus_gsi_cred_handle
 */
/* @{ */
/**
 * Get the policy languages of the cert chain in the handle.
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
    PROXYRESTRICTION *                  restriction;
    PROXYCERTINFO *                     pci;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_get_policy_languages";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto exit;
    }

    if((*policy_languages = sk_new_null()) == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("Couldn't create stack of strings for policy languages"));
        goto exit;
    }

    if(handle->cert_chain == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("The handle's cert chain is NULL"));
        goto exit;
    }

    for(index = 0; index < sk_X509_num(handle->cert_chain); ++index)
    {

        if((result = globus_i_gsi_cred_get_proxycertinfo(
            sk_X509_value(handle->cert_chain, index),
            &pci))
           != GLOBUS_SUCCESS)
        {
            result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN);
            goto exit;
        }

        if(pci == NULL || 
           (restriction = PROXYCERTINFO_get_restriction(pci)) == NULL)
        {
            /* no proxycertinfo extension, so no policy 
             * language for this cert */
            policy_language = GLOBUS_NULL;
        }
        else
        {
            policy_language = PROXYRESTRICTION_get_policy_language(
                restriction);
        }

        if(sk_ASN1_OBJECT_push(*policy_languages, 
                               OBJ_dup(policy_language)) == 0)
        {
            result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT_CHAIN,
                ("Error adding policy language string "
                 "to list of policy languages"));
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
 * Get Issuer Name
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
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL cred handle passed to function: %s", _function_name_));
        goto error_exit;
    }

    if(issuer_name == NULL)
    {
        result = GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL issuer name passed to function: %s", _function_name_));
        goto error_exit;
    }
    
    if((*issuer_name = X509_NAME_oneline(
        X509_get_issuer_name(handle->cert), NULL, 0)) == NULL)
    {
        result = GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT,
            ("Couldn't get subject name of credential's cert"));
        goto error_exit;
    }
    
    result = GLOBUS_SUCCESS;
    
 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * Good Till
 * @ingroup globus_gsi_cred_operations
 */
/* @{ */
/**
 * Get the amount of time this credential is good for (time at
 * which it expires
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
        globus_i_gsi_cred_make_time(X509_get_notAfter(current_cert), 
                                    &tmp_goodtill);

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

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* @} */


globus_result_t
globus_i_gsi_cred_make_time(
    ASN1_UTCTIME *                      ctm,
    time_t *                            newtime)
{
    char *                              str;
    time_t                              offset;
    char                                buff1[24];
    char *                              p;
    int                                 i;
    struct tm                           tm;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_i_gsi_cred_mktime";

    p = buff1;
    i = ctm->length;
    str = (char *)ctm->data;
    if ((i < 11) || (i > 17))
    {
        *newtime = 0;
    }
    memcpy(p,str,10);
    p += 10;
    str += 10;

    if ((*str == 'Z') || (*str == '-') || (*str == '+'))
    {
        *(p++)='0'; *(p++)='0';
    }
    else
    {
        *(p++)= *(str++); *(p++)= *(str++);
    }
    *(p++)='Z';
    *(p++)='\0';

    if (*str == 'Z')
    {
        offset=0;
    }
    else
    {
        if ((*str != '+') && (str[5] != '-'))
        {
            *newtime = 0;
        }
        offset=((str[1]-'0')*10+(str[2]-'0'))*60;
        offset+=(str[3]-'0')*10+(str[4]-'0');
        if (*str == '-')
        {
            offset=-offset;
        }
    }

    tm.tm_isdst = 0;
    tm.tm_year = (buff1[0]-'0')*10+(buff1[1]-'0');

    if (tm.tm_year < 70)
    {
        tm.tm_year+=100;
    }
        
    tm.tm_mon   = (buff1[2]-'0')*10+(buff1[3]-'0')-1;
    tm.tm_mday  = (buff1[4]-'0')*10+(buff1[5]-'0');
    tm.tm_hour  = (buff1[6]-'0')*10+(buff1[7]-'0');
    tm.tm_min   = (buff1[8]-'0')*10+(buff1[9]-'0');
    tm.tm_sec   = (buff1[10]-'0')*10+(buff1[11]-'0');

    /*
     * mktime assumes local time, so subtract off
     * timezone, which is seconds off of GMT. first
     * we need to initialize it with tzset() however.
     */

    tzset();

#if defined(HAVE_TIME_T_TIMEZONE)
    *newtime = (mktime(&tm) + offset*60*60 - timezone);
#elif defined(HAVE_TIME_T__TIMEZONE)
    *newtime = (mktime(&tm) + offset*60*60 - _timezone);
#else
    *newtime = (mktime(&tm) + offset*60*60);
#endif

    result = GLOBUS_SUCCESS;
    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}

#endif
