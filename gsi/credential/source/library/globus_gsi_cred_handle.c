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
    static char *                       _function_name_ = 
        "globus_gsi_cred_handle_init";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    *handle = (globus_gsi_cred_handle_t)
        globus_malloc(sizeof(globus_i_gsi_cred_handle_t));

    if(*handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

    /* initialize everything to NULL */
    memset(*handle, (int) NULL, sizeof(globus_i_gsi_cred_handle_t));

    if(globus_gsi_cred_handle_attrs_copy(handle_attrs, & (*handle)->attrs)
       != GLOBUS_SUCCESS)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS);
    }

    return GLOBUS_SUCCESS;
}
/* globus_gsi_cred_handle_init */
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
    static char *                       _function_name_ = 
        "globus_gsi_cred_set_cert";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(handle->cert != NULL)
    {
        X509_free(handle->cert);
        handle->cert = NULL;
    }

    if(cert != NULL && (handle->cert = X509_dup(cert)) == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

    return GLOBUS_SUCCESS;
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

    static char *                       _function_name_ =
        "globus_gsi_cred_set_key";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(key == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
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
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_PRIVATE_KEY);
    }

    globus_free(der_encoded);

    return GLOBUS_SUCCESS;
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
    X509 *                              tmp_cert;
    static char *                       _function_name_ = 
        "globus_gsi_cred_set_cert_chain";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(handle->cert_chain != NULL)
    {
        sk_X509_pop_free(handle->cert_chain, X509_free);
        handle->cert_chain = NULL;
    }

    if(cert_chain != NULL && 
       (handle->cert_chain = sk_X509_dup(cert_chain)) == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_X509_CERT_CHAIN);
    }

    for(i = 0; i < sk_X509_num(cert_chain); ++i)
    {
        if((tmp_cert = X509_dup(sk_X509_value(cert_chain, i))) == NULL)
        {
            return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_X509_CERT_CHAIN);
        }
        sk_X509_push(handle->cert_chain, tmp_cert);
    }

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
    static char *                       _function_name_ = 
        "globus_gsi_cred_get_cert";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(cert == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
    }

    *cert = X509_dup(handle->cert);

    return GLOBUS_SUCCESS;
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

    static char *                       _function_name_ = 
        "globus_gsi_cred_get_key";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(key == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_PRIVATE_KEY);
    }

    len = i2d_PrivateKey(handle->key, & der_encoded);

    if(!d2i_PrivateKey(handle->key->type, 
                       key, 
                       & der_encoded, len))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_PRIVATE_KEY);
    }

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
    int                                 i;
    X509 *                              tmp_cert;
    static char *                       _function_name_ = 
        "globus_gsi_cred_get_cert_chain";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(cert_chain == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_X509_CERT_CHAIN);
    }

    *cert_chain = sk_X509_dup(handle->cert_chain);
    for(i = 0; i < sk_X509_num(handle->cert_chain); ++i)
    {
        if((tmp_cert = X509_dup(sk_X509_value(handle->cert_chain, i)))
           == NULL)
        {
            return GLOBUS_GSI_CRED_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_X509_CERT_CHAIN);
        }
        sk_X509_push(*cert_chain, tmp_cert);
    }

    return GLOBUS_SUCCESS;
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
 *        using globus_free when the user is finished with it
 * @return 
 *        GLOBUS_SUCCESS if no error, a error object id otherwise
 */
globus_result_t globus_gsi_cred_get_subject_name(
    globus_gsi_cred_handle_t            handle,
    char **                             subject_name)
{
    static char *                       _function_name_ =
        "globus_gsi_cred_get_subject_name";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(subject_name == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
    }

    if((*subject_name = X509_NAME_oneline(
        X509_get_subject_name(handle->cert), NULL, 0)) == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

    return GLOBUS_SUCCESS;
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
    static char *                       _function_name_ =
        "globus_gsi_cred_get_issuer_name";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(issuer_name == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
    }
    
    if((*issuer_name = X509_NAME_oneline(
        X509_get_issuer_name(handle->cert), NULL, 0)) == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

    return GLOBUS_SUCCESS;
}
/* @} */
