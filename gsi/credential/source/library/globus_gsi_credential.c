#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_credential.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gsi_credential.h"
#include "globus_gsi_cred_system_config.h"
#include "globus_gsi_cert_utils.h"
#include "globus_gsi_proxy.h"
#include "version.h"
#include <openssl/pem.h>
#include <openssl/x509.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

extern int pci_NID;

static int globus_l_gsi_credential_activate(void);
static int globus_l_gsi_credential_deactivate(void);

int globus_i_gsi_cred_debug_level = 0;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_credential_module =
{
    "globus_credential",
    globus_l_gsi_credential_activate,
    globus_l_gsi_credential_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_gsi_credential_activate(void)
{
    int                                 result;
    char *                              tmp_string;
    static char *                       _function_name_ =
        "globus_l_gsi_credential_activate";

    tmp_string = globus_module_getenv("GLOBUS_GSI_CRED_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_cred_debug_level = atoi(tmp_string);
        
        if(globus_i_gsi_cred_debug_level < 0)
        {
            globus_i_gsi_cred_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSI_CRED_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_cred_debug_fstream = fopen(tmp_string, "w");
        if(globus_i_gsi_cred_debug_fstream == NULL)
        {
            result = GLOBUS_NULL;
            goto exit;
        }
    }
    else
    {
        /* if the env. var. isn't set, use stderr */
        globus_i_gsi_cred_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    result = globus_module_activate(GLOBUS_GSI_PROXY_MODULE);
    OpenSSL_add_ssl_algorithms();

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_credential_deactivate(void)
{
    int                                 result;
    static char *                       _function_name_ =
        "globus_l_gsi_credential_deactivate";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    result = globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    fclose(globus_i_gsi_cred_debug_fstream);
    return result;
}
/* globus_l_gsi_credential_deactivate() */

#endif

/**
 * Read Credential
 * @ingroup globus_gsi_cred_operation
 */
/* @{ */
/**
 * Read a Credential from a filesystem location.  The credential
 * to read will be determined by the search order of the handle
 * attributes.  
 * NOTE:  This function always searches for the desired credential.
 *        If you don't want to perform a search, then don't use this
 *        function.  The search goes in the order of the handle
 *        attributes' search order.
 *
 * @param handle
 *        The credential handle to set.  This credential handle
 *        should already be initialized using globus_gsi_cred_handle_init.
 * @param desired_subject
 *        The subject to check for when reading in a credential.  The
 *        desired_subject will be a substring of the matching cert's
 *        subject, so if looking for a host cert, the desired subject 
 *        should just be the FQDN of that host.  If null, the credential read
 *        in is the first match based on the system configuration
 *        (paths and environment variables)
 * @param service_name
 *        The service name that defines the type of certificate to
 *        search for.  This variable sets the location to search
 *        for the cert to be read in.  If null, a service cert
 *        is not searched for
 * @return
 *        GLOBUS_SUCCESS if no errors occured, otherwise, an error object
 *        identifier is returned.
 *
 * @see globus_gsi_cred_read_proxy
 * @see globus_gsi_cred_read_cert_and_key
 */
globus_result_t globus_gsi_cred_read(
    globus_gsi_cred_handle_t            handle,
    char *                              desired_subject,
    char *                              service_name)
{
    int                                 index = 0;
    globus_result_t                     result;
    char *                              found_subject;
    char *                              cert;
    char *                              key;
    char *                              proxy;

    static char *                       _function_name_ =
        "globus_gsi_cred_read";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_CRED,
            ("Null handle passed to function: %s", _function_name_));
        goto exit;
    }

    /* search for the credential of choice */

    do
    {
        result = GLOBUS_SUCCESS;

        switch(handle->attrs->search_order[index])
        {
            case GLOBUS_PROXY:
                result = GLOBUS_GSI_CRED_GET_PROXY_FILENAME(
                             & proxy, 
                             GLOBUS_PROXY_FILE_INPUT);
                if(result != GLOBUS_SUCCESS)
                {
                    GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                        result,
                        GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED);
                    break;
                }
                
                result = globus_gsi_cred_read_proxy(handle, proxy);
                if(result != GLOBUS_SUCCESS)
                {
                    GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                        result,
                        GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED);
                    break;
                }
            
                result = globus_gsi_cred_get_subject_name(handle, 
                                                          &found_subject);
                if(result != GLOBUS_SUCCESS)
                {
                    GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                        result,
                        GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED);
                    break;
                }

                if(desired_subject == NULL ||
                   strstr(found_subject, desired_subject))
                {                
                    goto exit;
                }

                free(found_subject);
                found_subject = NULL;
                break;

            case GLOBUS_USER:
            case GLOBUS_HOST:

                result = GLOBUS_GSI_CRED_GET_HOST_CERT_FILENAME(&cert, &key);
                if(result != GLOBUS_SUCCESS)
                {
                    GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                        result,
                        GLOBUS_GSI_CRED_ERROR_READING_HOST_CRED);
                    break;
                }                    

                result = globus_gsi_cred_read_cert_and_key(handle, cert,
                                                           key, NULL);
                if(result != GLOBUS_SUCCESS)
                {
                    GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                        result,
                        GLOBUS_GSI_CRED_ERROR_READING_HOST_CRED);
                    break;
                }
            
                result = globus_gsi_cred_get_subject_name(handle, 
                                                          &found_subject);
                if(result != GLOBUS_SUCCESS)
                {
                    GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                        result,
                        GLOBUS_GSI_CRED_ERROR_READING_HOST_CRED);
                    break;
                }

                if(desired_subject == NULL ||
                   strstr(found_subject, desired_subject) != NULL)
                {
                    goto exit;
                }

                free(found_subject);
                found_subject = NULL;
                break;
            
            case GLOBUS_SERVICE:
            
                if(service_name)
                {
                    result = GLOBUS_GSI_CRED_GET_SERVICE_CERT_FILENAME(
                                 service_name, &cert, &key);
                    if(result != GLOBUS_SUCCESS)
                    {
                        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                                 result,
                                 GLOBUS_GSI_CRED_ERROR_READING_SERVICE_CRED);
                        break;
                    }                    

                    result = globus_gsi_cred_read_cert_and_key(handle, cert,
                                                               key, NULL);
                    if(result != GLOBUS_SUCCESS)
                    {
                        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                            result,
                            GLOBUS_GSI_CRED_ERROR_READING_SERVICE_CRED);
                        break;
                    }
            
                    result = globus_gsi_cred_get_subject_name(handle, 
                                                              &found_subject);
                    if(result != GLOBUS_SUCCESS)
                    {
                        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                            result,
                            GLOBUS_GSI_CRED_ERROR_READING_SERVICE_CRED);
                        break;
                    }

                    if(desired_subject == NULL || 
                       strstr(found_subject, desired_subject))
                    {
                        goto exit;
                    }
                    
                    free(found_subject);
                    found_subject = NULL;
                }
                break;
            
            case GLOBUS_SO_END:
                GLOBUS_GSI_CRED_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CRED_ERROR_READING_CRED,
                    ("Credentials could not be found in any of the"
                    " possible locations specified by the search order"));
                goto exit;
        }
    } while(++index);
    
 exit:
    if(found_subject)
    {
        globus_free(found_subject);
    }

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}
/* @} */

/**
 * Read Proxy
 * @ingroup globus_gsi_cred_operation
 */
/* @{ */
/**
 * Read a proxy from a PEM file.  Assumes that the handle
 * attributes contain the filename of the proxy to read
 *
 * @param handle
 *        The credential handle to set based on the proxy
 *        parameters read from the file
 * @return
 *        GLOBUS_SUCCESS or an error object identifier
 */
globus_result_t globus_gsi_cred_read_proxy(
    globus_gsi_cred_handle_t            handle,
    char *                              proxy_filename)
{
    X509 *                              tmp_cert = NULL;
    BIO *                               proxy_bio;
    globus_result_t                     result;
    
    static char *                       _function_name_ =
        "globus_gsi_cred_read_proxy";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    /* create the bio to read the proxy in from */

    if((proxy_bio = BIO_new_file(proxy_filename, "r")) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Can't open file: %s for reading", proxy_filename));
        goto exit;
    }

    /* read in the certificate of the handle */
    
    if(handle->cert != NULL)
    {
        X509_free(handle->cert);
    }
    
    if(!PEM_read_bio_X509(proxy_bio, & handle->cert, NULL, NULL))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Couldn't read X509 proxy cert from bio"));
        goto exit;
    }

    /* read in the private key of the handle */

    if(handle->key != NULL)
    {
        EVP_PKEY_free(handle->key);
    }

    if((handle->key = PEM_read_bio_PrivateKey(proxy_bio, NULL, NULL, NULL))
       == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Couldn't read proxy's private key from bio"));
        goto exit;
    }

    /* read in the certificate chain of the handle */

    if(handle->cert_chain != NULL)
    {
        sk_X509_pop_free(handle->cert_chain, X509_free);
    }

    if((handle->cert_chain = sk_X509_new_null()) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Can't initialize cert chain"));
        goto exit;
    }

    while(!BIO_eof(proxy_bio))
    {
        if(!PEM_read_bio_X509(proxy_bio, &tmp_cert, NULL, NULL))
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
                ("Couldn't read proxy's cert chain certificate from bio"));
            goto exit;
        }
        
        if(!sk_X509_push(handle->cert_chain, tmp_cert))
        {
            X509_free(tmp_cert);
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
                ("Error adding certificate to proxy's cert chain"));
            goto exit;
        }

        X509_free(tmp_cert);
    }

    BIO_free(proxy_bio);

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return GLOBUS_SUCCESS;
}
/* @} */

/**
 * Read Cert and Key
 * @ingroup globus_gsi_cred_operations
 */
/* @{ */
/**
 * Read a cert and key from a the file locations specified in the
 * handle attributes.  Cert and key should be in PEM format.
 *
 * @param handle
 *        the handle to set the values of
 *
 * @return
 *        GLOBUS_SUCCESS or an error object identifier
 */
globus_result_t globus_gsi_cred_read_cert_and_key(
    globus_gsi_cred_handle_t            handle,
    char *                              cert_filename,
    char *                              key_filename,
    int                                 (*pw_cb)())
{
    BIO *                               cert_bio = NULL;
    BIO *                               key_bio = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_cred_read_cert_and_key";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_CRED,
            ("NULL handle passed to function: %s", _function_name_));
       goto exit;
    }

    if(!(cert_bio = BIO_new_file(cert_filename, "r")))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_CRED,
            ("Can't open cert file: %s for reading", cert_filename));
        goto exit;
    }

    if(!(key_bio = BIO_new_file(key_filename, "r")))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_CRED,
            ("Can't open bio stream for "
             "key file: %s for reading", key_filename));
        goto exit;
    }
    
    /* read in the cert and key */
    
    if(handle->cert != NULL)
    {
        X509_free(handle->cert);
    }

    if(handle->key != NULL)
    {
        EVP_PKEY_free(handle->key);
    }

    if(!PEM_read_bio_X509(cert_bio, & handle->cert, NULL, NULL))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_CRED,
            ("Can't read credential cert from bio stream"));
        goto exit;
    }

    if(!PEM_read_bio_PrivateKey(key_bio, & handle->key, pw_cb, NULL))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_CRED,
            ("Can't read credential private key from bio stream"));
        goto exit;
    }

    BIO_free(cert_bio);
    BIO_free(key_bio);

    if(handle->cert_chain != NULL)
    {
        sk_X509_pop_free(handle->cert_chain, X509_free);
        handle->cert_chain = NULL;
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;

    return result;
}

/**
 * Read Credential
 * @ingroup globus_gsi_credential
 */
/* @{ */
/**
 * Read a Credential from a BIO stream and set the 
 * credential handle to represent the read credential.
 * The values read from the stream, in order, will be
 * the signed certificate, the private key, 
 * and the certificate chain
 *
 * @param handle
 *        The credential handle to set.  The credential
 *        should not be initialized (i.e. NULL).
 * @param bio
 *        The stream to read the credential from
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which
 *        case an error object is returned
 */
globus_result_t globus_gsi_cred_read_proxy_bio(
    globus_gsi_cred_handle_t *          handle,
    BIO *                               bio)
{
    globus_result_t                     result;
    globus_gsi_cred_handle_t            hand;
    X509 *                              tmp_cert = NULL;

    static char *                       _function_name_ =
        "globus_gsi_cred_read_proxy_bio";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Null handle passed to function: %s", _function_name_));
        goto exit;
    }

    if(bio == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Null bio variable passed to function: %s", _function_name_));
        goto exit;
    }

    *handle = (globus_gsi_cred_handle_t)
        globus_malloc(sizeof(globus_i_gsi_cred_handle_t));

    hand = *handle;
    
    if(!PEM_read_bio_X509(bio, & hand->cert, NULL, NULL))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Can't read X509 cert from BIO stream"));
        goto exit;
    }

    if(!PEM_read_bio_PrivateKey(bio, & hand->key, NULL, NULL))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Can't read private key from BIO stream"));
        goto exit;
    }

    if((hand->cert_chain = sk_X509_new_null()) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
            ("Can't create empty X509 cert chain"));
        goto exit;
    }

    while(!BIO_eof(bio))
    {
        if(!PEM_read_bio_X509(bio, &tmp_cert, NULL, NULL))
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
                ("Can't read X509 cert from BIO stream"));
            goto exit;
        }
        
        if(!sk_X509_push(hand->cert_chain, tmp_cert))
        {
            X509_free(tmp_cert);
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_READING_PROXY_CRED,
                ("Can't add X509 cert to cert chain"));
            goto exit;
        }

        X509_free(tmp_cert);
    }

    result = GLOBUS_SUCCESS;

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */


/**
 * Write Credential
 * @ingroup globus_gsi_credential
 */
/* @{ */
/**
 * Write out a credential to a BIO.  The credential parameters written,
 * in order, are the signed certificate, the RSA private key,
 * and the certificate chain (a set of X509 certificates).
 * the credential is written out in PEM format. 
 *
 * @param handle
 *        The credential to write out
 * @param bio
 *        The BIO stream to write out to
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which
 *        case an error object ID is returned.
 */
globus_result_t globus_gsi_cred_write(
    globus_gsi_cred_handle_t            handle,
    BIO *                               bio)
{
    int                                 i;
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_write";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_CRED,
            ("NULL handle passed to function: %s", _function_name_));
        goto error_exit;
    }
    
    if(bio == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_CRED,
            ("NULL bio variable passed to function: %s", _function_name_));
        goto error_exit;
    }
    
    if(!PEM_write_bio_X509(bio, handle->cert))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_CRED,
            ("Can't write PEM formatted X509 cert to BIO stream"));
        goto error_exit;
    }
    
    if(!PEM_ASN1_write_bio(i2d_PrivateKey, PEM_STRING_RSA,
                           bio, (char *) handle->key,
                           NULL, NULL, 0, NULL, NULL))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_CRED,
            ("Can't write PEM formatted private key to BIO stream"));
        goto error_exit;
    }
    
    for(i = 0; i < sk_X509_num(handle->cert_chain); ++i)
    {
        if(!PEM_write_bio_X509(bio, sk_X509_value(handle->cert_chain, i)))
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WRITING_CRED,
                ("Can't write PEM formatted X509 cert"
                 " in cert chain to BIO stream"));
            goto error_exit;
        }
    }
    
 error_exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */
    
    
/* Utility function that will write the credential to the standard
 * proxy file.
 */

globus_result_t globus_gsi_cred_write_proxy(
    globus_gsi_cred_handle_t            handle,
    char *                              proxy_filename)
{
    globus_result_t                     result;
    int                                 i;
    BIO *                               proxy_bio = NULL;

    static char *                       _function_name_ =
        "globus_gsi_cred_write_proxy";

    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(handle == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_PROXY_CRED,
            ("NULL handle passed to function: %s", _function_name_));
        goto exit;
    }

    if(!(proxy_bio = BIO_new_file(proxy_filename, "w")))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_PROXY_CRED,
            ("Can't open bio stream for writing to file: %s", proxy_filename));
        goto exit;
    }

    if(handle->cert == NULL || handle->key == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_PROXY_CRED,
            ("NULL fields in credential handle"));
        goto close_proxy_bio;
    }

    if(!PEM_write_bio_X509(proxy_bio, handle->cert) ||
       !PEM_ASN1_write_bio(i2d_PrivateKey, PEM_STRING_RSA,
                           proxy_bio, (char *) handle->key, 
                           NULL, NULL, 0, NULL, NULL))
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_PROXY_CRED,
            ("Can't write X509 cert or Private Key to bio stream"));
        goto close_proxy_bio;
    }

    if(handle->cert_chain == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WRITING_PROXY_CRED,
            ("NULL cert_chain field in cred handle"));
        goto close_proxy_bio;
    }

    for(i = 0; i < sk_X509_num(handle->cert_chain); ++i)
    {
        if(!PEM_write_bio_X509(proxy_bio, 
                               sk_X509_value(handle->cert_chain, i)))
        {
            GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CRED_ERROR_WRITING_PROXY_CRED,
                ("Can't write PEM formatted X509 cert "
                 "in cert chain to bio stream"));
            goto close_proxy_bio;
        }
    }

    result = GLOBUS_SUCCESS;

 close_proxy_bio:

    if(proxy_bio != NULL)
    {
        BIO_free(proxy_bio);
    }

 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}    

globus_result_t
globus_gsi_cred_check_proxy(
    globus_gsi_cred_handle_t               handle,
    globus_gsi_cert_utils_proxy_type_t *   type)
{
    globus_result_t                     result;
    static char *                       _function_name_ =
        "globus_gsi_cred_check_proxy";
    GLOBUS_I_GSI_CRED_DEBUG_ENTER;
    
    result = globus_gsi_cert_utils_check_proxy_name(handle->cert, type);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED_CERT);
    }

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * Get PROXYCERTINFO Struct
 * @ingroup globus_i_gsi_cred
 */
/* @{ */
/** 
 * Get the PROXYCERTINFO struct from the X509 struct.
 * The PROXYCERTINFO struct that gets set must be freed
 * with a call to PROXYCERTINFO_free.
 *
 * @param cert
 *        The X509 struct containing the PROXYCERTINFO struct
 *        in its extensions
 * @param proxycertinfo
 *        The resulting PROXYCERTINFO struct.  This variable
 *        should be freed with a call to PROXYCERTINFO_free when
 *        no longer in use.  It will have a value of NULL if no
 *        proxycertinfo extension exists in the X509 certificate
 * @return
 *        GLOBUS_SUCCESS (even if no proxycertinfo extension was found)
 *        or an globus error object id if an error occurred
 */
globus_result_t
globus_i_gsi_cred_get_proxycertinfo(
    X509 *                              cert,
    PROXYCERTINFO **                    proxycertinfo)
{
    globus_result_t                     result;
    X509_EXTENSION *                    pci_extension = NULL;
    ASN1_OCTET_STRING *                 ext_data;
    int                                 extension_loc;
    static char *                       _function_name_ =
        "globus_i_gsi_cred_get_proxycertinfo";
    
    GLOBUS_I_GSI_CRED_DEBUG_ENTER;

    if(pci_NID == 0)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("No numeric ID defined for the PROXYCERTINFO struct"));
        goto exit;
    }

    if(cert == NULL)
    {
        GLOBUS_GSI_CRED_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("NULL X509 cert parameter passed to function: %s", 
             _function_name_));
        goto exit;
    }

    if((extension_loc = X509_get_ext_by_NID(cert, 
                                            pci_NID, -1)) == -1)
    {
        /* no proxycertinfo extension found in cert */
        *proxycertinfo = NULL;
        result = GLOBUS_SUCCESS;
        goto exit;
    }

    if((pci_extension = X509_get_ext(cert, 
                                     extension_loc)) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("Can't find PROXYCERTINFO extension in X509 cert at "
             "expected location: %d in extension stack", extension_loc));
        goto free_ext;
    }

    if((ext_data = X509_EXTENSION_get_data(pci_extension)) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("Can't get DER encoded extension "
             "data from X509 extension object"));
        goto free_ext_data;
    }

    if((d2i_PROXYCERTINFO(
        proxycertinfo,
        & ext_data->data,
        ext_data->length)) == NULL)
    {
        GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CRED,
            ("Can't convert DER encoded PROXYCERTINFO "
             "extension to internal form"));
        goto free_pci;
    }

    result = GLOBUS_SUCCESS;

 free_pci:
    PROXYCERTINFO_free(*proxycertinfo);
 free_ext_data:
    ASN1_OCTET_STRING_free(ext_data);
 free_ext:
    X509_EXTENSION_free(pci_extension);
 exit:

    GLOBUS_I_GSI_CRED_DEBUG_EXIT;
    return result;
}
/* @} */

#endif
