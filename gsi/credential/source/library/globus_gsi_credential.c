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
#include "globus_gsi_proxy.h"
#include "version.h"
#include <openssl/pem.h>
#include <openssl/x509.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

static int globus_l_gsi_credential_activate(void);
static int globus_l_gsi_credential_deactivate(void);

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
    globus_module_activate(GLOBUS_GSI_PROXY_MODULE);
    return GLOBUS_SUCCESS;
}

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_credential_deactivate(void)
{
    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);
    return GLOBUS_SUCCESS;
}
/* globus_l_gsi_proxy_deactivate() */

#endif

/* acquire a credential from a filesystem location. The search order
 * is there to allow people to specify what kind of credential should
 * looked for first. I'm not quite sure whether I like this yet.
 */
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
 *        function.
 *
 * @param handle
 *        The credential handle to set.  This credential handle
 *        should already be initialized using globus_gsi_cred_handle_init.
 * @param desired_subject
 *        The subject to check for when reading in a credential
 * @param cert_file
 *        The certificate filename to use when searching for a certificate
 *        to read into the handle
 * @param key_file
 *        The key filename to use when searching for a private key
 *        to read into the handle
 * @param proxy_file
 *        The proxy filename to use when searching for a proxy credential
 *        to read into the handle
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
    char *                              cert_file,
    char *                              key_file,
    char *                              proxy_file)
{
    int                                 index;
    globus_result_t                     result;
    char *                              found_subject;

    static char *                       _function_name_ =
        "globus_gsi_cred_read";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    /* search for the credential of choice */

    for(index = 0; index < 3; index++)
    {
        result = GLOBUS_SUCCESS;

        switch(handle->attrs->search_order[index])
        {
        case GLOBUS_PROXY:
            
            if(!proxy_file)
            {
                break;
            }

            if((result = globus_gsi_cred_read_proxy(handle, proxy_file)) 
               != GLOBUS_SUCCESS)
            {
                result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                    result,
                    GLOBUS_GSI_CRED_ERROR_READING_PEM);
                break;
            }
            
            globus_gsi_cred_get_subject_name(handle, & found_subject);
            if(desired_subject == NULL ||
               !strcmp(found_subject, desired_subject))
            {                
                goto done;
            }
            break;

        case GLOBUS_USER:
        case GLOBUS_HOST:
        case GLOBUS_SERVICE:

            if(!cert_file || !key_file)
            {
                break;
            }
            
            if((result = globus_gsi_cred_read_cert_and_key(handle,
                                                           cert_file,
                                                           key_file))
               != GLOBUS_SUCCESS)
            {
                result = GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
                    result,
                    GLOBUS_GSI_CRED_ERROR_READING_PEM);
                break;
            }
            
            globus_gsi_cred_get_subject_name(handle, & found_subject);
            if(desired_subject == NULL ||
               !strcmp(found_subject, desired_subject))
            {
                goto done;
            }
            break;
            
        case GLOBUS_SO_END:
            return globus_i_gsi_credential_error_result(
                GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL,
                __FILE__, _function_name_, __LINE__, 
                "Credentials could not be found in any of the"
                "possible locations specified by the search order");
        }
    }
    
 done:
    if(found_subject)
    {
        globus_free(found_subject);
    }
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
    
    static char *                       _function_name_ =
        "globus_gsi_cred_read_proxy";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    /* create the bio to read the proxy in from */

    if((proxy_bio = BIO_new_file(proxy_filename, "r")) == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_OPENSSL_ERROR);
    }

    /* read in the certificate of the handle */
    
    if(handle->cert != NULL)
    {
        X509_free(handle->cert);
    }
    
    if(!PEM_read_bio_X509(proxy_bio, & handle->cert, NULL, NULL))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_READING_PEM);
    }

    /* read in the private key of the handle */

    if(handle->key != NULL)
    {
        EVP_PKEY_free(handle->key);
    }

    if((handle->key = PEM_read_bio_PrivateKey(proxy_bio, NULL, NULL, NULL))
       == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_READING_PEM);
    }

    /* read in the certificate chain of the handle */

    if(handle->cert_chain != NULL)
    {
        sk_X509_pop_free(handle->cert_chain, X509_free);
    }

    if((handle->cert_chain = sk_X509_new_null()) == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

    while(!BIO_eof(proxy_bio))
    {
        if(!PEM_read_bio_X509(proxy_bio, &tmp_cert, NULL, NULL))
        {
            return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_READING_PEM);
        }
        
        if(!sk_X509_push(handle->cert_chain, tmp_cert))
        {
            X509_free(tmp_cert);
            return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_X509);
        }

        X509_free(tmp_cert);
    }

    BIO_free(proxy_bio);

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
    char *                              key_filename)
{
    BIO *                               cert_bio = NULL;
    BIO *                               key_bio = NULL;
    FILE *                              cert_fp = NULL;
    FILE *                              key_fp = NULL;

    static char *                       _function_name_ =
        "globus_gsi_cred_read_cert_and_key";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(!(cert_fp = fopen(cert_filename, "r")))
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_OPENING_FILE);
    }

    if(!(cert_bio = BIO_new_file(cert_filename, "r")) ||
       !(BIO_set_fp(cert_bio, cert_fp, BIO_NOCLOSE|BIO_FP_TEXT)))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_OPENSSL_ERROR);
    }

    if(!(key_fp = fopen(key_filename, "r")))
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_OPENING_FILE);
    }

    if(!(key_bio = BIO_new_file(key_filename, "r")) ||
       !(BIO_set_fp(key_bio, key_fp, BIO_NOCLOSE|BIO_FP_TEXT)))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_OPENSSL_ERROR);
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
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_READING_PEM);
    }

    if(!PEM_read_bio_PrivateKey(key_bio, & handle->key, NULL, NULL))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_READING_PEM);
    }

    BIO_free(cert_bio);
    BIO_free(key_bio);
    fclose(cert_fp);
    fclose(key_fp);

    if(handle->cert_chain != NULL)
    {
        sk_X509_pop_free(handle->cert_chain, X509_free);
        handle->cert_chain = NULL;
    }

    return GLOBUS_SUCCESS;
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
    globus_gsi_cred_handle_t            hand;
    X509 *                              tmp_cert = NULL;

    static char *                       _function_name_ =
        "globus_gsi_cred_read_proxy_bio";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(bio == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_OPENSSL_ERROR);
    }

    *handle = (globus_gsi_cred_handle_t)
        globus_malloc(sizeof(globus_i_gsi_cred_handle_t));

    hand = *handle;
    
    if(!PEM_read_bio_X509(bio, & hand->cert, NULL, NULL))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_READING_PEM);
    }

    if(!PEM_read_bio_PrivateKey(bio, & hand->key, NULL, NULL))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_READING_PEM);
    }

    if((hand->cert_chain = sk_X509_new_null()) == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

    while(!BIO_eof(bio))
    {
        if(!PEM_read_bio_X509(bio, &tmp_cert, NULL, NULL))
        {
            return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_READING_PEM);
        }
        
        if(!sk_X509_push(hand->cert_chain, tmp_cert))
        {
            X509_free(tmp_cert);
            return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WITH_X509);
        }

        X509_free(tmp_cert);
    }

    return GLOBUS_SUCCESS;
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
    static char *                       _function_name_ =
        "globus_gsi_cred_write";
    
    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }
    
    if(bio == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_BAD_PARAMETER);
    }
    
    if(!PEM_write_bio_X509(bio, handle->cert))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WRITING_PEM);
    }
    
    if(!PEM_ASN1_write_bio(i2d_PrivateKey, PEM_STRING_RSA,
                           bio, (char *) handle->key,
                           NULL, NULL, 0, NULL, NULL))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WRITING_PEM);
    }
    
    for(i = 0; i < sk_X509_num(handle->cert_chain); ++i)
    {
        if(!PEM_write_bio_X509(bio, sk_X509_value(handle->cert_chain, i)))
        {
            return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WRITING_PEM);
        }
    }
    
    return GLOBUS_SUCCESS;
}
/* @} */
    
    
/* Utility function that will write the credential to the standard
 * proxy file.
 */

globus_result_t globus_gsi_cred_write_proxy(
    globus_gsi_cred_handle_t            handle,
    char *                              proxy_filename)
{
    int                                 i;
    BIO *                               proxy_bio = NULL;
    FILE *                              proxy_fp = NULL;

    static char *                       _function_name_ =
        "globus_gsi_cred_write_proxy";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(!(proxy_fp = fopen(proxy_filename, "w")))
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_OPENING_FILE);
    }

    if(!(proxy_bio = BIO_new(BIO_s_file())) || 
       !(BIO_set_fp(proxy_bio, proxy_fp, BIO_NOCLOSE|BIO_FP_TEXT)))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_OPENING_FILE);
    }

    if(handle->cert == NULL || handle->key == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

    if(!PEM_write_bio_X509(proxy_bio, handle->cert) ||
       !PEM_ASN1_write_bio(i2d_PrivateKey, PEM_STRING_RSA,
                           proxy_bio, (char *) handle->key, 
                           NULL, NULL, 0, NULL, NULL))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WRITING_PEM);
    }

    if(handle->cert_chain == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

    for(i = 0; i < sk_X509_num(handle->cert_chain); ++i)
    {
        if(!PEM_write_bio_X509(proxy_bio, 
                               sk_X509_value(handle->cert_chain, i)))
        {
            return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_CRED_ERROR_WRITING_PEM);
        }
    }

    globus_free(proxy_filename);
    BIO_free(proxy_bio);
    fclose(proxy_fp);

    return GLOBUS_SUCCESS;
}    

/* Determine whether the credential structure contains a proxy */

globus_result_t globus_gsi_cred_is_proxy(
    globus_gsi_cred_handle_t            handle,
    int *                               is_proxy)
{
    char *                              subject_name = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_cred_is_proxy";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }
    
    if((result = globus_gsi_cred_get_subject_name(
        handle, & subject_name)) != GLOBUS_SUCCESS)
    {
        return globus_i_gsi_credential_error_chain_result(
            result,
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE_ATTRS,
            __FILE__, _function_name_, __LINE__,
            "Error getting subject name of cred handle");
    }

    if(strstr(subject_name, "CN=proxy") != NULL)
    {
        *is_proxy = 1;
    }
    else if(strstr(subject_name, "CN=limited proxy") != NULL)
    {
        *is_proxy = 2;
    }
    else if(strstr(subject_name, "CN=restricted proxy") != NULL)
    {
        *is_proxy = 3;
    }
    else
    {
        *is_proxy = 0;
    }

    globus_free(subject_name);
    return GLOBUS_SUCCESS;
}

/*  int */
/*  proxy_verify_cert_chain( */
/*      X509 *                              ucert, */
/*      STACK_OF(X509) *                    cert_chain, */
/*      proxy_verify_desc *                 pvd) */
/*  { */
/*      int                                 i; */
/*      int                                 j; */
/*      int                                 retval = 0; */
/*      X509_STORE *                        cert_store = NULL; */
/*      X509_LOOKUP *                       lookup = NULL; */
/*      X509_STORE_CTX                      csc; */
/*      X509 *                              xcert = NULL; */
/*      X509 *                              scert = NULL; */
/*  #ifdef DEBUG */
/*      fprintf(stderr,"proxy_verify_cert_chain\n"); */
/*  #endif */
/*      scert = ucert; */
/*      cert_store = X509_STORE_new(); */
/*      X509_STORE_set_verify_cb_func(cert_store, proxy_verify_callback); */
/*      if (cert_chain != NULL) */
/*      { */
/*          for (i=0;i<sk_X509_num(cert_chain);i++) */
/*          { */
/*              xcert = sk_X509_value(cert_chain,i); */
/*              if (!scert) */
/*              { */
/*                  scert = xcert; */
/*              } */
/*              else */
/*              { */
/*  #ifdef DEBUG */
/*                  { */
/*                      char * s; */
/*                      s = X509_NAME_oneline(X509_get_subject_name(xcert), */
/*                                            NULL,0); */
/*                      fprintf(stderr,"Adding %d %p %s\n",i,xcert,s); */
/*                      free(s); */
/*                  } */
/*  #endif */
/*                  j = X509_STORE_add_cert(cert_store, xcert); */
/*                  if (!j) */
/*                  { */
/*                      if ((ERR_GET_REASON(ERR_peek_error()) == */
/*                           X509_R_CERT_ALREADY_IN_HASH_TABLE)) */
/*                      { */
/*                          ERR_clear_error(); */
/*                          break; */
/*                      } */
/*                      else */
/*                      { */
/*                          *DEE need errprhere * */
/*                          goto err; */
/*                      } */
/*                  } */
/*              } */
/*          } */
/*      } */
/*      if ((lookup = X509_STORE_add_lookup(cert_store, */
/*                                          X509_LOOKUP_hash_dir()))) */
/*      { */
/*          X509_LOOKUP_add_dir(lookup,pvd->pvxd->certdir,X509_FILETYPE_PEM); */
/*          X509_STORE_CTX_init(&csc,cert_store,scert,NULL); */

/*  #if SSLEAY_VERSION_NUMBER >=  0x0090600fL */
/*          * override the check_issued with our version * */
/*          csc.check_issued = proxy_check_issued; */
/*  #endif */
/*          X509_STORE_CTX_set_ex_data(&csc, */
/*                                     PVD_STORE_EX_DATA_IDX, (void *)pvd); */
                 
/*          if(!X509_verify_cert(&csc)) */
/*          { */
/*              goto err; */
/*          } */
/*      }  */
/*      retval = 1; */

/*  err: */
/*      return retval; */
/*  } */


/* If we can, walk the cert chain and make sure that the credential is
 * ok. Might also check that all proxy certs are wellformed.
 */

globus_result_t 
globus_gsi_cred_verify(
    globus_gsi_cred_handle_t            handle)
{
    globus_result_t                     result;
    int                                 is_proxy;

    static char *                       _function_name_ =
        "globus_gsi_cred_verify";

    if(handle == NULL)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_NULL_HANDLE);
    }

    if(!handle->cert || !handle->key)
    {
        return GLOBUS_GSI_CRED_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_VERIFYING_CERT);
    }

    /* check that the private key goes with the public key in the cert */

    if(!X509_check_private_key(handle->cert, handle->key))
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_VERIFYING_CERT);
    }

    /* find out if its a proxy */

    if((result = globus_gsi_cred_is_proxy(handle, & is_proxy))
        != GLOBUS_SUCCESS)
    {
        return GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CRED_ERROR_VERIFYING_CERT);
    }

    if(is_proxy == 0)
    {
        /* then not a proxy - return successful verify of cred */
        return GLOBUS_SUCCESS;
    }
    
/* it is a proxy - now we do further verification */

    if(handle->cert_chain == NULL)
    {
        return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_CRED_ERROR_WITH_CREDENTIAL_HANDLE);
    }

/*       verify proxy cert chain */
/*      context = SSL_CTX_new(SSLv3_method()); */
/*      if(context == NULL) */
/*      { */
/*          return GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT( */
/*              GLOBUS_GSI_CRED_ERROR_CANT_INIT_SSL_CONTEXT); */
/*      } */
    
/*      SSL_CTX_set_options(contex, 0); */
/*      SSL_CTX_set_cert_verify_callback(context, proxy_app_verify_callback, NULL); */

/*      SSL_CTX_set_verify(context, SSL_VERIFY_PEER, proxy_verify_callback); */

/*      SSL_CTX_set_purpose(context, X509_PURPOSE_ANY); */

/*      SSL_CTX_sess_set_cache_size(context, 5); */

/*      if(!SSL_CTX_load_verify_locations(context, ca_cert_file */
/*      if(!X509_verify_cert(handle->cert,  */

    return GLOBUS_SUCCESS;
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/*  globus_result_t */
/*  globus_i_gsi_cred_verify_cert_chain( */
/*      X509 *                              ucert, */
/*      STACK_OF(X509) *                    cert_chain, */
/*      proxy_verify_desc *                 pvd) */
/*  { */
/*      int                                 i; */
/*      int                                 j; */
/*      int                                 retval = 0; */
/*      X509_STORE *                        cert_store = NULL; */
/*      X509_LOOKUP *                       lookup = NULL; */
/*      X509_STORE_CTX                      csc; */
/*      X509 *                              xcert = NULL; */
/*      X509 *                              scert = NULL; */
/*  #ifdef DEBUG */
/*      fprintf(stderr,"proxy_verify_cert_chain\n"); */
/*  #endif */
/*      scert = ucert; */
/*      cert_store = X509_STORE_new(); */
/*      X509_STORE_set_verify_cb_func(cert_store, proxy_verify_callback); */
/*      if (cert_chain != NULL) */
/*      { */
/*          for (i=0;i<sk_X509_num(cert_chain);i++) */
/*          { */
/*              xcert = sk_X509_value(cert_chain,i); */
/*              if (!scert) */
/*              { */
/*                  scert = xcert; */
/*              } */
/*              else */
/*              { */
/*  #ifdef DEBUG */
/*                  { */
/*                      char * s; */
/*                      s = X509_NAME_oneline(X509_get_subject_name(xcert), */
/*                                            NULL,0); */
/*                      fprintf(stderr,"Adding %d %p %s\n",i,xcert,s); */
/*                      free(s); */
/*                  } */
/*  #endif */
/*                  j = X509_STORE_add_cert(cert_store, xcert); */
/*                  if (!j) */
/*                  { */
/*                      if ((ERR_GET_REASON(ERR_peek_error()) == */
/*                           X509_R_CERT_ALREADY_IN_HASH_TABLE)) */
/*                      { */
/*                          ERR_clear_error(); */
/*                          break; */
/*                      } */
/*                      else */
/*                      { */
/*                          *DEE need errprhere * */
/*                          goto err; */
/*                      } */
/*                  } */
/*              } */
/*          } */
/*      } */
/*      if ((lookup = X509_STORE_add_lookup(cert_store, */
/*                                          X509_LOOKUP_hash_dir()))) */
/*      { */
/*          X509_LOOKUP_add_dir(lookup,pvd->pvxd->certdir,X509_FILETYPE_PEM); */
/*          X509_STORE_CTX_init(&csc,cert_store,scert,NULL); */

/*  #if SSLEAY_VERSION_NUMBER >=  0x0090600fL */
/*          * override the check_issued with our version * */
/*          csc.check_issued = proxy_check_issued; */
/*  #endif */
/*          X509_STORE_CTX_set_ex_data(&csc, */
/*                                     PVD_STORE_EX_DATA_IDX, (void *)pvd); */
                 
/*          if(!X509_verify_cert(&csc)) */
/*          { */
/*              goto err; */
/*          } */
/*      }  */
/*      retval = 1; */

/*  err: */
/*      return retval; */
/*  } */
/*  #endif * NO_PROXY_VERIFY_CALLBACK * */

/*  int */
/*  globus_i_gsi_X509_check_issued( */
/*      X509_STORE_CTX *                    ctx, */
/*      X509 *                              x, */
/*      X509 *                              issuer) */
/*  { */
/*      int                                 ret; */
/*      int                                 proxy_type; */

/*      ret = X509_check_issued(issuer, x); */

/*      if (ret != X509_V_OK) */
/*      { */
/*          switch (ret) */
/*          { */
/*  #warning  SLANG:  removed to see if its needed - if it doesnt break... */
/*  *          case X509_V_ERR_AKID_SKID_MISMATCH: * */
/*              *  */
/*               * If the proxy was created with a previous version of Globus */
/*               * where the extensions where copied from the user certificate */
/*               * This error could arise, as the akid will be the wrong key */
/*               * So if its a proxy, we will ignore this error. */
/*               * We should remove this in 12/2001  */
/*               * At which time we may want to add the akid extension to the proxy. */
/*               * */

/*          case X509_V_ERR_KEYUSAGE_NO_CERTSIGN: */
/*              * */
/*               * If this is a proxy certificate then the issuer */
/*               * does not need to have the key_usage set. */
/*               * So check if its a proxy, and ignore */
/*               * the error if so.  */
/*               * */
/*              result = globus_l_gsi_proxy_check_proxy_name(x, & proxy_type); */
/*              if (result == GLOBUS_SUCCESS && proxy_type >= 1) */
/*              { */
/*                  ret = X509_V_OK; */
/*              } */
/*              break; */
/*          default: */
/*              break; */
/*          } */
/*      } */

/*      return ret; */
/*  } */

/*  int */
/*  globus_i_gsi_X509_verify_cert_callback( */
/*      X509_STORE_CTX *                    ctx) */
/*  { */

/*      * */
/*       * OpenSSL-0.9.6 has a  check_issued routine which */
/*       * we want to override so we  can replace some of the checks. */
/*       * */
/*      ctx->check_issued = globus_i_gsi_X509_check_issued; */
/*      return X509_verify_cert(ctx); */
/*  } */

globus_result_t
globus_i_gsi_credential_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_result_t                     result;

    va_start(ap, format);

    result = globus_error_put(
        globus_i_gsi_credential_openssl_error_construct(
            error_type,
            filename,
            function_name,
            line_number,
            format,
            ap));

    va_end(ap);

    return result;
}

globus_object_t *
globus_i_gsi_credential_openssl_error_construct(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap)
{
    static FILE *                       proxy_openssl_error_file = NULL;
    char *                              desc_string = NULL;
    char *                              reason_string = NULL;
    int                                 len;
    globus_object_t *                   error_object;

    globus_libc_lock();
    
    proxy_openssl_error_file = fopen("/dev/null", "w");
    len = vfprintf(proxy_openssl_error_file, format ? format : "", ap) + 1;
    reason_string = (char *) globus_malloc(len);
    vsprintf(reason_string, format ? format : "", ap);

    len = fprintf(proxy_openssl_error_file, "OpenSSL Error: %s:%s:%d: %s",
                  filename, function_name, line_number,
                  globus_l_gsi_cred_error_strings[error_type]);
    desc_string = (char *) globus_malloc(len);
    sprintf(desc_string, "OpenSSL Error: %s:%s:%d: %s",
            filename, function_name, line_number,
            globus_l_gsi_cred_error_strings[error_type]);

    fclose(proxy_openssl_error_file);

    globus_libc_unlock();

    error_object = globus_error_wrap_openssl_error(
        GLOBUS_GSI_PROXY_MODULE,
        desc_string,
        error_type,
        reason_string);
    
    globus_free(desc_string);
    globus_free(reason_string);

    return error_object;
}            

globus_result_t
globus_i_gsi_credential_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_result_t                     result;

    va_start(ap, format);

    result = globus_error_put(
        globus_i_gsi_credential_error_construct(
            error_type,
            filename,
            function_name,
            line_number,
            format,
            ap));
        
    va_end(ap);

    return result;
}
            
globus_object_t *
globus_i_gsi_credential_error_construct(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap)
{
    static FILE *                       proxy_error_file = NULL;
    char *                              desc_string = NULL;
    char *                              reason_string = NULL;
    int                                 len;
    globus_object_t *                   error_object;

    globus_libc_lock();

    proxy_error_file = fopen("/dev/null", "w");
    len = vfprintf(proxy_error_file, format ? format : "", ap) + 1;
    reason_string = globus_malloc(len);
    vsprintf(reason_string, format ? format : "", ap);

    len = fprintf(proxy_error_file, "%s:%s:%d: %s", 
                  filename, function_name, line_number, 
                  globus_l_gsi_cred_error_strings[error_type]);
    desc_string = globus_malloc(len);
    sprintf(desc_string, "%s:%s:%d: %s", 
            filename, function_name, line_number,
            globus_l_gsi_cred_error_strings[error_type]);
    
    fclose(proxy_error_file);
    
    globus_libc_unlock();

    error_object = globus_error_construct_error(
        GLOBUS_GSI_CREDENTIAL_MODULE,
        NULL,
        error_type,
        desc_string,
        reason_string);
    
    globus_free(desc_string);
    globus_free(reason_string);
    
    return error_object;
}

globus_result_t
globus_i_gsi_credential_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_result_t                     result;

    va_start(ap, format);

    result = globus_error_put(
        globus_i_gsi_credential_error_chain_construct(
            chain_result,
            error_type,
            filename,
            function_name,
            line_number,
            format,
            ap));
        
    va_end(ap);

    return result;
}
            
globus_object_t *
globus_i_gsi_credential_error_chain_construct(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap)
{
    static FILE *                       proxy_error_file = NULL;
    char *                              desc_string = NULL;
    char *                              reason_string = NULL;
    int                                 len;
    globus_object_t *                   error_object;

    globus_libc_lock();

    proxy_error_file = fopen("/dev/null", "w");
    len = vfprintf(proxy_error_file, format ? format : "", ap) + 1;
    reason_string = globus_malloc(len);
    vsprintf(reason_string, format ? format : "", ap);

    len = fprintf(proxy_error_file, "%s:%s:%d: %s", 
                  filename, function_name, line_number, 
                  globus_l_gsi_cred_error_strings[error_type]);
    desc_string = globus_malloc(len);
    sprintf(desc_string, "%s:%s:%d: %s", 
            filename, function_name, line_number,
            globus_l_gsi_cred_error_strings[error_type]);

    fclose(proxy_error_file);
    
    globus_libc_unlock();

    error_object = globus_error_construct_error(
        GLOBUS_GSI_CREDENTIAL_MODULE,
        globus_error_get(chain_result),
        error_type,
        desc_string,
        reason_string);

    globus_free(desc_string);
    globus_free(reason_string);

    return error_object;
}

#endif
