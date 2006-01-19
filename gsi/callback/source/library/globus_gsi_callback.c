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
 * @file globus_gsi_callback.c
 * Globus GSI Callback
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_common.h"
#include "proxycertinfo.h"
#include "globus_gsi_callback_constants.h"
#include "globus_i_gsi_callback.h"
#include "globus_gsi_system_config.h"
#include "openssl/err.h"
#include "openssl/asn1.h"
#include "openssl/ssl.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/x509v3.h"
#include "version.h"

#ifndef BUILD_FOR_K5CERT_ONLY
#ifndef NO_OLDGAA_API
#include "globus_oldgaa.h"
#include "globus_oldgaa_utils.h"
#else
#include "ca_policy_file_parse.h"
#endif
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
static globus_mutex_t                   globus_l_gsi_callback_oldgaa_mutex;

static int globus_l_gsi_callback_activate(void);
static int globus_l_gsi_callback_deactivate(void);

int                              globus_i_gsi_callback_debug_level   = 0;
FILE *                           globus_i_gsi_callback_debug_fstream = NULL;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_gsi_callback_module =
{
    "globus_gsi_callback_module",
    globus_l_gsi_callback_activate,
    globus_l_gsi_callback_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_gsi_callback_activate(void)
{
    int                                 result = (int) GLOBUS_SUCCESS;
    char *                              tmp_string;
    static char *                       _function_name_ =
        "globus_l_gsi_callback_activate";

    tmp_string = globus_module_getenv("GLOBUS_GSI_CALLBACK_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_callback_debug_level = atoi(tmp_string);
        
        if(globus_i_gsi_callback_debug_level < 0)
        {
            globus_i_gsi_callback_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSI_CALLBACK_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_callback_debug_fstream = fopen(tmp_string, "a");
        if(globus_i_gsi_callback_debug_fstream == NULL)
        {
            result = (int) GLOBUS_FAILURE;
            goto exit;
        }
    }
    else
    {
        globus_i_gsi_callback_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    result = globus_module_activate(GLOBUS_COMMON_MODULE);

    if(result != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    
    result = globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE);

    if(result != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    result = globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);

    if(result != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    globus_mutex_init(&globus_l_gsi_callback_oldgaa_mutex, NULL);
    
    OpenSSL_add_all_algorithms();

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;

 exit:

    return result;
}

/**
 * Module deactivation
 */
static
int
globus_l_gsi_callback_deactivate(void)
{
    int                                 result = (int) GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_l_gsi_callback_deactivate";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    EVP_cleanup();

    globus_mutex_destroy(&globus_l_gsi_callback_oldgaa_mutex);
    globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
    globus_module_deactivate(GLOBUS_GSI_SYSCONFIG_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;

    if(globus_i_gsi_callback_debug_fstream != stderr)
    {
        fclose(globus_i_gsi_callback_debug_fstream);
    }

    return result;
}

static int globus_i_gsi_callback_SSL_callback_data_index = -1;
static int globus_i_gsi_callback_X509_STORE_callback_data_index = -1;


static int
globus_l_gsi_callback_openssl_new(
    void *                              parent, 
    void *                              ptr, 
    CRYPTO_EX_DATA *                    ad,
    int                                 idx, 
    long                                argl, 
    void *                              argp)
{
    int                                 result = 1;
    static char *                       _function_name_ =
        "globus_gsi_callback_openssl_new";
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /* init app specific data (callback data)
     * since we can't allocate the ptr here
     * this function isn't particularly useful
     */
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

static int
globus_l_gsi_callback_openssl_free(
    void *                              parent, 
    void *                              ptr, 
    CRYPTO_EX_DATA *                    ad,
    int                                 idx, 
    long                                argl, 
    void *                              argp)
{
    int                                 result = 1;
    static char *                       _function_name_ =
        "globus_gsi_callback_openssl_free";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /* free the callback data - currently not used*/

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

static int
globus_l_gsi_callback_openssl_dup(
    CRYPTO_EX_DATA *                    to, 
    CRYPTO_EX_DATA *                    from, 
    void *                              from_d,                   
    int                                 idx, 
    long                                argl, 
    void *                              argp)
{
    int                                 result = 1;
    static char *                       _function_name_ =
        "globus_gsi_callback_openssl_dup";
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /* copy the callback data - currenlty not used by OpenSSL */

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

#endif

/**
 * @name Get callback data index from X509_STORE
 * @ingroup globus_gsi_callback
 */
/* @{ */
/**
 * Retrieve or create the index for our callback data structure in the
 * X509_STORE.
 *
 * @param index
 *        Will contain the index upon return
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_X509_STORE_callback_data_index(
    int *                               index)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_X509_STORE_callback_data_index";
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    if(globus_i_gsi_callback_X509_STORE_callback_data_index < 0)
    {
        globus_i_gsi_callback_X509_STORE_callback_data_index = 
            X509_STORE_CTX_get_ex_new_index(
                0, NULL, 
                (CRYPTO_EX_new *)  &globus_l_gsi_callback_openssl_new,
                (CRYPTO_EX_dup *)  &globus_l_gsi_callback_openssl_dup,
                (CRYPTO_EX_free *) &globus_l_gsi_callback_openssl_free);
        if(globus_i_gsi_callback_X509_STORE_callback_data_index < 0)
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_WITH_CALLBACK_DATA_INDEX,
                (_CLS("Couldn't create external data index for SSL object")));
            goto exit;
        }
    }

    *index = globus_i_gsi_callback_X509_STORE_callback_data_index;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Get callback data index from SSL structure
 * @ingroup globus_gsi_callback
 */
/* @{ */
/**
 * Retrieve or create the index for our callback data structure in the
 * SSL structure.
 *
 * @param index
 *        Will contain the index upon return
 *
 * @return
 *        GLOBUS_SUCCESS unless an error occurred, in which case, 
 *        a globus error object ID is returned
 */
globus_result_t
globus_gsi_callback_get_SSL_callback_data_index(
    int *                               index)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_gsi_callback_get_SSL_callback_data_index";
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
    
    if(globus_i_gsi_callback_SSL_callback_data_index < 0)
    {
        globus_i_gsi_callback_SSL_callback_data_index = SSL_get_ex_new_index(
            0, NULL, 
            (CRYPTO_EX_new *)  &globus_l_gsi_callback_openssl_new,
            (CRYPTO_EX_dup *)  &globus_l_gsi_callback_openssl_dup,
            (CRYPTO_EX_free *) &globus_l_gsi_callback_openssl_free);
        if(globus_i_gsi_callback_SSL_callback_data_index < 0)
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_WITH_CALLBACK_DATA_INDEX,
                (_CLS("Couldn't create external data index for SSL object")));
            goto exit;
        }
    }

    *index = globus_i_gsi_callback_SSL_callback_data_index;

 exit:
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Certificate verify wrapper
 * @ingroup globus_gsi_callback
 */
/* @{ */
/**
 * This function wraps the OpenSSL certificate verification callback for the
 * purpose of a replacing the standard issuer check with one that deals with
 * proxy certificates. Should be used with SSL_CTX_set_cert_verify_callback()
 *
 * @param context
 *        The X509_STORE_CTX for which to register the callback.
 * @param arg
 *        Arguments to the callback. Currently ignored.
 * @return
 *        1 on success
 *        0 on failure
 */
int 
globus_gsi_callback_X509_verify_cert(
    X509_STORE_CTX *                    context,
    void *                              arg)
{
    int                                 result;
    static char *                       _function_name_ =
        "globus_gsi_callback_X509_verify_cert";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /*
     * OpenSSL-0.9.6 has a  check_issued routine which
     * we want to override so we  can replace some of the checks.
     */
    context->check_issued = globus_gsi_callback_check_issued;
    result = X509_verify_cert(context);

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}
/* @} */

/**
 * @name Independent path validation callback.
 * @ingroup globus_gsi_callback
 */
/* @{ */
/**
 * This function provides a path validation callback for validation outside of
 * a SSL session. It should be used in X509_STORE_set_verify_cb_func().
 *
 * @param preverify_ok
 *        Communicates the result of default validation steps performed by
 *        OpenSSL  
 * @param x509_context
 *        The validation state object
 * @return
 *        1 on success
 *        0 on failure 
 */
int globus_gsi_callback_create_proxy_callback(
    int                                 preverify_ok,
    X509_STORE_CTX *                    x509_context)
{
    int                                 cb_index;
    int                                 verify_result;
    globus_result_t                     result;
    globus_gsi_callback_data_t          callback_data;
    static char *                       _function_name_ = 
        "globus_i_gsi_callback_create_proxy_callback";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    result = globus_gsi_callback_get_X509_STORE_callback_data_index(&cb_index);
    if(result != GLOBUS_SUCCESS)
    {
        verify_result = 0;
        goto exit;
    }
            
    callback_data = (globus_gsi_callback_data_t)
       X509_STORE_CTX_get_ex_data(
           x509_context, 
           cb_index);

    if(!callback_data)
    {
        verify_result = 0;
        goto exit;
    }

    result = globus_i_gsi_callback_cred_verify(preverify_ok,
                                               callback_data,
                                               x509_context);

    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
        callback_data->error = result;
        verify_result = 0;
        goto set_callback_data_error;
    }

    result = GLOBUS_SUCCESS;
    verify_result = 1;

 set_callback_data_error:

    callback_data->error = result;

 exit:

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return verify_result;
}
/* @} */

/**
 * @name SSL path validation callback.
 * @ingroup globus_gsi_callback
 */
/* @{ */
/**
 * This function provides a path validation callback for the validation part of
 * establishing a SSL session. It handles proxy certificates, X509 Extensions
 * and CRL checking. It should be used in SSL_CTX_set_verify().
 *
 * @param preverify_ok
 *        Communicates the result of default validation steps performed by
 *        OpenSSL  
 * @param x509_context
 *        The validation state object.
 * @return
 *        1 on success
 *        0 on failure 
 */
int globus_gsi_callback_handshake_callback(
    int                                 preverify_ok,
    X509_STORE_CTX *                    x509_context)
{
    int                                 verify_result;
    int                                 callback_data_index;
    globus_result_t                     result;
    globus_gsi_callback_data_t          callback_data;
    SSL *                               ssl = NULL;
    static char *                       _function_name_ = 
        "globus_gsi_callback_handshake_callback";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /* the first index should contain the SSL structure */
    ssl = (SSL *)
        X509_STORE_CTX_get_ex_data(x509_context,
                                   SSL_get_ex_data_X509_STORE_CTX_idx());
    if(!ssl)
    {
        verify_result = 0;
        goto exit;
    }

    result = globus_gsi_callback_get_SSL_callback_data_index(
        &callback_data_index);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
        verify_result = 0;
        goto set_callback_data_error;
    }

    callback_data = *(globus_gsi_callback_data_t *)
        SSL_get_ex_data(ssl, callback_data_index);
    if(!callback_data)
    {
        verify_result = 0;
        goto exit;
    }

    result = globus_i_gsi_callback_cred_verify(preverify_ok,
                                               callback_data,
                                               x509_context);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
        verify_result = 0;
        goto set_callback_data_error;
    }

    result = GLOBUS_SUCCESS;
    verify_result = 1;

 set_callback_data_error:

    callback_data->error = result;

 exit: 
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return verify_result;
}
/* @} */

/**
 * @name OpenSSL X509_check_issued() wrapper
 * @ingroup globus_gsi_callback
 */
/* @{ */
/**
 * This function wraps the OpenSSL X509_check_issued() call and catches the
 * error caused by the fact that a proxy certificate issuer may not have to
 * have the correct KeyUsage fields set.
 *
 * @param context
 *        The validation state object.
 * @param cert
 *        The certificate to check
 * @param issuer
 *        The issuer certificate to check 
 * @return
 *        1 on success
 *        0 on failure 
 */
int globus_gsi_callback_check_issued(
    X509_STORE_CTX *                    context,
    X509 *                              cert,
    X509 *                              issuer)
{
    globus_result_t                     result;
    int                                 return_value;
    int                                 return_code = 1;
    globus_gsi_cert_utils_cert_type_t   cert_type;
    static char *                       _function_name_ =
        "globus_gsi_callback_check_issued";
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
    
    return_value = X509_check_issued(issuer, cert);
    if(return_value != X509_V_OK)
    {
        return_code = 0;
        switch(return_value)
        {
 
        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
             /* If this is a proxy certificate then the issuer
              * does not need to have the key_usage set.
              * So check if its a proxy, and ignore
              * the error if so. 
              */
            result = globus_gsi_cert_utils_get_cert_type(cert, &cert_type);
            if(result != GLOBUS_SUCCESS)
            {
                return_code = 0;
                break;
            }
            
            if(GLOBUS_GSI_CERT_UTILS_IS_PROXY(cert_type))
            {
                /* its a proxy! */
                return_code = 1;
            }
            break;
            
        default:
            break;
        }
    }
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return return_code;
}
/* @} */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

globus_result_t
globus_i_gsi_callback_cred_verify(
    int                                 preverify_ok,
    globus_gsi_callback_data_t          callback_data,
    X509_STORE_CTX *                    x509_context)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    X509 *                              tmp_cert = NULL;
    static char *                       _function_name_ = 
        "globus_i_gsi_callback_cred_verify";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
    
    /* Now check for some error conditions which
     * can be disregarded. 
     */
    if (!preverify_ok)
    {
        switch (x509_context->error)
        {
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:

            GLOBUS_I_GSI_CALLBACK_DEBUG_PRINT(
                2, "X509_V_ERR_PATH_LENGTH_EXCEEDED\n");
            /*
             * Since OpenSSL does not know about proxies,
             * it will count them against the path length
             * So we will ignore the errors and do our
             * own checks later on, when we check the last
             * certificate in the chain we will check the chain.
             */
            result = GLOBUS_SUCCESS;
            break;

        default:
            result = (globus_result_t)GLOBUS_FAILURE;
            break;
        }                       

        if (result != GLOBUS_SUCCESS)
        {
	    char *                      subject_name =
	      X509_NAME_oneline(X509_get_subject_name(x509_context->current_cert), 0, 0);

            if (x509_context->error == X509_V_ERR_CERT_NOT_YET_VALID)
            {
                GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CALLBACK_ERROR_CERT_NOT_YET_VALID,
                    (_CLS("Cert with subject: %s is not yet valid"
		     "- check clock skew between hosts."), subject_name));
            }
            else if (x509_context->error == 
                     X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            {
                GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CALLBACK_ERROR_CANT_GET_LOCAL_CA_CERT,
                    (_CLS("Cannot find issuer certificate for "
		     "local credential with subject: %s"), subject_name));
            }
            else if (x509_context->error == X509_V_ERR_CERT_HAS_EXPIRED)
            {
                GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CALLBACK_ERROR_CERT_HAS_EXPIRED,
                    (_CLS("Credential with subject: %s has expired."), subject_name));
            }
            else
            {
                GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED,
                    (X509_verify_cert_error_string(x509_context->error)));
            }
	
	    OPENSSL_free(subject_name);

            goto exit;
        }

        goto exit;
    }

    result = globus_i_gsi_callback_check_proxy(x509_context,
                                               callback_data);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
        goto exit;
    }

    if(callback_data->cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_EEC ||
       callback_data->cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_CA)
    {
        /* only want to check that the cert isn't revoked if its not
         * a proxy, since proxies don't ever get revoked
         */
#ifdef X509_V_ERR_CERT_REVOKED
        result = globus_i_gsi_callback_check_revoked(x509_context,
                                                     callback_data);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
            goto exit;
        }
#endif
    
        /* only want to check singing_policy file if its not a proxy */
        result = globus_i_gsi_callback_check_signing_policy(
            x509_context,
            callback_data);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
            goto exit;
        }        
    }

    tmp_cert = X509_dup(x509_context->current_cert);

    /* add the current cert to the callback data's cert chain */
    sk_X509_insert(callback_data->cert_chain, 
                   tmp_cert, 0);

    callback_data->cert_depth++;

    result =
        globus_i_gsi_callback_check_critical_extensions(x509_context,
                                                        callback_data);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
        goto exit;
    }

    result = globus_i_gsi_callback_check_path_length(x509_context,
                                                     callback_data);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
        goto exit;
    }
    
 exit:

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_i_gsi_callback_check_proxy(
    X509_STORE_CTX *                    x509_context,
    globus_gsi_callback_data_t          callback_data)
{
    globus_gsi_cert_utils_cert_type_t   cert_type;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_i_gsi_callback_check_proxy";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /* All of the OpenSSL tests have passed and we now get to 
     * look at the certificate to verify the proxy rules, 
     * and ca-signing-policy rules. We will also do a CRL check
     */
    result = globus_gsi_cert_utils_get_cert_type(x509_context->current_cert,
                                                    &cert_type);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED);
        goto exit;
    }

    if(GLOBUS_GSI_CERT_UTILS_IS_PROXY(cert_type))
    {  
        /* it is a proxy */

        /* a legacy globus proxy may only be followed by another legacy globus
         * proxy or a limited legacy globus_proxy.
         * a limited legacy globus proxy may only be followed by another
         * limited legacy globus proxy
         * a draft compliant proxy may only be followed by another draft
         * compliant proxy
         * a draft compliant limited proxy may only be followed by another draft
         * compliant limited proxy or a draft compliant independent proxy
         */
        
        if((GLOBUS_GSI_CERT_UTILS_IS_GSI_2_PROXY(callback_data->cert_type) &&
            !GLOBUS_GSI_CERT_UTILS_IS_GSI_2_PROXY(cert_type)) ||
           (GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY(callback_data->cert_type) &&
            !GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY(cert_type)) ||
           (GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY(callback_data->cert_type) &&
            !GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY(cert_type)))
        {
            GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_MIXING_DIFFERENT_PROXY_TYPES);
            goto exit;
        }

        if(GLOBUS_GSI_CERT_UTILS_IS_LIMITED_PROXY(callback_data->cert_type) &&
           !(GLOBUS_GSI_CERT_UTILS_IS_LIMITED_PROXY(cert_type) ||
             GLOBUS_GSI_CERT_UTILS_IS_INDEPENDENT_PROXY(cert_type)))
        {
            GLOBUS_GSI_CALLBACK_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_LIMITED_PROXY,
                (_CLS("Can't sign a non-limited, non-independent proxy "
                      "with a limited proxy")));
            x509_context->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
            goto exit;
        }
       
        GLOBUS_I_GSI_CALLBACK_DEBUG_PRINT(2, "Passed proxy test\n");

        callback_data->proxy_depth++;

        if(callback_data->max_proxy_depth != -1 &&
           callback_data->max_proxy_depth < callback_data->proxy_depth)
        {
            GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_PROXY_PATH_LENGTH_EXCEEDED);
            goto exit;
        }
    }

    callback_data->cert_type = cert_type;
  
 exit:

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

/* this function can go away with OpenSSL 0.9.7 and
 * its support for CRL checking - SLANG
 */
globus_result_t
globus_i_gsi_callback_check_revoked(
    X509_STORE_CTX *                    x509_context,
    globus_gsi_callback_data_t          callback_data)
{
    X509_REVOKED *                      revoked = NULL;
    X509_CRL *                          crl = NULL;
    X509_CRL_INFO *                     crl_info = NULL;        
    X509_OBJECT                         x509_object;
    int					contents_freed = 1;
    int                                 i, n;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_i_gsi_callback_check_revoked";
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
                        
    /* 
     * SSLeay 0.9.0 handles CRLs but does not check them. 
     * We will check the crl for this cert, if there
     * is a CRL in the store. 
     * If we find the crl is not valid, we will fail, 
     * as once the sysadmin indicates that CRLs are to 
     * be checked, he best keep it upto date. 
     * 
     * When future versions of SSLeay support this better,
     * we can remove these tests. 
     * 
     * we come through this code for each certificate,
     * starting with the CA's We will check for a CRL
     * each time, but only check the signature if the
     * subject name matches, and check for revoked
     * if the issuer name matches.
     * this allows the CA to revoke its own cert as well. 
     */
    if (X509_STORE_get_by_subject(
            x509_context,
            X509_LU_CRL, 
            X509_get_issuer_name(x509_context->current_cert),
            &x509_object))
    {
	X509 *				issuer;
        time_t                          last_time;
        int                             has_next_time;
        time_t                          next_time;
        EVP_PKEY *                      issuer_key;

	contents_freed = 0;

        crl =  x509_object.data.crl;
        crl_info = crl->crl;

        has_next_time = (crl_info->nextUpdate != NULL);
        
        globus_gsi_cert_utils_make_time(crl_info->lastUpdate, &last_time);
        if (has_next_time) {
            globus_gsi_cert_utils_make_time(crl_info->nextUpdate, &next_time);
        }

        GLOBUS_I_GSI_CALLBACK_DEBUG_PRINT(2, "CRL last Update: ");
        GLOBUS_I_GSI_CALLBACK_DEBUG_FPRINTF(
            2, (globus_i_gsi_callback_debug_fstream,
                "%s", asctime(gmtime(&last_time))));
        GLOBUS_I_GSI_CALLBACK_DEBUG_PRINT(2, "\nCRL next Update: ");
        GLOBUS_I_GSI_CALLBACK_DEBUG_FPRINTF(
            2, (globus_i_gsi_callback_debug_fstream,
                "%s", has_next_time ? asctime(gmtime(&next_time)) : "<not set>" ));
        GLOBUS_I_GSI_CALLBACK_DEBUG_PRINT(2, "\n");

        /* verify the signature on this CRL */
    
	if(x509_context->get_issuer(&issuer, 
				    x509_context, 
				    x509_context->current_cert) <= 0)
	{
            char *                      subject_string;

            subject_string = X509_NAME_oneline(
                X509_get_issuer_name(x509_context->current_cert),
                NULL, 0);
            
	    GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
		result,
		GLOBUS_GSI_CALLBACK_ERROR_INVALID_CRL,
		(_CLS("Couldn't get the issuer certificate of the CRL with "
		 "subject: %s"), subject_string));
            OPENSSL_free(subject_string);
            x509_context->error = X509_V_ERR_CRL_SIGNATURE_FAILURE;
            goto free_X509_object;
	}

        issuer_key = X509_get_pubkey(issuer);
        
        if(issuer_key == NULL)
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_INVALID_CRL,
                (_CLS("Couldn't verify that the available CRL is valid")));
            x509_context->error = X509_V_ERR_CRL_SIGNATURE_FAILURE;
            X509_free(issuer);
            goto free_X509_object;
        }

        X509_free(issuer);

        if (X509_CRL_verify(crl, issuer_key) <= 0)
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_INVALID_CRL,
                (_CLS("Couldn't verify that the available CRL is valid")));
            x509_context->error = X509_V_ERR_CRL_SIGNATURE_FAILURE;
            EVP_PKEY_free(issuer_key);
            goto free_X509_object;
        }

        EVP_PKEY_free(issuer_key);
        
        /* Check date */

        i = X509_cmp_current_time(crl_info->lastUpdate);
        if (i == 0)
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_INVALID_CRL,
                (_CLS("In the available CRL, the thisUpdate field is not valid")));
            x509_context->error = X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD;
            goto free_X509_object;
        }

        if (i > 0)
        {
            GLOBUS_GSI_CALLBACK_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_INVALID_CRL,
                (_CLS("The available CRL is not yet valid")));
            x509_context->error = X509_V_ERR_CRL_NOT_YET_VALID;
            goto free_X509_object;
        }
        
        i = (has_next_time) ? X509_cmp_current_time(crl_info->nextUpdate) : 1;
        if (i == 0)
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_INVALID_CRL,
                (_CLS("In the available CRL, the nextUpdate field is not valid")));
            x509_context->error = X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD;
            goto free_X509_object;
        }
           
        if (i < 0)
        {
            GLOBUS_GSI_CALLBACK_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_INVALID_CRL,
                (_CLS("The available CRL has expired")));
            x509_context->error = X509_V_ERR_CRL_HAS_EXPIRED;
            goto free_X509_object;
        }

        X509_OBJECT_free_contents(&x509_object);
	contents_freed = 1;

        /* check if this cert is revoked */

        n = sk_X509_REVOKED_num(crl_info->revoked);
        for (i = 0; i < n; i++)
        {
            revoked = (X509_REVOKED *) 
		sk_X509_REVOKED_value(crl_info->revoked, i);
        
            if(!ASN1_INTEGER_cmp(
                revoked->serialNumber,
                X509_get_serialNumber(x509_context->current_cert)))
            {
                char *                      subject_string;
                long                        serial;
            
                serial = ASN1_INTEGER_get(revoked->serialNumber);

                subject_string = X509_NAME_oneline(X509_get_subject_name(
                    x509_context->current_cert), NULL, 0);
            
                GLOBUS_GSI_CALLBACK_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CALLBACK_ERROR_REVOKED_CERT,
                    (_CLS("Serial number = %ld (0x%lX) "
		     "Subject=%s"),
                     serial, serial, subject_string));

                x509_context->error = X509_V_ERR_CERT_REVOKED;

                GLOBUS_I_GSI_CALLBACK_DEBUG_FPRINTF(
                    2, (globus_i_gsi_callback_debug_fstream,
                        "revoked %lX\n", 
			ASN1_INTEGER_get(revoked->serialNumber)));

                OPENSSL_free(subject_string);
            }
        }
    }

 free_X509_object:
    
    if(!contents_freed)
    {
	X509_OBJECT_free_contents(&x509_object);
    }

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_i_gsi_callback_check_signing_policy(
    X509_STORE_CTX *                    x509_context,
    globus_gsi_callback_data_t          callback_data)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_i_gsi_callback_check_signing_policy";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
    
    /* Do not need to check self signed certs against ca_policy_file */

    if (X509_NAME_cmp(X509_get_subject_name(x509_context->current_cert),
                      X509_get_issuer_name(x509_context->current_cert)))
    {
        result = globus_i_gsi_callback_check_gaa_auth(
            x509_context, callback_data);

        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_WITH_SIGNING_POLICY);
            goto exit;
        }
    }

 exit:
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_i_gsi_callback_check_gaa_auth(
    X509_STORE_CTX *                    x509_context,
    globus_gsi_callback_data_t          callback_data)
{
    char *                              error_string = NULL;
    char *                              issuer_name = NULL;
    char *                              subject_name = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char *                              ca_policy_file_path = NULL;

#ifndef NO_OLDGAA_API

    oldgaa_rights_ptr                   rights = NULL;
    oldgaa_policy_ptr                   policy_handle = NULL;
    oldgaa_answer_ptr                   detailed_answer = NULL;
    oldgaa_sec_context_ptr              oldgaa_sc = NULL;
    oldgaa_options_ptr                  options = NULL;
    oldgaa_error_code                   policy_result;
    oldgaa_data_ptr                     policy_db = OLDGAA_NO_DATA;
    uint32                              minor_status;

#else /* Von's code */

    int                                 policy_result;

#endif /* NO_OLDGAA_API */

    static char *                       _function_name_ =
        "globus_i_gsi_callback_check_gaa_auth";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;
    
    subject_name = X509_NAME_oneline(
        X509_get_subject_name(x509_context->current_cert),
        NULL,
        0);
    issuer_name = X509_NAME_oneline(
        X509_get_issuer_name(x509_context->current_cert),
        NULL,
        0);
    
#ifndef NO_OLDGAA_API
 
    result =
        GLOBUS_GSI_SYSCONFIG_GET_SIGNING_POLICY_FILENAME(
            X509_get_issuer_name(x509_context->current_cert),
            callback_data->cert_dir,
            &ca_policy_file_path);

    if(result != GLOBUS_SUCCESS)
    {
        ca_policy_file_path = NULL;
        GLOBUS_GSI_CALLBACK_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_WITH_SIGNING_POLICY);
        goto exit;
    }

    if(ca_policy_file_path == NULL)
    {
        /* signing policy file doesn't exist or can't be read */
            
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_WITH_SIGNING_POLICY,
            (_CLS("The signing policy file doesn't exist or can't be read")));
        x509_context->error = X509_V_ERR_APPLICATION_VERIFICATION;
        goto exit;
    }

    GLOBUS_I_GSI_CALLBACK_DEBUG_FPRINTF(
        2, (globus_i_gsi_callback_debug_fstream,
            "ca_policy_file_path is %s\n", ca_policy_file_path));

    globus_mutex_lock(&globus_l_gsi_callback_oldgaa_mutex);

    if(oldgaa_globus_initialize(&oldgaa_sc,
                                &rights,
                                &options,
                                &policy_db,
                                issuer_name,
                                subject_name,
                                ca_policy_file_path)
       != OLDGAA_SUCCESS) 
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_OLD_GAA,
            (_CLS("Couldn't initialize OLD GAA: "
             "Minor status=%d"), policy_db->error_code));
        x509_context->error = X509_V_ERR_APPLICATION_VERIFICATION;
        globus_mutex_unlock(&globus_l_gsi_callback_oldgaa_mutex);
        goto exit;
    }
    
    if(oldgaa_get_object_policy_info(
        &minor_status,  
        OLDGAA_NO_DATA,
        policy_db,
        oldgaa_globus_policy_retrieve,
        &policy_handle) != OLDGAA_SUCCESS)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_OLD_GAA,
            (_CLS("Could not get policy info: "
             "Minor status=%d"), minor_status));
        x509_context->error =  X509_V_ERR_APPLICATION_VERIFICATION;
        globus_mutex_unlock(&globus_l_gsi_callback_oldgaa_mutex);
        goto exit;
    }
    
    policy_result = oldgaa_check_authorization(
        &minor_status,
        oldgaa_sc,
        policy_handle,
        rights,
        options,
        &detailed_answer);
    
    if (!detailed_answer)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_OLD_GAA,
            (_CLS("Error checking certificate with subject %s"
             "against signing policy file %s"),
             subject_name == NULL ? "NULL" : subject_name,
             ca_policy_file_path == NULL ? "NULL" : ca_policy_file_path));
        x509_context->error = X509_V_ERR_INVALID_PURPOSE; 
        
        oldgaa_globus_cleanup(&oldgaa_sc,
                              &rights,
                              options,
                              &detailed_answer,  
                              policy_db,
                              NULL);
        globus_mutex_unlock(&globus_l_gsi_callback_oldgaa_mutex);
        goto exit;
    }

    if(GLOBUS_I_GSI_CALLBACK_DEBUG(2))
    {
            
        fprintf(globus_i_gsi_callback_debug_fstream,
                "oldgaa result: %d(0 yes, 1 no, -1 maybe)\n", policy_result);
    
        if(detailed_answer) 
        { 
            fprintf(globus_i_gsi_callback_debug_fstream,
                    "\nprint detailed answer:\n\n");
            
#ifndef WIN32
            if(detailed_answer->rights)
            {
                oldgaa_globus_print_rights(detailed_answer->rights);
            }
#endif
        }
    }
    
    if (policy_handle)
    {
        oldgaa_release_principals(&minor_status, &policy_handle);
    }
    
    oldgaa_globus_cleanup(&oldgaa_sc,
                          &rights,
                          options,
                          &detailed_answer,  
                          policy_db,
                          NULL);

    globus_mutex_unlock(&globus_l_gsi_callback_oldgaa_mutex);
    
#else /* Von's code */
    
/* #warning this doesn't appear to be defined anywhere within the gsi code */
    policy_result = ca_policy_file_check_signature(issuer_name,
                                                   subject_name,
                                                   &error_string,
                                                   callback_data->cert_dir);
    
#endif /* #ifndef NO_OLDGAA_API */
    
    OPENSSL_free(subject_name);
    subject_name = NULL;
    OPENSSL_free(issuer_name);
    issuer_name = NULL;
    
    if (policy_result != 0)
    {
        GLOBUS_GSI_CALLBACK_ERROR_RESULT(
            result,
            GLOBUS_GSI_CALLBACK_ERROR_OLD_GAA,
            (_CLS("CA policy violation: %s"), 
             error_string ? error_string : "<no reason given>"));
        x509_context->error = X509_V_ERR_INVALID_PURPOSE; 
        goto exit;
    }

 exit:

    if(ca_policy_file_path)
    {
        globus_libc_free(ca_policy_file_path);
    }

    if(error_string)
    {
        globus_libc_free(error_string);
    }

    if(issuer_name)
    {
        OPENSSL_free(issuer_name);
    }

    if(subject_name)
    {
        OPENSSL_free(subject_name);
    }

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_i_gsi_callback_check_critical_extensions(
    X509_STORE_CTX *                    x509_context,
    globus_gsi_callback_data_t          callback_data)
{
    ASN1_OBJECT *                       extension_object = NULL;
    X509_EXTENSION *                    extension = NULL;
    PROXYCERTINFO *                     proxycertinfo = NULL;
    PROXYPOLICY *                       policy = NULL;
    int                                 nid;
    int                                 pci_NID;
    int                                 pci_old_NID;
    int                                 critical_position = -1;
    long                                path_length;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_i_gsi_callback_check_critical_extensions";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    pci_NID = OBJ_sn2nid(PROXYCERTINFO_SN);
    pci_old_NID = OBJ_sn2nid(PROXYCERTINFO_OLD_SN);

    while((critical_position = 
          X509_get_ext_by_critical(x509_context->current_cert, 
                                   1, critical_position)) >= 0)
    {
        extension = X509_get_ext(x509_context->current_cert, critical_position);
        if(!extension)
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED,
                (_CLS("Couldn't get critical extension of "
                 "certificate being verified")));
            x509_context->error = X509_V_ERR_CERT_REJECTED;
            goto exit;
        }

        extension_object = X509_EXTENSION_get_object(extension);
        if(!extension_object)
        {
            GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                result,
                GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED,
                (_CLS("Couldn't get object form of X509 extension for "
                 "the certificate being verified.")));
            x509_context->error = X509_V_ERR_CERT_REJECTED;
            goto exit;
        }

        nid = OBJ_obj2nid(extension_object);

        if(nid == pci_NID || nid == pci_old_NID)
        {
            /* check for path length constraint */

            if((proxycertinfo = X509V3_EXT_d2i(extension)) == NULL)
            {
                GLOBUS_GSI_CALLBACK_OPENSSL_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED,
                    (_CLS("Can't convert DER encoded PROXYCERTINFO "
                     "extension to internal form")));
                x509_context->error = X509_V_ERR_CERT_REJECTED;
                goto exit;
            }

            path_length = PROXYCERTINFO_get_path_length(proxycertinfo);

            /* ignore negative values */
            
            if(path_length > -1)
            {
                if(callback_data->max_proxy_depth == -1 ||
                   callback_data->max_proxy_depth >
                   callback_data->proxy_depth + path_length)
                {
                    callback_data->max_proxy_depth =
                        callback_data->proxy_depth + path_length;
                }
            }

            policy = PROXYCERTINFO_get_policy(proxycertinfo);
        }
        
        if((nid != NID_basic_constraints &&
            nid != NID_key_usage &&
            nid != NID_ext_key_usage &&
            nid != NID_netscape_cert_type &&
            nid != NID_subject_key_identifier &&
            nid != NID_authority_key_identifier &&
            nid != pci_NID &&
            nid != pci_old_NID) || (policy && policy->policy))
        {
            if(callback_data->extension_cb)
            {
                if(!callback_data->extension_cb(callback_data, extension))
                {
                    GLOBUS_GSI_CALLBACK_ERROR_RESULT(
                        result,
                        GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED,
                        (_CLS("Certificate has unknown critical extension "
                         "with numeric ID: %d, "
                         "rejected during validation"), nid));
                    x509_context->error = X509_V_ERR_CERT_REJECTED;
                    goto exit;
                }
            }
            else
            {
                GLOBUS_GSI_CALLBACK_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED,
                    (_CLS("Certificate has unknown critical extension, "
                     "with numeric ID: %d, "
                     "rejected during validation"), nid));
                x509_context->error = X509_V_ERR_CERT_REJECTED;
                goto exit;
            }
        }
    }

 exit:

    if(proxycertinfo != NULL)
    {
        PROXYCERTINFO_free(proxycertinfo);
    }

    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_i_gsi_callback_check_path_length(
    X509_STORE_CTX *                    x509_context,
    globus_gsi_callback_data_t          callback_data)
{
    X509 *                              cert = NULL;
    globus_result_t                     result  = GLOBUS_SUCCESS;
    int                                 i;
    
    static char *                       _function_name_ =
        "globus_i_gsi_callback_check_path_length";

    GLOBUS_I_GSI_CALLBACK_DEBUG_ENTER;

    /*
     * We ignored any path length restriction errors because
     * OpenSSL was counting proxies against the limit.
     * If we are on the last cert in the chain, we 
     * know how many are proxies, so we can do the 
     * path length check now. 
     * See x509_vfy.c check_chain_purpose
     * all we do is substract off the proxy_depth 
     */

    if(x509_context->current_cert == x509_context->cert)
    {
        for (i = 0; i < sk_X509_num(x509_context->chain); i++)
        {
            cert = sk_X509_value(x509_context->chain, i);

            GLOBUS_I_GSI_CALLBACK_DEBUG_FPRINTF(
                3, (globus_i_gsi_callback_debug_fstream,
                    "pathlen=:i=%d x=%p pl=%ld\n",
                    i, cert, cert->ex_pathlen));

            if (((i - callback_data->proxy_depth) > 1) && 
                (cert->ex_pathlen != -1) &&
                ((i - callback_data->proxy_depth) > (cert->ex_pathlen + 1)) &&
                (cert->ex_flags & EXFLAG_BCONS))
            {
                x509_context->current_cert = cert; /* point at failing cert */
                GLOBUS_GSI_CALLBACK_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_CALLBACK_ERROR_VERIFY_CRED,
                    (_CLS("Path length of proxy cert has exceeded the limit")));
            }
        }
    }
    
    GLOBUS_I_GSI_CALLBACK_DEBUG_EXIT;
    return result;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
