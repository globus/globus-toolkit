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
 * @file import_sec_context.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/ssl2.h"
#include "ssl_locl.h"
#include <string.h>

/*
 * inorder to define a number of low level ssl routines
 * we need to include non installed header
 * #include <ssl_locl.h>
 * We will define the four routines here. 
 */

/**
 * @name Import Security Context
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * GSSAPI routine to import the security context based
 * on the input token.
 * See: <draft-ietf-cat-gssv2-cbind-04.txt>
 *
 */
OM_uint32 
GSS_CALLCONV gss_import_sec_context(
    OM_uint32 *                         minor_status ,
    const gss_buffer_t                  interprocess_token,
    gss_ctx_id_t *                      context_handle_P) 
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status = GSS_S_COMPLETE;
    globus_result_t                     local_result;
    gss_ctx_id_desc *                   context = GSS_C_NO_CONTEXT;
    SSL *                               ssl_handle = NULL;
    SSL_SESSION *                       session = NULL;
    SSL_CIPHER *                        cipher;
    STACK_OF(SSL_CIPHER) *              ciphers;
    BIO *                               bp = NULL;
    X509 *                              peer_cert;
    unsigned char                       int_buffer[4];
    long                                length;
    long                                version;
    gss_cred_usage_t                    cred_usage;
    long                                Time=time(NULL);
    int                                 index;
    int                                 res;
    int                                 ssl_result;
    static char *                       _function_name_ =
        "gss_import_sec_context";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

#ifdef WIN32
        major_status = GSS_S_UNAVAILABLE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_UNSUPPORTED,
            (_GGSL("This function does not currently support the "
             "Windows platform")));
        goto exit;
#endif

    /* module activation if not already done by calling
     * globus_module_activate
     */
    
    globus_thread_once(
        &once_control,
        globus_l_gsi_gssapi_activate_once);

    if (interprocess_token == NULL || 
        interprocess_token == GSS_C_NO_BUFFER || 
        context_handle_P == NULL)
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
            (_GGSL("The inter-process token is not valid")));
        goto exit;
    }

    /* Open mem bio for reading the session */
    if ((bp = BIO_new(BIO_s_mem())) == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Couldn't initialize BIO for importing context")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }
        
    /* write the input token to the BIO so we can read it back */
    BIO_write(bp, interprocess_token->value, interprocess_token->length);

    /* get some of our gss specific info */
    /* get version */
    BIO_read(bp, (char *) int_buffer, 4); 
    N2L(int_buffer, version);
    if (version > GLOBUS_I_GSI_GSSAPI_IMPL_VERSION)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Trying to import version %d of a security context token "
             "only version %d is supported by this implementation"),
             version, GLOBUS_I_GSI_GSSAPI_IMPL_VERSION));
        goto exit;
    }

    BIO_read(bp, (char *) int_buffer, 4); /* get cred_usage */
    N2L(int_buffer, cred_usage);

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        2, (globus_i_gsi_gssapi_debug_fstream, "CredUsage=%d\n", cred_usage));

    /*
     * We know we are using SSLv3, and which ciphers
     * are available. We could get this from the 
     * imported session. 
     */

    major_status =
        globus_i_gsi_gss_create_and_fill_context(&local_minor_status,
                                                 &context,
                                                 GSS_C_NO_CREDENTIAL,
                                                 cred_usage,
                                                 0);

    if (GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CONTEXT);
        goto exit;
    }

    ssl_handle = context->gss_ssl;

    /*
     * We need to do what the s3_srvr.c ssl_accept would do
     * during the initial handshake to get the SSL 
     * control blocks setup. But we also need to 
     * have them setup so the client does not know
     * we have started over. 
     * This is more the a renegociate, as the client does not
     * know we have transfered the context to another process. 
     */ 

    RAND_add((unsigned char *) &Time, sizeof(Time),
             .5 /* .5 byte or 4 bits of entrophy */);

    ERR_clear_error();

    if (!SSL_in_init(ssl_handle) || SSL_in_before(ssl_handle))
    {
        SSL_clear(ssl_handle);
    }

    /* we do this here, and later, since SSLeay-0.9.0 has a problem*/
    res = ssl3_setup_buffers(ssl_handle);
    if (!res)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Couldn't initialize buffers in SSL handle")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    res = ssl_init_wbio_buffer(ssl_handle, 0);
    if (!res)
    {  
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Couldn't initialize write bio buffer in SSL handle")));
        major_status = GSS_S_FAILURE;
        goto exit; 
    } 

    session = d2i_SSL_SESSION_bio(bp, NULL);

    if (!session)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Couldn't initialize SSL_SESSION handle")));
        major_status = GSS_S_NO_CONTEXT;
        goto exit;
    }
        
    /* get number of peer certs  (version 1 has 0 or 1) */
    BIO_read(bp, (char *) int_buffer, 4);
    N2L(int_buffer, length);

    if(length > 0)
    {
        int                             index;
        STACK_OF(X509) *                cert_chain = sk_X509_new_null();

        /* import the peer's cert chain */
        for(index = 0; index < length; index++)
        {
            peer_cert = d2i_X509_bio(bp, NULL);
            
            if (!peer_cert)
            {
                major_status = GSS_S_NO_CONTEXT;
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status, major_status,
                    (_GGSL("Couldn't read DER encoded peer cert from BIO")));
                sk_X509_pop_free(cert_chain, X509_free);        
                goto exit;
            }
            
            sk_X509_push(cert_chain, peer_cert);
        }

        
        local_result = 
            globus_gsi_callback_set_cert_depth(context->callback_data,
                                               length);
        if(local_result)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
            major_status = GSS_S_FAILURE;
            sk_X509_pop_free(cert_chain, X509_free);        
            goto exit;
        }

        local_result = 
            globus_gsi_callback_set_cert_chain(context->callback_data,
                                               cert_chain);

        sk_X509_pop_free(cert_chain, X509_free);
        
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
    }

    /* need to set cipher from cipher_id in the session */
    ciphers = SSL_get_ciphers(ssl_handle);

    session->cipher = NULL;
    for (index = 0; index < sk_SSL_CIPHER_num(ciphers); index++)
    {
        cipher = sk_SSL_CIPHER_value(ciphers, index);
        if (cipher->id == session->cipher_id)
        {
            session->cipher = cipher;
            break;
        }
    }
    
    if (!(session->cipher))
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_NO_CIPHER,
            (_GGSL("Attempt to set the session cipher failed")));
        goto exit;
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT_OBJECT(3, SSL_SESSION, session);
        
    SSL_set_session(ssl_handle, session);
        
    ssl_result = ssl3_setup_buffers(ssl_handle);
    if (!ssl_result)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Couldn't setup buffers in SSL handle")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    major_status = globus_i_gsi_gss_SSL_read_bio(
        &local_minor_status,
        context,
        bp);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL);
        goto exit;
    }

    major_status = globus_i_gsi_gss_retrieve_peer(&local_minor_status,
                                                  context, cred_usage);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL);
        goto exit;
    }

    ssl_handle->new_session = 0;
    ssl_handle->init_num = 0;
    ssl_handle->in_handshake = 0;
    
    *context_handle_P = context;
    context = GSS_C_NO_CONTEXT;

exit:

    if(session)
    {
        SSL_SESSION_free(session);
    }
    
    if(bp)
    {
        BIO_free(bp);
    }

    if (context != GSS_C_NO_CONTEXT)
    {
        gss_delete_sec_context(&local_minor_status,
                               (gss_ctx_id_t *) &context,
                               GSS_C_NO_BUFFER);
    }


    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */
