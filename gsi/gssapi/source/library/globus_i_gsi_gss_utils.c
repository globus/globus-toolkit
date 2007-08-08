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
 * @file globus_i_gsi_gss_utils.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */

static char *rcsid = "$Id$";

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"
#include "globus_gsi_credential.h"
#include "globus_gsi_callback.h"
#include "globus_gsi_callback_constants.h"
#include "globus_gsi_system_config.h"
#include "openssl/ssl3.h"

#include <string.h>
#include <stdlib.h>

#include "ssl_locl.h"

#ifdef WIN32
#define strcasecmp stricmp
#define strncasecmp strnicmp
#endif

extern int                              globus_i_gsi_gssapi_debug_level;
extern FILE *                           globus_i_gsi_gssapi_debug_fstream;

/**
 * @anchor globus_i_gsi_gss_utils
 * @mainpage Globus GSI GSS-API
 *
 * The globus_i_gsi_gss_utils code is used by the other 
 * gss api code to perform internal functions such as
 * initializing objects and performing the SSL handshake
 */

/**
 * @name Copy GSS API Name
 * @ingroup globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Copy a gss_name_t structure, including the group information
 * and the name's OID.
 *
 * @param minor_status
 *        This minor status contains the resulting error
 *        if an error occurred.  The error should be cast
 *        to a globus_result_t before accessing
 * @param output
 *        Target name.
 * @param input
 *        Source name.
 * @return
 *        GSS_S_COMPLETE - successful copy
 *        GSS_F_FAILURE - failed to copy
 */
OM_uint32 
globus_i_gsi_gss_copy_name_to_name(
    OM_uint32 *                         minor_status,
    gss_name_desc **                    output,
    const gss_name_desc *               input)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_name_desc *                     output_name;
    X509_NAME *                         x509n = NULL;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_copy_name_to_name";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    output_name = (gss_name_desc *) malloc(sizeof(gss_name_desc));

    if (output_name == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_BAD_NAME;
        goto exit;
    }
    
    if(input->x509n != NULL)
    {
        x509n = X509_NAME_dup(input->x509n);
        if (x509n == NULL)
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME,
                (_GGSL("Couldn't copy X509_NAME struct")));
            major_status = GSS_S_BAD_NAME;
            goto exit;
        }
    }

    output_name->name_oid = input->name_oid;
    output_name->x509n = x509n;
    
    *output = output_name;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;
    major_status = GSS_S_COMPLETE;

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;    
    return major_status;
}
/* @} */

/**
 * @name Init Security Context
 * @ingroup globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Initialize a security context structure.
 *
 * Called by the GSSAPI functions @ref gss_init_sec_context 
 * and @ref gss_accept_sec_context to 
 * setup the initial context. This includes establishing the
 * SSL session control blocks.
 *
 * @param minor_status
 *        A mechanism specific status code.  This is cast from a 
 *        globus_result_t which will either be GLOBUS_SUCCESS or
 *        a globus error object ID.  If not GLOBUS_SUCCESS, the
 *        globus_error_t object can be retrieved by doing:
 *        globus_error_get((globus_result_t)*minor_status)
 * 
 * @param context_handle_P
 *        
 * @param cred_handle
 * @param cred_usage
 * @param req_flags
 * @return
 */
OM_uint32
globus_i_gsi_gss_create_and_fill_context(
    OM_uint32 *                         minor_status,
    gss_ctx_id_desc **                  context_handle_P,
    gss_cred_id_desc *                  cred_handle,
    const gss_cred_usage_t              cred_usage,
    OM_uint32                           req_flags)
{
    globus_result_t                     local_result;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_ctx_id_desc*                    context = NULL;
    int                                 cb_index;
    OM_uint32                           local_minor_status;
    char *                              certdir = NULL;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_create_and_fill_context";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = GLOBUS_SUCCESS;

    /* initialize the context handle */
    if(*context_handle_P == GSS_C_NO_CONTEXT)
    {
        context = (gss_ctx_id_desc*) 
            malloc(sizeof(gss_ctx_id_desc));
        if (context == NULL)
        {
            GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
        
        memset(context, (int)NULL, sizeof(gss_ctx_id_desc));
        *context_handle_P = context;
        context->ctx_flags = 0;
    }
    else
    {
        context = *context_handle_P;
    }
    
    context->req_flags = req_flags;
    context->gss_state = GSS_CON_ST_HANDSHAKE;
    context->delegation_state = GSS_DELEGATION_START;
    context->locally_initiated = (cred_usage == GSS_C_INITIATE);
    context->ctx_flags |= GSS_I_CTX_INITIALIZED;
    globus_mutex_init(&context->mutex, NULL);

    /* initialize the peer_cred_handle */
    context->peer_cred_handle = malloc(sizeof(gss_cred_id_desc));
    if(context->peer_cred_handle == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto free_context;
    }

    memset(context->peer_cred_handle, (int) NULL, sizeof(gss_cred_id_desc));
    
    local_result = globus_gsi_cred_handle_init(
        &context->peer_cred_handle->cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result, 
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto free_peer_cred;
    }

    if((context->peer_cred_handle->globusid = 
        malloc(sizeof(gss_name_desc))) == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto free_peer_cred_handle;
    }

    memset(context->peer_cred_handle->globusid, 
           (int) NULL, 
           sizeof(gss_name_desc));

    /* initialize the proxy_handle */
    local_result = globus_gsi_proxy_handle_init(& context->proxy_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
        major_status = GSS_S_FAILURE;
        goto free_globusid;
    }

    /* initialize the callback data */
    if(context->callback_data == NULL)
    {
        local_result = globus_gsi_callback_data_init(&context->callback_data);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
            major_status = GSS_S_FAILURE;
            goto free_proxy_handle;
        }
    }
    
    /* if the extension_oids are set, then we set them in the callback data */
    if(context->extension_oids)
    {
        local_result = globus_gsi_callback_set_extension_oids(
            context->callback_data,
            (void *) context->extension_oids);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
    }
    
    /* get the local credential */
    if (cred_handle == GSS_C_NO_CREDENTIAL || (req_flags & GSS_C_ANON_FLAG))
    {
        if(req_flags & GSS_C_ANON_FLAG)
        {
            major_status = globus_i_gsi_gss_create_anonymous_cred(
                &local_minor_status, 
                (gss_cred_id_t *) &context->cred_handle, 
                cred_usage);
        }
        else
        {
            major_status = gss_acquire_cred(
                &local_minor_status, 
                GSS_C_NO_NAME, 
                GSS_C_INDEFINITE,
                GSS_C_NO_OID_SET, 
                cred_usage, 
                (gss_cred_id_t *) &context->cred_handle, 
                NULL, 
                NULL);
        }
        
        if (GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            goto free_callback_data;
        }

        context->cred_obtained = 1;
    }
    else
    {
        context->cred_obtained = 0;
        context->cred_handle = cred_handle;
    }

    /* set the cert_dir in the callback data */
    local_result = 
        GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&certdir);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto free_callback_data;
    }

    if (certdir)
    {
        local_result = globus_gsi_callback_set_cert_dir(
            context->callback_data, 
            certdir);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto free_cert_dir;
        }
    }
    else
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, 
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL,
            (_GGSL("The cert_dir parameter in "
             "the credential handle needs to bet set")));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    if(certdir)
    {
        free(certdir);
        certdir = NULL;
    }

    context->gss_ssl = SSL_new(context->cred_handle->ssl_context);

    if (context->gss_ssl == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status, 
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CONTEXT,
            (_GGSL("Couldn't create SSL object for handshake")));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    if (globus_i_gsi_gssapi_force_tls)
    {
	/* GLOBUS_GSSAPI_FORCE_TLS defined in environment. */
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(
            2, "Forcing TLS.\n");
	SSL_set_ssl_method(context->gss_ssl, TLSv1_method());
    }
    else if (cred_usage == GSS_C_INITIATE)
    {
	/* For backward compatibility.  Older GSI GSSAPI accepters
	   will fail if we try to negotiate TLSv1, so stick with SSLv3
	   when initiating to be safe. */
	SSL_set_ssl_method(context->gss_ssl, SSLv3_method());
    }
    else
    {
	/* Accept both SSLv3 and TLSv1. */
	SSL_set_ssl_method(context->gss_ssl, SSLv23_method());
    }
    /* Never use SSLv2. */
    SSL_set_options(context->gss_ssl, 
                    SSL_OP_NO_SSLv2 |
                    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

    local_result = globus_gsi_callback_get_SSL_callback_data_index(&cb_index);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL);
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }
    
    if(!SSL_set_ex_data(context->gss_ssl, 
                        cb_index,
                        (char *) &context->callback_data))
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
            (_GGSL("Couldn't set the callback data as the external data "
             "of the SSL object")));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    /*
     * If initiate and caller did not set the GSS_C_CONF_FLAG
     * then add the NULL ciphers to beginning.
     */
    if (!(context->req_flags & GSS_C_CONF_FLAG))
    {
        if(!SSL_set_cipher_list(context->gss_ssl,
                                "eNULL:ALL:!ADH:RC4+RSA:+SSLv2"))
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                (_GGSL("Couldn't set the cipher cert order in the SSL object")));
            major_status = GSS_S_FAILURE;
            goto free_cert_dir;   
        }
    }
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        3, (globus_i_gsi_gssapi_debug_fstream,
            "SSL is at %p\n", context->gss_ssl));
    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        3, (globus_i_gsi_gssapi_debug_fstream,
            "SSL_set_app_data to callback data %p\n", context->callback_data));
    
    if ((context->gss_rbio = BIO_new(BIO_s_mem())) == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
            (_GGSL("Can't initialize read BIO for SSL handle")));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    if ((context->gss_wbio = BIO_new(BIO_s_mem())) == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
            (_GGSL("Can't initialize write BIO for SSL handle")));
        major_status = GSS_S_FAILURE;
        goto free_rbio;
    }

    if ((context->gss_sslbio = BIO_new(BIO_f_ssl())) == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
            (_GGSL("Can't create SSL bio")));
        major_status = GSS_S_FAILURE;
        goto free_wbio;
    }
    if ( cred_usage == GSS_C_INITIATE)
    {
        SSL_set_connect_state(context->gss_ssl);
    }
    else
    {
        SSL_set_accept_state(context->gss_ssl);
    }
    
    SSL_set_bio(context->gss_ssl,
                context->gss_rbio,
                context->gss_wbio);
    
    BIO_set_ssl(context->gss_sslbio, 
                context->gss_ssl, 
                BIO_NOCLOSE);
    
    {
        char buff[256];
        int i;
        STACK *sk;
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(
            2, "Ciphers available:\n");
        sk=(STACK *)SSL_get_ciphers(context->gss_ssl);
        for (i=0; i<sk_num(sk); i++)
        {
            SSL_CIPHER_description((SSL_CIPHER *)sk_value(sk,i),
                                   buff,256);
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                3, (globus_i_gsi_gssapi_debug_fstream, buff));
        }
    }

    if(!context->extension_oids)
    {
        major_status = gss_create_empty_oid_set(
            &local_minor_status,
            (gss_OID_set *) &context->extension_oids);
        
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_OID);
            goto exit;
        }
    }
    
    goto exit;

 free_wbio:

    if(context->gss_wbio)
    {
        BIO_free(context->gss_wbio);
    }

 free_rbio:

    if(context->gss_rbio)
    {
        BIO_free(context->gss_rbio);
    }

 free_cert_dir:
    
    if(certdir)
    {
        globus_libc_free(certdir);
    }

    if(context->cred_handle && context->cred_obtained)
    {
        gss_release_cred(&local_minor_status, 
                         (gss_cred_id_t *) &context->cred_handle);
    }

 free_callback_data:

    if(context->callback_data)
    {
        globus_gsi_callback_data_destroy(context->callback_data);
    }

 free_proxy_handle:
    
    if(context->proxy_handle)
    {
        globus_gsi_proxy_handle_destroy(context->proxy_handle);
    }

 free_globusid:

    if(context->peer_cred_handle->globusid)
    {
        globus_libc_free(context->peer_cred_handle->globusid);
    }

 free_peer_cred_handle:

    if(context->peer_cred_handle->cred_handle)
    {
        globus_gsi_cred_handle_destroy(context->peer_cred_handle->cred_handle);
    }

 free_peer_cred:

    if(context->peer_cred_handle)
    {
        globus_libc_free(context->peer_cred_handle);
    }

 free_context:

    if(context)
    {
        globus_libc_free(context);
        *context_handle_P = NULL;
    }

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Put Token
 * @group globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * 
 * Called by init_sec_context and accept_sec_context.
 * An input token is placed in the SSL read BIO
 * 
 * @param minor_status
 * @param context_handle
 * @param bio
 * @param input_token
 *
 * @return
 */
OM_uint32
globus_i_gsi_gss_put_token(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_desc *             context_handle,
    BIO *                               bio,
    const gss_buffer_t                  input_token)
{
    BIO *                               read_bio;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_put_token";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    if(input_token == GSS_C_NO_BUFFER)
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
            (_GGSL("The input token is NULL (GSS_C_NO_BUFFER)\n")));
        goto exit;        
    }

    if(bio)
    {
        read_bio = bio;
    }
    else
    {
        read_bio = context_handle->gss_rbio;
    }

    /* add any input data onto the input for the SSL BIO */

    if (input_token->length > 0)
    {
        BIO_write(read_bio,
                  input_token->value,
                  input_token->length);

        if(GLOBUS_I_GSI_GSSAPI_DEBUG(3))
        {
            BIO *                       debug_bio;
            fprintf(globus_i_gsi_gssapi_debug_fstream,
                    "input token: length = %u\n"
                    "              value  = \n",
                    input_token->length);
        
            debug_bio = BIO_new_fp(globus_i_gsi_gssapi_debug_fstream, 
                                   BIO_NOCLOSE);
            BIO_dump(debug_bio, 
                     input_token->value,
                     input_token->length);
            BIO_free(debug_bio);
        }
    }
    else 
    {
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            3, (globus_i_gsi_gssapi_debug_fstream,
                "input_token: length = %u\n", input_token->length));

        major_status = GSS_S_DEFECTIVE_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
            (_GGSL("The input token has an invalid length of: %u\n"), 
             input_token->length));
        goto exit;
    }

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Get Token
 * @group globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Get the token from the context handle
 *
 * @param minor_status
 * @param context_handle
 * @param bio
 * @param output_token
 * 
 * @return
 */
OM_uint32
globus_i_gsi_gss_get_token(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_desc*              context_handle,
    BIO *                               bio,
    const gss_buffer_t                  output_token)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    BIO *                               write_bio;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_get_token";
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if(bio)
    {
        write_bio = bio;
    }
    else
    {
        write_bio = context_handle->gss_wbio;
    }
    
    /* make out token */
    output_token->length = BIO_pending(write_bio);
    if (output_token->length > 0)
    {
        int                             len = 0;
        int                             rc;

        output_token->value = (char *) malloc(output_token->length);
        if (output_token->value == NULL)
        {
            output_token->length = 0;
            GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        while(len < output_token->length)
        { 
            
            rc = BIO_read(write_bio,
                          ((char *) output_token->value) + len,
                          output_token->length - len);
            if(rc > 0)
            {
                len += rc;
            }
            else
            {
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status, 
                    GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                    (_GGSL("Error reading token from BIO: %d\n"), rc));
                major_status = GSS_S_FAILURE;
                goto exit;
            }
        }            

        if(GLOBUS_I_GSI_GSSAPI_DEBUG(3))
        {
            BIO *                       debug_bio;
            fprintf(globus_i_gsi_gssapi_debug_fstream,
                    "output token: length = %u\n"
                    "              value  = \n",
                    output_token->length);
        
            debug_bio = BIO_new_fp(globus_i_gsi_gssapi_debug_fstream, 
                                   BIO_NOCLOSE);
            BIO_dump(debug_bio, 
                     output_token->value,
                     output_token->length);
            BIO_free(debug_bio);
        }
    }
    else
    {
        output_token->value = NULL;
    }

exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Handshake
 * @ingroup globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Do the SSL handshake
 *
 * Called by init_sec_context and accept_sec_context.
 * the BIO_handshake is done again which causes the SSL 
 * session to start or continue its handshake process,
 * and when it waits return. 
 *
 * @param minor_status
 * @param context_handle
 *
 * @return 
 */
OM_uint32    
globus_i_gsi_gss_handshake(
    OM_uint32 *                         minor_status,
    gss_ctx_id_desc *                   context_handle)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_result_t                     local_result = GLOBUS_SUCCESS;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    int rc;
    
    static char *                       _function_name_ =
        "globus_i_gsi_gss_handshake";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    ERR_clear_error();
    /*
     * do the BIO_do_handshake which may produce output,
     * and endup waiting for input.
     * when completed without error, connection established
     */
    rc = BIO_do_handshake(context_handle->gss_sslbio);
    if (rc <= 0) {
        if (!BIO_should_retry(context_handle->gss_sslbio) || 
            !BIO_should_read(context_handle->gss_sslbio)) {
            
            /* problem! */
            
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "disp=%d,level=%d,desc=%d,left=%d\n",
                    context_handle->gss_ssl->s3->alert_dispatch,
                    context_handle->gss_ssl->s3->send_alert[0],
                    context_handle->gss_ssl->s3->send_alert[1],
                    context_handle->gss_ssl->s3->wbuf.left));
			
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "SSL_get_error = %d\n",
                    SSL_get_error(context_handle->gss_ssl, rc)));

            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream, 
                    "shutdown=%d\n",
                    SSL_get_shutdown(context_handle->gss_ssl)));

            /* checks for ssl alert 42 */
            if (ERR_peek_error() == 
                ERR_PACK(ERR_LIB_SSL,SSL_F_SSL3_READ_BYTES,
                         SSL_R_SSLV3_ALERT_BAD_CERTIFICATE))
            {
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_REMOTE_CERT_VERIFY_FAILED,
                    (_GGSL("Couldn't verify the remote certificate")));
            }
            else
            {
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_HANDSHAKE,
                    (_GGSL("Couldn't do ssl handshake")));
            }

            major_status = GSS_S_DEFECTIVE_CREDENTIAL;
        }
    }

    local_result = globus_gsi_callback_get_error(context_handle->callback_data,
                                                 &result);

    if(local_result != GLOBUS_SUCCESS)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
        goto exit;
    }
    
    if(result != GLOBUS_SUCCESS && GSS_ERROR(major_status))
    {
        result = globus_i_gsi_gssapi_error_join_chains_result(
            (globus_result_t) *minor_status,
            result);
        
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, result,
            GLOBUS_GSI_GSSAPI_ERROR_REMOTE_CERT_VERIFY_FAILED);
        goto exit;
    }
    else if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, *minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_REMOTE_CERT_VERIFY_FAILED);
        goto exit;
    }
    else if(result != GLOBUS_SUCCESS)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, result,
            GLOBUS_GSI_GSSAPI_ERROR_REMOTE_CERT_VERIFY_FAILED);
        goto exit;
    }

    if (!GSS_ERROR(major_status)) {
        if (rc > 0)
        {
            SSL_CIPHER *                current_cipher;
            major_status = GSS_S_COMPLETE; 

            /*
             * Set  GSS_C_CONF_FLAG if cipher uses encryption
             * which is at least 56 bit. SSL defines a number
             * of different levels, we need to map to a single GSS
             * flag. See the s3_lib.c for list of ciphers. 
             * This could be changed to SSL_MEDIUM or SSL_HIGH 
             * if a site wants higher protection. 
             */

            current_cipher = SSL_get_current_cipher(context_handle->gss_ssl);
            
            if ((current_cipher->algo_strength & SSL_STRONG_MASK) >= SSL_LOW) 
            {
                context_handle->ret_flags |= GSS_C_CONF_FLAG;
            }

            /* DEBUG BLOCK */
            {
                char                    cipher_description[256];
                GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(
                    2, "SSL handshake finished\n");
                GLOBUS_I_GSI_GSSAPI_DEBUG_FNPRINTF(
                    2, (20, "Using %s.\n",
			SSL_get_version(context_handle->gss_ssl)));
                GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                    2, (globus_i_gsi_gssapi_debug_fstream,
                        "cred_usage=%d\n",
                        context_handle->cred_handle->cred_usage));
                GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(
                    2, "Cipher being used:\n");
                SSL_CIPHER_description(
                    context_handle->gss_ssl->session->cipher,
                    cipher_description, 256);
                GLOBUS_I_GSI_GSSAPI_DEBUG_FNPRINTF(
                    2, (256, "%s", cipher_description));
            }

        } 
        else 
        {
            major_status = GSS_S_CONTINUE_NEEDED;
        }
    }

 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Retrieve Peer
 * @ingroup globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Retrieve Peer
 *
 * Called after the handshake has completed sucessfully,
 * and gets the subject name, so it can be returned to the
 * call of the GSSAPI init_sec_context or accept_sec_context. 
 * 
 * @param minor_status
 * @param context_handle
 * @param cred_usage
 *
 * @return
 */
OM_uint32
globus_i_gsi_gss_retrieve_peer(
    OM_uint32 *                         minor_status,
    gss_ctx_id_desc *                   context_handle,
    const gss_cred_usage_t              cred_usage) 
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    globus_result_t                     local_result = GLOBUS_SUCCESS;
    X509 *                              peer_cert = NULL;
    STACK_OF(X509) *                    peer_cert_chain = NULL;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_retrieve_peer";
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    *minor_status = GLOBUS_SUCCESS;

    if (context_handle->gss_ssl->session)
    {
        peer_cert = context_handle->gss_ssl->session->peer;
    }

    if(peer_cert == NULL)
    {
        context_handle->peer_cred_handle->globusid->name_oid 
            = GSS_C_NT_ANONYMOUS;
    }
    else
    {
        context_handle->peer_cred_handle->globusid->name_oid 
            = GSS_C_NO_OID;

        local_result = globus_gsi_cred_set_cert(
            context_handle->peer_cred_handle->cred_handle, 
            peer_cert);

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_GETTING_PEER_CRED);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        local_result = globus_gsi_callback_get_cert_chain(
            context_handle->callback_data,
            &peer_cert_chain);
        
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
            major_status = GSS_S_FAILURE;
            peer_cert_chain = NULL;
            goto exit;
        }
        
        local_result = globus_gsi_cred_get_X509_subject_name(
            context_handle->peer_cred_handle->cred_handle,
            &context_handle->peer_cred_handle->globusid->x509n);

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_GETTING_PEER_CRED);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        if(context_handle->peer_cred_handle->globusid->x509n == NULL)
        {
            major_status = GSS_S_FAILURE;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_PROCESS_CERT,
                (_GGSL("NULL subject name of peer credential")));
            goto exit;
        }

        local_result = globus_gsi_cert_utils_get_base_name(
            context_handle->peer_cred_handle->globusid->x509n,
            peer_cert_chain);

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_GETTING_PEER_CRED);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
        
        X509_free(sk_X509_shift(peer_cert_chain));
        
        local_result = globus_gsi_cred_set_cert_chain(
            context_handle->peer_cred_handle->cred_handle, 
            peer_cert_chain);

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_GETTING_PEER_CRED);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        /* debug statement */
        { 
            char * subject;
            subject = X509_NAME_oneline(
                context_handle->peer_cred_handle->globusid->x509n,
                NULL,
                0);
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream, 
                    "X509 subject after proxy : %s\n", subject));
            OPENSSL_free(subject);
        }

    }

 exit:

    if(peer_cert_chain)
    { 
        sk_X509_pop_free(peer_cert_chain, X509_free);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Create Anonymous Cred
 * @ingroup globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Create Anonymous Cred
 *
 * @param minor_status
 * @param output_cred_handle
 * @param cred_usage
 *
 * @return
 */
OM_uint32
globus_i_gsi_gss_create_anonymous_cred(
    OM_uint32 *                         minor_status,
    gss_cred_id_t *                     output_cred_handle,
    const gss_cred_usage_t              cred_usage)
{
    gss_cred_id_desc *                  newcred = NULL;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    globus_result_t                     local_result = GLOBUS_SUCCESS;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_create_anonymous_cred";
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    
    newcred = (gss_cred_id_desc*) malloc(sizeof(gss_cred_id_desc));
    
    if (newcred == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    newcred->cred_usage = cred_usage;

    local_result = globus_gsi_cred_handle_init(&newcred->cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto free_cred;
    }

    newcred->globusid = (gss_name_desc *) malloc(sizeof(gss_name_desc));

    if (newcred->globusid == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto free_cred;
    }
    
    newcred->globusid->name_oid = GSS_C_NT_ANONYMOUS;

    newcred->globusid->x509n = NULL;

    major_status = globus_i_gsi_gssapi_init_ssl_context(
        &local_minor_status,
        (gss_cred_id_t) newcred,
        GLOBUS_I_GSI_GSS_ANON_CONTEXT);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto free_cred;
    }
   
    *output_cred_handle = newcred;
    
    major_status = GSS_S_COMPLETE;
    goto exit;
    
 free_cred:

    if(newcred)
    {
        major_status =
            gss_release_cred(&local_minor_status, (gss_cred_id_t *) &newcred);
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL);
    }

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}

OM_uint32
globus_i_gsi_gss_cred_read_bio(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     cred_id_handle,
    BIO *                               bp)
{
    globus_gsi_cred_handle_t            local_cred_handle;
    OM_uint32                           local_minor_status;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    globus_result_t                     local_result;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_cred_read_bio";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = GLOBUS_SUCCESS;

    local_result = globus_gsi_cred_handle_init(&local_cred_handle, NULL);

    if(local_result != GLOBUS_SUCCESS)
    {
        local_cred_handle = NULL;
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    local_result = globus_gsi_cred_read_proxy_bio(local_cred_handle, bp);

    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    major_status = globus_i_gsi_gss_create_cred(&local_minor_status,
                                                cred_usage,
                                                cred_id_handle, 
                                                &local_cred_handle);
    
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

 exit:

    if(local_cred_handle != NULL)
    {
        globus_gsi_cred_handle_destroy(local_cred_handle);
    }
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}

OM_uint32
globus_i_gsi_gss_cred_read(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     cred_handle,
    const X509_NAME *                   desired_subject) 
{
    globus_result_t                     local_result = GLOBUS_SUCCESS;
    globus_gsi_cred_handle_t            local_cred_handle;
    OM_uint32                           local_minor_status;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_cred_read";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    local_result = globus_gsi_cred_handle_init(&local_cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        local_cred_handle = NULL;
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    local_result = globus_gsi_cred_read(local_cred_handle, 
                                        desired_subject);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    major_status = globus_i_gsi_gss_create_cred(&local_minor_status,
                                                cred_usage,
                                                cred_handle, 
                                                &local_cred_handle);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }
    
 exit:

    if(local_cred_handle != NULL)
    {
        globus_gsi_cred_handle_destroy(local_cred_handle);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Credential Set
 * @ingroup globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Credential Set
 *
 * @param minor_status
 * @param cred_usage
 * @param cred_handle
 * @param ucert
 * @param upkey,
 * @param cert_chain
 *
 * @return
 */
OM_uint32
globus_i_gsi_gss_cred_set(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     cred_handle,
    X509 *                              ucert,
    EVP_PKEY *                          upkey,
    STACK_OF(X509) *                    cert_chain)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    globus_result_t                     local_result;
    globus_gsi_cred_handle_t            local_cred_handle;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_cred_set";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = GLOBUS_SUCCESS;

    local_result = globus_gsi_cred_handle_init(&local_cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        local_cred_handle = NULL;
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    local_result = globus_gsi_cred_set_cert(local_cred_handle, ucert);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }
    
    local_result = globus_gsi_cred_set_key(local_cred_handle, upkey);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    local_result = globus_gsi_cred_set_cert_chain(local_cred_handle, 
                                                  cert_chain);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    major_status = globus_i_gsi_gss_create_cred(&local_minor_status,
                                                cred_usage,
                                                cred_handle, 
                                                &local_cred_handle);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }
    
 exit:

    if(local_cred_handle != NULL)
    {
        globus_gsi_cred_handle_destroy(local_cred_handle);
    }
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Create Cred
 * @ingroup globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Create Cred
 * 
 * Called by acquire_cred and accept_sec_context for a delegate.
 * Setup the credential including the SSL_CTX
 *
 * @param minor_status
 * @param cred_usage
 * @param output_cred_handle_P
 * @param cred_handle
 *
 * @return
 */
OM_uint32 
globus_i_gsi_gss_create_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     output_cred_handle_P,
    globus_gsi_cred_handle_t *          cred_handle)
{
    gss_cred_id_desc **                 output_cred_handle = 
        (gss_cred_id_desc **) output_cred_handle_P;
    OM_uint32                           major_status = GSS_S_NO_CRED;
    OM_uint32                           local_minor_status;
    globus_result_t                     local_result;
    gss_cred_id_desc *                  newcred = NULL;
    globus_gsi_cert_utils_cert_type_t   cert_type;
    
    static char *                       _function_name_ =
        "globus_i_gsi_gss_create_cred";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    *output_cred_handle = NULL;

    newcred = (gss_cred_id_desc*) malloc(sizeof(gss_cred_id_desc));

    if (newcred == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    newcred->cred_usage = cred_usage;
    newcred->globusid = NULL;

    /* delegated certificate */

    /* get the globusid, which is the subject name - any proxy entries
     */
    newcred->globusid = (gss_name_desc*) malloc(sizeof(gss_name_desc));
    if (newcred->globusid == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }
    memset(newcred->globusid, 0, sizeof(gss_name_desc));
    newcred->globusid->name_oid = GSS_C_NO_OID;

    if(!cred_handle || !*cred_handle)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL,
            (_GGSL("NULL credential handle passed to function: %s"), 
             _function_name_));
        goto error_exit;
    }

    newcred->cred_handle = *cred_handle;
    *cred_handle = NULL;

    major_status = globus_i_gsi_gssapi_init_ssl_context(
        &local_minor_status,
        (gss_cred_id_t) newcred,
        GLOBUS_I_GSI_GSS_DEFAULT_CONTEXT);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    local_result = globus_gsi_cred_get_X509_subject_name(
        newcred->cred_handle, 
        &newcred->globusid->x509n);
    if (local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    local_result = globus_gsi_cred_get_cert_type(
        newcred->cred_handle, 
        &cert_type);
    
    if (local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    if(GLOBUS_GSI_CERT_UTILS_IS_PROXY(cert_type))
    {
        STACK_OF(X509) *                cert_chain;
        X509 *                          proxy;
        
        local_result = globus_gsi_cred_get_cert_chain(
            newcred->cred_handle, 
            &cert_chain);
        if (local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto error_exit;
        }

        local_result = globus_gsi_cred_get_cert(
            newcred->cred_handle, 
            &proxy);
        if (local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            sk_X509_pop_free(cert_chain, X509_free);
            goto error_exit;
        }
        
        sk_X509_unshift(cert_chain,proxy);
        
        /* now strip off any /CN=proxy entries */
        local_result = globus_gsi_cert_utils_get_base_name(
            newcred->globusid->x509n,
            cert_chain);
        
        sk_X509_pop_free(cert_chain, X509_free);
        

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto error_exit;
        }
    }
    
    *output_cred_handle = newcred;
    goto exit;

 error_exit:
    
    if(newcred)
    {
        gss_release_cred(&local_minor_status, (gss_cred_id_t *) &newcred);
    }

 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    return major_status;
}
/* @} */


OM_uint32
globus_i_gsi_gss_SSL_write_bio(
    OM_uint32 *                         minor_status,
    gss_ctx_id_desc *                   context,
    BIO *                               bp)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    SSL *                               ssl_handle;
    unsigned char                       intbuffer[4];
    static char *                       _function_name_ =
        "globus_i_gsi_gss_SSL_write_bio";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    ssl_handle = context->gss_ssl;

    /* DEBUG BLOCK */
    {
        int index;
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "client_random=");
        for(index = 0; index < SSL3_RANDOM_SIZE; ++index)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->client_random[index]));
        }
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nserver_random =");
        for(index = 0; index < SSL3_RANDOM_SIZE; ++index)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->server_random[index]));
        }
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\n");
    }
    
    BIO_write(bp, (char *) ssl_handle->s3->client_random, SSL3_RANDOM_SIZE);
    BIO_write(bp, (char *) ssl_handle->s3->server_random, SSL3_RANDOM_SIZE);
    
    ssl3_setup_key_block(ssl_handle);
    
    /* DEBUG BLOCK */
    {
        int index;
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream,
                "tmp.key_block_length=%d\ntmp.key_block=",
                ssl_handle->s3->tmp.key_block_length));
        for (index = 0; index < ssl_handle->s3->tmp.key_block_length; ++index)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X",ssl_handle->s3->tmp.key_block[index]));
        }
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nwrite_sequence=");
        for (index = 0; index < 8; ++index)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->write_sequence[index]));
        }
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nread_sequence =");
        for (index = 0; index < 8; ++index)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->read_sequence[index]));
        }
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nwrite_iv=");
        for (index = 0; index < 8; ++index)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->enc_write_ctx->iv[index]));
        }
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nread_iv=");
        for (index = 0; index < 8; index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->enc_read_ctx->iv[index]));
        }
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\n");
    }
    
    L2N(ssl_handle->s3->tmp.key_block_length, intbuffer);

    BIO_write(bp, (char *) intbuffer, 4);

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        3, (globus_i_gsi_gssapi_debug_fstream,
            "exporting security context: BIO pending=%d\n",
            BIO_pending(bp)));

    BIO_write(bp, (char *) ssl_handle->s3->tmp.key_block,
              ssl_handle->s3->tmp.key_block_length);
    BIO_write(bp, (char *) ssl_handle->s3->write_sequence, 8);
    BIO_write(bp, (char *) ssl_handle->s3->read_sequence, 8);
    BIO_write(bp, (char *) ssl_handle->enc_write_ctx->iv, EVP_MAX_IV_LENGTH);
    BIO_write(bp, (char *) ssl_handle->enc_read_ctx->iv, EVP_MAX_IV_LENGTH);
    
    ssl3_cleanup_key_block(ssl_handle);

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

OM_uint32
globus_i_gsi_gss_SSL_read_bio(
    OM_uint32 *                         minor_status,
    gss_ctx_id_desc *                   context,
    BIO *                               bp)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    SSL *                               ssl_handle;
    unsigned char                       int_buffer[4];
    int                                 length;
    int                                 len = 0;
    int                                 rc;
    int                                 ssl_result;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_SSL_read_bio";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    ssl_handle = context->gss_ssl;

    if (BIO_pending(bp) < (2 * SSL3_RANDOM_SIZE))
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Couldn't read from bio for importing SSL handle")));
        goto exit;
    }

    BIO_read(bp, (char*) ssl_handle->s3->client_random, SSL3_RANDOM_SIZE);
    BIO_read(bp, (char*) ssl_handle->s3->server_random, SSL3_RANDOM_SIZE);

    /* DEBUG BLOCK */
    {
        int index;
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "client_random=");
        for (index =0 ; index < SSL3_RANDOM_SIZE; index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->client_random[index]));
        }

        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nserver_random ="); 
        for (index = 0; index < SSL3_RANDOM_SIZE; index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->server_random[index]));
        }
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\n");
    }

    ssl_handle->shutdown = 0;

    ssl_handle->s3->tmp.new_cipher = ssl_handle->session->cipher;
        
    /* read the tmp.key_block */
    if (BIO_pending(bp) < 4)
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BAD_LEN,
            (_GGSL("Invalid data on BIO, should be 4 bytes available")));
        goto exit;
    }

    /* get length */
    BIO_read(bp, (char *) int_buffer, 4); 
    N2L(int_buffer, length);

    if (BIO_pending(bp) < length)
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BAD_LEN,
            (_GGSL("Invalid BIO - not enough data to read an int")));
        goto exit;
    }

    ssl_handle->s3->tmp.key_block = (unsigned char *) OPENSSL_malloc(length);
    if (ssl_handle->s3->tmp.key_block == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto exit;
    }
                
    ssl_handle->s3->tmp.key_block_length = length;

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        3, (globus_i_gsi_gssapi_debug_fstream,
            "reading in context: BIO pending = %d\n",
            BIO_pending(bp)));

    while(len < length)
    {
        rc = BIO_read(bp,  
                      (char *) ssl_handle->s3->tmp.key_block + len,
                      ssl_handle->s3->tmp.key_block_length - len);
        if(rc > 0)
        {
            len += rc;
        }
        else
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_READ_BIO,
                (_GGSL("Couldn't read expected bytes of: %d from BIO"),
                 length));;
        }
    }

    /* DEBUG BLOCK */
    {
        int index;
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream,
                "tmp.key_block_length=%d\ntmp.key_block=",
                ssl_handle->s3->tmp.key_block_length));
        for(index = 0; index < ssl_handle->s3->tmp.key_block_length; index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->tmp.key_block[index]));
        }
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\n");
    }

    ssl_result = ssl_cipher_get_evp(
        ssl_handle->session,
        &ssl_handle->s3->tmp.new_sym_enc,
        &ssl_handle->s3->tmp.new_hash,
        (SSL_COMP **) &ssl_handle->s3->tmp.new_compression);
    if (!ssl_result)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Couldn't set the compression type in the SSL handle")));
        major_status = GSS_S_FAILURE;
        goto free_key_block;
    }
    
    ssl_result = ssl_handle->method->ssl3_enc->change_cipher_state(
        ssl_handle,
        (!ssl_handle->server)?SSL3_CHANGE_CIPHER_CLIENT_WRITE:SSL3_CHANGE_CIPHER_SERVER_WRITE);
    if (!ssl_result)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Attempt to change cipher state of the SSL handle failed")));
        major_status = GSS_S_FAILURE;
        goto free_key_block;
    }

    ssl_result = ssl_cipher_get_evp(
        ssl_handle->session,
        &ssl_handle->s3->tmp.new_sym_enc,
        &ssl_handle->s3->tmp.new_hash,
        (SSL_COMP **) &ssl_handle->s3->tmp.new_compression);
    if (!ssl_result)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Couldn't set the compression type in the SSL handle")));
        major_status = GSS_S_FAILURE;
        goto free_key_block;
    }

    ssl_result = ssl_handle->method->ssl3_enc->change_cipher_state(
        ssl_handle,
        (!ssl_handle->server)?SSL3_CHANGE_CIPHER_CLIENT_READ:SSL3_CHANGE_CIPHER_SERVER_READ); 
    
    if (!ssl_result)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Attempt to change cipher state of the SSL handle failed")));
        major_status = GSS_S_FAILURE;
        goto free_key_block;
    }

    ssl_handle->hit = 1;

    ssl_handle->state = SSL_ST_OK;

    /* will free the one we read */
    ssl3_cleanup_key_block(ssl_handle); 
    
    length = BIO_pending(bp);
    if (length != 8 + 8 + EVP_MAX_IV_LENGTH + EVP_MAX_IV_LENGTH)
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL,
            (_GGSL("Error reading SSL data from BIO")));
        goto free_key_block;
    }
    
    BIO_read(bp, (char*) ssl_handle->s3->write_sequence, 8);
    BIO_read(bp, (char*) ssl_handle->s3->read_sequence,  8);
    BIO_read(bp, (char*) ssl_handle->enc_write_ctx->iv,  EVP_MAX_IV_LENGTH);
    BIO_read(bp, (char*) ssl_handle->enc_read_ctx->iv,   EVP_MAX_IV_LENGTH);
    
    /* DEBUG BLOCK */
    {
        int index;
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "write_sequence=");
        for (index = 0; index < 8; index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->write_sequence[index]));
        }

        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nread_sequence=");
        for (index = 0; index < 8; index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->s3->read_sequence[index]));
        }
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nwrite_iv=");
        for (index = 0; index < EVP_MAX_IV_LENGTH; index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->enc_write_ctx->iv[index]));
        }
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\nread_iv=");
        for (index = 0; index < EVP_MAX_IV_LENGTH; index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%02X", ssl_handle->enc_read_ctx->iv[index]));
        }
        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\n");
    }

    goto exit;

 free_key_block:

    if(ssl_handle->s3->tmp.key_block)
    {
        OPENSSL_free(ssl_handle->s3->tmp.key_block);
    }

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */


/**
 * @name Init SSL Context
 * @ingroup globus_i_gsi_gssapi
 */
/* @{ */
/**
 * Initialize the SSL Context for use in the SSL authentication mechanism.
 * The ssl context held by the cred handle is used to generate SSL objects
 * for the SSL handshake.  Initializing the SSL context consists of
 * setting the method to be used (SSLv3), setting the callback to perform
 * certificate verification, and finding the appropriate issuing CA's of
 * the certs used for authentication.
 *
 * @param minor_status
 *        The mech specific status code.  This is GLOBUS_SUCCESS if the
 *        call was successful, otherwise it is set to a globus error
 *        object identifier
 * @param cred_handle
 *        The credential handle containing the SSL_CTX to be initialized
 * @param anon_ctx
 *        Specify the SSL context as anonymous (1) or not (0).  An anonymous
 *        SSL_CTX does not have the cert or key set. 
 *
 * @return
 *        GSS_S_COMPLETE if initiating the SSL_CTX was successful
 *        GSS_S_FAILURE if an error occurred
 */
OM_uint32
globus_i_gsi_gssapi_init_ssl_context(
    OM_uint32 *                         minor_status,
    gss_cred_id_t                       credential,
    globus_i_gsi_gss_context_type_t     anon_ctx)
{
    X509 *                              client_cert = NULL;
    EVP_PKEY *                          client_key = NULL;
    STACK_OF(X509) *                    client_cert_chain = NULL;
    globus_result_t                     local_result;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_cred_id_desc *                  cred_handle;
    char *                              ca_cert_dir = NULL;

    static char *                       _function_name_ =
        "globus_i_gsi_gssapi_init_ssl_context";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    cred_handle = (gss_cred_id_desc *) credential;
    
    if(cred_handle == NULL)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL,
            (_GGSL("Null credential handle passed to function: %s"),
             _function_name_));
        goto exit;
    }

    cred_handle->ssl_context = SSL_CTX_new(SSLv23_method());
    if(cred_handle->ssl_context == NULL)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
            (_GGSL("Can't initialize the SSL_CTX")));
        goto exit;
    }

    SSL_CTX_set_options(cred_handle->ssl_context,SSL_OP_NO_SSLv2);
            
    SSL_CTX_set_cert_verify_callback(cred_handle->ssl_context,
                                     globus_gsi_callback_X509_verify_cert,
                                     NULL);

    SSL_CTX_sess_set_cache_size(cred_handle->ssl_context, 5);

    local_result = GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&ca_cert_dir);
    
    if(local_result != GLOBUS_SUCCESS)
    {
        ca_cert_dir = NULL;
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        goto exit;
    }

    if(!SSL_CTX_load_verify_locations(cred_handle->ssl_context,
                                      NULL,
                                      ca_cert_dir))
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
            ("\n       x509_cert_dir=", (ca_cert_dir) ? ca_cert_dir : _GGSL("NONE")));
        goto exit;
    }

    /* Set the verify callback to test our proxy 
     * policies. 
     */
    SSL_CTX_set_verify(cred_handle->ssl_context, SSL_VERIFY_PEER,
                       globus_gsi_callback_handshake_callback);

    SSL_CTX_set_verify_depth(cred_handle->ssl_context,
                             GLOBUS_GSI_CALLBACK_VERIFY_DEPTH);

    /*
     * for now we will accept any purpose, as Globus does
     * not have any restrictions such as this is an SSL client
     * or SSL server. Globus certificates are not required
     * to have these fields set today.
     */
    SSL_CTX_set_purpose(cred_handle->ssl_context, X509_PURPOSE_ANY);

    X509_STORE_set_flags(SSL_CTX_get_cert_store(cred_handle->ssl_context),
                         X509_V_FLAG_IGNORE_CRITICAL);
    
    if(anon_ctx != GLOBUS_I_GSI_GSS_ANON_CONTEXT)
    {
        local_result = globus_gsi_cred_get_cert(cred_handle->cred_handle,
                                                &client_cert);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        if(!client_cert)
        {
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL,
                (_GGSL("The GSI credential's certificate has not been set.")));
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        if(!SSL_CTX_use_certificate(cred_handle->ssl_context, 
                                    client_cert))
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                (_GGSL("Couldn't set the certificate to "
                 "be used for the SSL context")));
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        local_result = globus_gsi_cred_get_key(cred_handle->cred_handle,
                                               &client_key);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        if(!client_key)
        {
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL,
                (_GGSL("The GSI credential's private key has not been set.")));
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        if(!SSL_CTX_use_PrivateKey(cred_handle->ssl_context, client_key))
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                (_GGSL("Couldn't set the private key to "
                 "be used for the SSL context")));
            major_status = GSS_S_FAILURE;
            goto exit;
        }
            
        local_result = globus_gsi_cred_get_cert_chain(cred_handle->cred_handle,
                                                      &client_cert_chain);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        if(client_cert_chain)
        {
            int                         index;
            X509 *                      tmp_cert = NULL;
            for(index = 0; index < sk_X509_num(client_cert_chain); ++index)
            {
                tmp_cert = X509_dup(sk_X509_value(client_cert_chain, index));
                if(!X509_STORE_add_cert(
                       SSL_CTX_get_cert_store(cred_handle->ssl_context),
                       tmp_cert))
                {
                    /* need to free to reduce ref count */
                    X509_free(tmp_cert);
                    if ((ERR_GET_REASON(ERR_peek_error()) ==
                         X509_R_CERT_ALREADY_IN_HASH_TABLE))
                    {
                        ERR_clear_error();
                        break;
                    }
                    else
                    {
                        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                            minor_status,
                            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                            (_GGSL("Couldn't add certificate to the SSL context's "
                             "certificate store.")));
                        major_status = GSS_S_FAILURE;
                        goto exit;
                    }
                }
                /* need to free to reduce ref count */
                X509_free(tmp_cert);
            }
        }
    }

 exit:

    if(client_cert)
    {
        X509_free(client_cert);
    }
    
    if(client_key)
    {
        EVP_PKEY_free(client_key);
    }

    if(client_cert_chain)
    {
        sk_X509_pop_free(client_cert_chain, X509_free);
    }

    if(ca_cert_dir)
    {
        free(ca_cert_dir);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

OM_uint32
globus_i_gsi_gss_get_context_goodtill(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context,
    time_t *                            goodtill)
{
    time_t                              peer_cred_goodtill;
    time_t                              local_cred_goodtill;
    globus_result_t                     local_result;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_get_context_goodtill";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    local_result = globus_gsi_cred_get_goodtill(
        ((gss_ctx_id_desc *)context)->cred_handle->cred_handle,
        &local_cred_goodtill);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    local_result = globus_gsi_cred_get_goodtill(
        ((gss_ctx_id_desc *)context)->peer_cred_handle->cred_handle,
        &peer_cred_goodtill);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }
    
    *goodtill = 
        (local_cred_goodtill > peer_cred_goodtill) ? peer_cred_goodtill 
                                                   : local_cred_goodtill;

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Verify Extensions Callback
 * @ingroup globus_i_gsi_gss_utils
 */
/* @{ */
/**
 * Verify Extensions Callback 
 *
 * @param callback_data
 * @param extension
 *
 * @return
 */
int globus_i_gsi_gss_verify_extensions_callback(
    globus_gsi_callback_data_t          callback_data,
    X509_EXTENSION *                    extension)
{
    gss_OID_set                         extension_oids;
    ASN1_OBJECT *                       extension_obj;
    int                                 index;
    int                                 return_val = 0;
    globus_result_t                     local_result;
    gss_OID_desc                        oid;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_verify_extensions_callback";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    local_result = globus_gsi_callback_get_extension_oids(
        callback_data,
        (void **) &extension_oids);

    if(local_result != GLOBUS_SUCCESS)
    {
        return_val = 0;
        goto exit;
    }

    if(extension_oids == GSS_C_NO_OID_SET)
    {
        return_val = 0;
        goto exit;
    }
    
    extension_obj = X509_EXTENSION_get_object(extension);

    for(index = 0; index < extension_oids->count; index++)
    {
        oid = extension_oids->elements[index];
        if((extension_obj->length == oid.length) &&
           !memcmp(extension_obj->data, oid.elements, extension_obj->length))
        {
            return_val = 1;
            goto exit;
        }
    }

    return_val = 0;

 exit:

    GLOBUS_I_GSI_GSSAPI_INTERNAL_DEBUG_EXIT;
    return return_val;
}
/* @} */

unsigned char *
globus_i_gsi_gssapi_get_hostname(
    const gss_name_desc *               name)
{
    int                                 common_name_NID;
    int                                 index;
    unsigned int                        length;
    unsigned char *                     data;
    unsigned char *                     result = NULL;
    X509_NAME_ENTRY *                   name_entry = NULL;

    common_name_NID = OBJ_txt2nid("CN");
    for (index = 0; index < X509_NAME_entry_count(name->x509n); index++)
    {
        name_entry = X509_NAME_get_entry(name->x509n, index);
        if (OBJ_obj2nid(name_entry->object) == common_name_NID)
        {
            length = name_entry->value->length;
            data = name_entry->value->data;
            if ( length > 5 && !strncasecmp(data, (unsigned char*)"host/", 5))
            {
                length -= 5;
                data += 5;
            }
            else if ( length > 4 && 
                      !strncasecmp(data, (unsigned char*)"ftp/", 4))
            {
                length -= 4;
                data += 4;
            }
            break;
        }
        name_entry = NULL;
    }

    if(name_entry)
    { 
        result = malloc(length + 1);
        
        if(result == NULL)
        {
            return result;
        }
        
        memcpy(result, data, length);
        result[length] = '\0';
    }
    
    return result;
}


#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
