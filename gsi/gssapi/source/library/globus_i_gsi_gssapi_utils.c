#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_gsi_gssutils.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#error can you make sure that all gss functions are implemented with GSS_CALLCONV in GSI-3

#error and also look at the use of the function(s) mentioned in the mem leak bug report in GSI-3

#error also look for X509_REQ_get_pubkey, it does the same kind of refcounting thing

#error do search and replace for stderr

static char *rcsid = "$Id$";

#include <string.h>
#include <stdlib.h>

#include "gssapi_openssl.h"
#include "gssutils.h"
#include "sslutils.h"
#include "globus_gsi_cred_callback.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @anchor globus_i_gsi_gssapi_utils
 * @mainpage Globus GSI GSS-API
 *
 * The globus_i_gsi_gss_utils code is used by the other 
 * gss api code to perform internal functions such as
 * initializing objects and performing the SSL handshake
 */

/**
 * @name Copy GSS API Name
 * @ingroup globus_i_gsi_gssapi_utils
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
    STACK *                             group = NULL;
    ASN1_BIT_STRING *                   group_types = NULL;
    int                                 i;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_copy_name_to_name";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    output_name = (gss_name_desc *) malloc(sizeof(gss_name_desc));

    if (output_name == NULL)
    {
        GLOBUS_I_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
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
                ("Couldn't copy X509_NAME struct"));
            major_status = GSS_S_FAILURE;
            goto exit;
        }
    }

    if(input->group != NULL &&
       input->group_types != NULL)
    {
        group_types = ASN1_BIT_STRING_new();
        group = sk_new_null();

        for(i=0;i<sk_num(input->group);i++)
        {
            sk_insert(group,strdup(sk_value(input->group,i)),i);
            if(ASN1_BIT_STRING_get_bit(input->group_types,i))
            {
                ASN1_BIT_STRING_set_bit(group_types,i,1);
            }
        }
    }
    
    output_name->name_oid = input->name_oid;
    output_name->x509n = x509n;
    output_name->group = group;
    output_name->group_types = group_types;
    
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
 * @ingroup globus_i_gsi_gssapi_utils
 */
/* @{ */
/* Initialize a security context structure.
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
    OM_uint32                           result = GSS_S_COMPLETE;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_ctx_id_desc*                    context = NULL;
    gss_cred_id_t                       output_cred_handle= NULL;
    int                                 j;
    OM_uint32                           local_minor_status;
    char *                              certdir = NULL;
    SSL_CTX *                           ssl_context = NULL;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_create_and_fill_context";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = GLOBU_SUCCESS;

    /* initialize the context handle */
    if(*context_handle_P == GSS_C_NO_CONTEXT)
    {
        context = (gss_ctx_id_desc*) globus_malloc(sizeof(gss_ctx_id_desc));
        if (context == NULL)
        {
            GLOBUS_I_GSI_GSSAPI_MALLOC_ERROR(minor_status);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
        
        memset(context,(int)NULL,sizeof(gss_ctx_id_desc));
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
    context->peer_cred_handle = globus_malloc(sizeof(gss_cred_id_desc));
    if(context->peer_cred_handle == NULL)
    {
        GLOBUS_I_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto free_context;
    }
    
    local_result = globus_gsi_cred_handle_init(
        context->peer_cred_handle->cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result, 
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto free_peer_cred_handle;
    }

    if((context->peer_cred_handle->globusid = 
        globus_malloc(sizeof(gss_name_desc))) == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto free_peer_cred_handle;
    }

    memset(context->peer_cred_handle->globusid, 
           (char *) NULL, 
           sizeof(gss_name_desc));

    /* initialize the proxy_handle */
    local_result = globus_gsi_proxy_handle_init(& context->proxy_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_PROXY_HANDLE);
        major_status = GSS_S_FAILURE;
        goto free_globusid;
    }

    /* initialize the delegation credential handle */
    local_result = globus_gsi_cred_handle_init(
        &context->deleg_cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto free_proxy_handle;
    }

    /* 
     * set the callback data if its OK to accept proxies
     * signed by limited proxies
     */
    
    if ( context->req_flags & GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG)
    {
        local_result = globus_gsi_callback_data_set_multiple_limited_proxy_ok(
            context->callback_data, 1);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
            major_status = GSS_S_FAILURE;
            goto free_deleg_cred_handle;
        }
    }

    /* get the local credential */
    if (cred_handle == GSS_C_NO_CREDENTIAL)
    {
        if(req_flags & GSS_C_ANON_FLAG)
        {
            major_status = gss_create_anonymous_cred(&local_minor_status, 
                                                     &output_cred_handle, 
                                                     cred_usage);
        }
        else
        {
            major_status = gss_acquire_cred(&local_minor_status, 
                                            GSS_C_NO_NAME, 
                                            GSS_C_INDEFINITE,
                                            GSS_C_NO_OID_SET, 
                                            cred_usage, 
                                            &output_cred_handle, 
                                            NULL, 
                                            NULL);
        }
        
        if (GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CREDENTIAL);
            major_status = major_status;
            goto free_deleg_cred_handle;
        }

        context->cred_handle = output_cred_handle;
        context->cred_obtained = 1;
    }
    else
    {
        context->cred_handle = cred_handle;
        context->cred_obtained = 0;
    }

    /* set the cert_dir in the callback data */
    local_result = globus_gsi_cred_handle_get_handle_attrs(
        context->cred_handle->cred_handle, &handle_attrs);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto free_output_cred_handle;
    }

    local_result = 
        globus_gsi_cred_handle_attrs_get_ca_cert_dir(
            handle_attrs, &certdir);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto free_handle_attrs;
    }

    if (certdir)
    {
        local_result = globus_gsi_callback_data_set_cert_dir(
            context->callback_data, 
            cert_dir);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
            major_status = GSS_S_FAILURE;
            goto free_cert_dir;
        }
    }
    else
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, GSS_S_FAILURE, 
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE,
            ("The cert_dir parameter in "
             "the credential handle needs to bet set"));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    globus_libc_free(certdir);

    /* setup the SSL object for the gss_shuffle routine */
    local_result = globus_gsi_cred_get_ssl_context(
        context->cred_handle->cred_handle,
        &ssl_context);

    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    context->gss_ssl = SSL_new(ssl_context);

    SSL_CTX_free(ssl_context);

    if (context->gss_ssl == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status, 
            GLOBUS_GSI_GSSAPI_ERROR_WITH_SSL,
            ("Couldn't create SSL object for handshake"));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    if (cred_usage == GSS_C_ACCEPT)
    {
        SSL_set_ssl_method(context->gss_ssl, SSLv23_method());
        SSL_set_options(context->gss_ssl, SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1);
    }
    else
    {
        SSL_set_ssl_method(context->gss_ssl, SSLv3_method());
    }

    globus_gsi_cred_callback_SSL_callback_data_index = 
        SSL_get_ex_new_index(
            0, NULL, 
            (CRYPTO_EX_new *)  &globus_gsi_callback_openssl_new,
            (CRYPTO_EX_dup *)  &globus_gsi_callback_openssl_dup,
            (CRYPTO_EX_free *) &globus_gsi_callback_openssl_free);
    
    if(globus_gsi_cred_SSL_callback_data_index == -1)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_SSL,
            ("Couldn't create external data index for SSL object"));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    if(!SSL_set_ex_data(context->gss_ssl, 
                        globus_gsi_cred_callback_SSL_callback_data_index, 
                        (char *) &context->callback_data))
    {
        GLOBUS_GSI_GSSAPI_OPENSSLS_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_SSL,
            ("Couldn't set the callback data as the external data "
             "of the SSL object"));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    /*
     * If initiate and caller did not set the GSS_C_CONF_FLAG
     * then add the NULL ciphers to begining.
     */
    if (!(context->req_flags & GSS_C_CONF_FLAG))
    {
        n = (newcred->cred_handle->ssl_context->method->num_ciphers)();
        for (i = 0; i < n; i++)
        {
            cipher = 
                (newcred->cred_handle->ssl_context->method->get_cipher)(i);

#define MY_NULL_MASK 0x130021L

            if (cipher && 
                ((cipher->algorithms & MY_NULL_MASK) == MY_NULL_MASK))
            {
                sk_SSL_CIPHER_push(
                    newcred->cred_handle->ssl_context->cipher_list, cipher);
                sk_SSL_CIPHER_push(
                    newcred->cred_handle->ssl_context->cipher_list_by_id, 
                    cipher);
            }
        }
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        3, (globus_i_gsi_gssapi_debug_fstream,
            "SSL is at %p\n", context->gss_ssl));
    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        3, (globus_i_gsi_gssapi_debug_fstream,
            "SSL_set_app_data to pvd %p\n", context->callback_data));
    
    if ((context->gss_rbio = BIO_new(BIO_s_mem())) == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_BIO,
            ("Can't initialize read BIO for SSL handle"));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    if ((context->gss_wbio = BIO_new(BIO_s_mem())) == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_BIO,
            ("Can't initialize write BIO for SSL handle"));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
    }

    if ((context->gss_sslbio = BIO_new(BIO_f_ssl())) == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_BIO,
            ("Can't create SSL bio"));
        major_status = GSS_S_FAILURE;
        goto free_cert_dir;
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

 done:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Put Token
 * @group globus_i_gsi_gssapi_utils
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
    OM_uint32                           minor_status,
    const gss_ctx_id_desc*              context_handle,
    BIO *                               bio,
    const gss_buffer_t                  input_token)
{
    BIO *                               read_bio;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_put_token";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    if(bio)
    {
        read_bio = bio;
    }
    else
    {
        read_bio = context_handle->gss_rbio;
    }

    /* add any input data onto the input for the SSL BIO */

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        3, (globus_i_gsi_gssapi_debug_fstream,
            "input token: len=%d", input_token->length));

    if (input_token->length > 0)
    {
        BIO_write(read_bio,
                  input_token->value,
                  input_token->length);

        GLOBUS_I_GSI_GSSAPI_DEBUG_FNPRINTF(
            3, (globus_i_gsi_gssapi_debug_fstream, 
                input_token->length,
                "value=%s\n", input_token->value));
    }
    else
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_DEFECTIVE_TOKEN,
            (NULL));
        major_status = GSS_S_DEFECTIVE_TOKEN;
        goto exit;
    }

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Get Token
 * @group globus_i_gsi_gssapi_utils
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
    OM_unt32 *                          minor_status,
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
        output_token->value = (char *) malloc(output_token->length);
        if (output_token->value == NULL)
        {
            output_token->length = 0;
            GLOBUS_I_GSI_GSSAPI_MALLOC_ERROR(minor_status);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        BIO_read(write_bio,
                 output_token->value,
                 output_token->length);

        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            3, (stderr,"output token: len=%d",input_token->length));
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_FNPRINTF(
            3, (stderr, input_token->length,
                "value=%s\n", input_token->value));
    }
    else
    {
        output_token->value = NULL;
    }

    return_value = GSS_S_COMPLETE;

exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Handshake
 * @ingroup globus_i_gsi_gssapi_utils
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
    OM_uint32                           major_status = GSS_S_COMPLETE;
    int rc;
    
    static char *                       _function_name_ =
        "globus_i_gsi_gss_handshake";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

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
                    ,"SSL_get_error = %d\n",
                    SSL_get_error(context_handle->gss_ssl, rc)));

            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (stderr,"shutdown=%d\n",
                    SSL_get_shutdown(context_handle->gss_ssl)));

            /* checks for ssl alert 42 */
            if (ERR_peek_error() == 
                ERR_PACK(ERR_LIB_SSL,SSL_F_SSL3_READ_BYTES,
                         SSL_R_SSLV3_ALERT_BAD_CERTIFICATE))
            {
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_REMOTE_CERT_VERIFY_FAILED,
                    ("Couldn't verify the remote certificate"));
            }
            else
            {
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_HANDSHAKE,
                    ("Couldn't do ssl handshake"));
            }

            major_status = GSS_S_DEFECTIVE_CREDENTIAL;
            goto exit;
        }
    }

    if (!GSS_ERROR(major_status)) {
        if (rc > 0) {
            major_status = GSS_S_COMPLETE; 

            /*
             * Set  GSS_C_CONF_FLAG if cipher uses encryption
             * which is at least 56 bit. SSL defines a number
             * of different levels, we need to map to a single GSS
             * flag. See the s3_lib.c for list of ciphers. 
             * This could be changed to SSL_MIDUM or SSL_HIGH 
             * if a site wants higher protection. 
             */
            
            if ((context_handle->gss_ssl->session->cipher->algo_strength
                 & SSL_STRONG_MASK) >= SSL_LOW) 
            {
                context_handle->ret_flags |= GSS_C_CONF_FLAG;
            }

            {
                char buff[256];

                GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(
                    2, "SSL handshake finished\n");
                GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                    2, (globus_i_gsi_gssapi_debug_fstream,
                        "cred_usage=%d\n",
                        context_handle->cred_handle->cred_usage));
                GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(
                    2, "Cipher being used:\n");
                SSL_CIPHER_description(
                    context_handle->gss_ssl->session->cipher,
                    buff, 256);
                GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                    2, (globus_i_gsi_gssapi_debug_fstream, buff));
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
 * @ingroup globus_i_gsi_gssapi_utils
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
    OM_uint32                           minor_status,
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
                GLOBUS_GSI_GSSAPI_ERROR_WITH_PEER_CRED);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        local_result = globus_gsi_callback_get_peer_cert_chain(
            context_handle->callback_data,
            &peer_cert_chain);
        
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

#error figure out which end the peer cert is at in the cert chain and remove it from the chain

        local_result = globus_gsi_cred_set_cert_chain(
            context->peer_cred_handle->cred_handle, 
            peer_cert_chain);

        sk_X509_pop_free(peer_cert_chain);
        peer_cert_chain = NULL;

        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_PEER_CRED);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        local_result = globus_gsi_cred_get_subject_name(
            context->peer_cred_handle->cred_handle,
            &context->peer_cred_handle->globusid->x509n);

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_PEER_CRED);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        if(context->peer_cred_handle->globusid->x509n == NULL)
        {
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                major_status,
                GLOBUS_GSI_GSSAPI_ERROR_PROCESS_CERT,
                ("NULL subject name of peer credential"));
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        local_result = globus_gsi_cred_get_base_name(
            context->peer_cred_handle->globusid->x509n);

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                major_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_PEER_CRED,
                ("Couldn't get base subject name of peer credential"));
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        /* debug statement */
        { 
            char * s;
            s = X509_NAME_oneline(context->peer_cred_handle->globusid->x509n,
                                  NULL,
                                  0);
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream, 
                    "X509 subject after proxy : %s\n", s));
            globus_libc_free(s);
        }

        local_result = globus_gsi_callback_get_cert_depth(
            context_handle->callback_data,
            &cert_depth);

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                major_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        local_result = globus_gsi_cred_get_group_name(
            context_handle->peer_cred_handle->cred_handle,
            & context->peer_cred_handle->globusid->group,
            & context->peer_cred_handle->globusid->group_types);
    
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                major_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_PEER_CRED);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
    }

 exit:

    if(peer_cert_chain)
    {
        sk_X509_pop_free(peer_cert_chain);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Create Anonymous Cred
 * @ingroup globus_i_gsi_gssapi_utils
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
        GLOBUS_I_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    newcred->cred_usage = cred_usage;

    local_result = globus_gsi_cred_handle_init(&newcred->cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CREDENTIAL);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    newcred->globusid = (gss_name_desc *) malloc(sizeof(gss_name_desc));

    if (newcred->globusid == NULL)
    {
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;
        goto exit;
    }
    
    newcred->globusid->name_oid = GSS_C_NT_ANONYMOUS;

    newcred->globusid->x509n = NULL;

    newcred->globusid->group = NULL;

    newcred->globusid->group_types = NULL;
    
    *output_cred_handle = newcred;
    
    major_status = GSS_S_COMPLETE;
    goto exit;
    
 error:

    if(newcred)
    {
        major_status =
            gss_release_cred(&local_minor_status, (gss_cred_id_t *) &newcred);
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CREDENTIAL);
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

    local_result = globus_gsi_cred_handle_init(& local_cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    result = globus_gsi_cred_read_bio(local_cred_handle, bp);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    major_status = globus_i_gsi_gss_create_cred(&local_minor_status,
                                                cred_usage,
                                                cred_id_handle, 
                                                local_cred_handle);
    
    if(major_status != GSS_S_COMPLETE)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}

OM_uint32
globus_i_gsi_gss_cred_read(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     cred_handle,
    const char *                        desired_subject) 
{
    globus_result_t                     local_result;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    char *                              local_desired_subject = NULL;
    char *                              actual_subject = NULL;
    char *                              service_name = NULL;
    static char *                       _function_name_ =
        "globus_i_gsi_gss_cred_read";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    local_result = globus_gsi_cred_handle_init(&local_cred_handle, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    /* split the service name from the subject */
    if(desired_subject != NULL)
    {
        local_desired_subject = strdup(desired_subject);
        actual_subject = strchr(local_desired_subject, '@');
        if(actual_subject == NULL)
        {
            actual_subject = local_desired_subject;
        }
        else
        {
            local_desired_subject[actual_subject - 
                                 local_desired_subject] = '\0';
            service_name = local_desired_subject;
            actual_subject++;
        }
    }

    local_result = globus_gsi_cred_read(local_cred_handle, 
                                        actual_subject,
                                        service_name);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    major_status = globus_i_gsi_gss_create_cred(&local_minor_status,
                                                cred_usage,
                                                cred_id_handle, 
                                                local_cred_handle);
    if(major_status != GSS_S_COMPLETE)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Credential Set
 * @ingroup globus_i_gsi_gssapi_utils
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

    static char *                       _function_name_ =
        "globus_i_gsi_gss_cred_set";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = GLOBUS_SUCCESS;

    local_result = globus_gsi_cred_handle_init(&local_cred_handle, NULL);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    local_result = globus_gsi_cred_handle_set_cert(local_cred_handle, ucert);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }
    
    local_result = globus_gsi_cred_handle_set_key(local_cred_handle, upkey);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WIH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    local_result = globus_gsi_cred_handle_set_cert_chain(local_cred_handle, 
                                                         cert_chain);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    major_status = globus_i_gsi_gss_create_cred(&local_minor_status,
                                                cred_usage,
                                                cred_id_handle, 
                                                local_cred_handle);
    if(major_status != GSS_S_COMPLETE)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    goto exit;

 error_exit:
    
    globus_gsi_cred_destroy(local_cred_handle);

 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Create Cred
 * @ingroup globus_i_gsi_gssapi_utils
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
    globus_gsi_cred_handle_t            cred_handle)
{
    gss_cred_id_desc **                 output_cred_handle = 
        (gss_cred_id_desc **) output_cred_handle_P;
    OM_uint32                           major_status = GSS_S_NO_CRED;
    OM_uint32                           local_minor_status;
    globus_result_t                     result;
    gss_cred_id_desc *                  newcred;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_create__cred";

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

    newcred->globusid->name_oid = GSS_C_NO_OID;

    if(!cred_handle)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status, 
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE,
            ("NULL credential handle passed to function: %s", 
             _function_name_));
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    newcred->cred_handle = cred_handle;

    local_result = globus_gsi_cred_handle_init_ssl_context(
        newcred->cred_handle);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    local_result = globus_gsi_cred_get_subject(newcred->cred_handle, 
                                               &newcred->globusid->x509n);
    if (local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    /* now strip off any /CN=proxy entries */
    local_result = globus_gsi_cred_get_base_name(newcred->globusid->x509n);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    local_result = globus_gsi_cred_get_group_names(
        newcred->cred_handle,
        &newcred->globusid->group,
        &newcred->globusid->group_types);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED_HANDLE);
        major_status = GSS_S_FAILURE;
        goto error_exit;
    }

    *output_cred_handle = newcred;
    goto exit:

 error_exit:
    
    gss_release_cred(&local_minor_status, (gss_cred_id_t *) &newcred);
    
 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    return major_status;
}

/**
 * @name Verify Extensions Callback
 * @ingroup globus_i_gsi_gssapi_utils
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
    globus_gsi_cred_callback_data_t     callback_data,
    X509_EXTENSION *                    extension)
{
    gss_OID_set                         extension_oids;
    ASN1_OBJECT *                       extension_obj;
    int                                 i;
    int                                 return_val = 0;
    globus_result_t                     result;
    gss_OID_desc                        oid;

    static char *                       _function_name_ =
        "globus_i_gsi_gss_verify_extensions_callback";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    local_result = globus_gsi_callback_get_extension_oids(
        callback_data,
        &extension_oids);

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

    for(i = 0; i < extension_oids->count; i++)
    {
        oid = extension_oids->elements[i];
        if((extension_obj->length == oid.length) &&
           !memcmp(extension_obj->data, oid.elements, extension_obj->length))
        {
            return_val = 1;
            goto exit;
        }
    }

    return_val = 0;

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return return_val;
}
/* @} */

/**
 * @name Create String
 * @ingroup globus_i_gsi_gssapi_utils
 */
/* @{ */
/**
 * Create String
 *
 * @param format
 * @param ...
 *
 * @return
 */
char *
globus_i_gsi_gssapi_create_string(
    const char *                        format,
    ...)
{
    va_list                             ap;
    int                                 len = 128;
    int                                 length;
    char *                              error_string;
    static char *                       _function_name_ =
        "globus_i_gsi_gssapi_create_error_string";
    
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    globus_libc_lock();
    
    va_start(ap, format);

    if((error_string = globus_malloc(len)) == NULL)
    {
        return NULL;
    }

    while(1)
    {
        length = vsnprintf(error_string, len, format, ap);
        if(length > -1 && length < len)
        {
            break;
        }

        if(length > -1)
        {
            len = length + 1;
        }
        else
        {
            len *= 2;
        }

        if((error_string = realloc(error_string, len)) == NULL)
        {
            return NULL;
        }
    }

    va_end(ap);

    globus_libc_unlock();

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return error_string;
}
/* @} */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
