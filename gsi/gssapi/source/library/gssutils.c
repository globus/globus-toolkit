es/**********************************************************************

gssutils.c

Description:
	Routines used internally by this implementation of GSSAPI

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include "sslutils.h"
#include <string.h>
#include <stdlib.h>

/**
 * Copy a gss_name_t
 *
 * Copy a gssapi name to a new name. This should be
 * gss_duplicate_name. 
 *
 * @param output
 *        Target name.
 * @param input
 *        Source name
 * @return
 *        GSS_S_COMPLETE - successful copy
 *        GSS_F_FAILURE - failed to copy
 */
OM_uint32 
gss_copy_name_to_name(
    gss_name_desc **                    output,
    const gss_name_desc *               input)
{
    gss_name_desc *                     output_name;
    X509_NAME *                         x509n = NULL;
    STACK *                             group = NULL;
    ASN1_BIT_STRING *                   group_types = NULL;
    int                                 i;

    static char *                       _function_name_ =
        "gss_copy_name_to_name";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    output_name = (gss_name_desc *) malloc(sizeof(gss_name_desc));

    if (output_name == NULL)
    {
#error
        GSSerr(GSSERR_F_NAME_TO_NAME, GSSERR_R_OUT_OF_MEMORY);
        return GSS_S_FAILURE ;
    }
    
    if(input->x509n != NULL)
    {
        x509n = X509_NAME_dup(input->x509n);
        if (x509n == NULL)
        {
#error
            return GSS_S_FAILURE;
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

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    
    return  GSS_S_COMPLETE;
}

/**
 * Initialize a security context structure.
 *
 * Called by init_sec_context and accept_sec_context to 
 * setup the initial context. This includes establishing the
 * SSL session control blocks
 *
 * @param context_handle_P
 * @param cred_handle
 * @param cred_usage
 * @param req_flags
 * @return
 */


OM_uint32
gss_create_and_fill_context(
    OM_uint32 *                         minor_status,
    gss_ctx_id_desc **                  context_handle_P,
    gss_cred_id_desc *                  cred_handle,
    const gss_cred_usage_t              cred_usage,
    OM_uint32                           req_flags)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_ctx_id_desc*                    context = NULL;
    gss_cred_id_t                       output_cred_handle= NULL;
    int                                 j;
    OM_uint32                           local_minor_status;
    char *                              certdir = NULL;
    SSL_CTX *                           ssl_context = NULL;
    OM_uint32                           return_value;

    static char *                       _function_name_ =
        "gss_create_and_fill_context";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    if(*context_handle_P == GSS_C_NO_CONTEXT)
    {
        context = (gss_ctx_id_desc*) globus_malloc(sizeof(gss_ctx_id_desc)) ;
        if (context == NULL)
        {
            minor_status = (OM_unit32 *) globus_error_wrap_errno_error(
                GLOBUS_GSI_GSSAPI_MODULE,
                NULL,
                errno);
                    ...
            return_value = GSS_S_FAILURE;
            goto done:
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

    if((context->peer_cred_handle = globus_malloc(sizeof(gss_cred_id_desc)))
       == NULL)
    {
#error some error here
    }
    
    if((globus_gsi_cred_handle_init(context->peer_cred_handle->cred_handle,
                                    NULL)) != GLOBUS_SUCCESS)
    {
#error blah
    }

    if((context->peer_cred_handle->globusid = 
        globus_malloc(sizeof(gss_name_desc))) == NULL)
    {
#error blah
    }

    memset(context->peer_cred_handle->globusid, 
           (char *) NULL, 
           sizeof(gss_name_desc));
    
    /* 
     * set if its OK to accept proxies signed by limited proxies
     */
    
    if ( context->req_flags & GSS_C_GLOBUS_LIMITED_PROXY_MANY_FLAG)
    {
        context->callback_data.multiple_limited_proxy_ok = 1;
    }

    if (cred_handle == GSS_C_NO_CREDENTIAL)
    {
        if(req_flags & GSS_C_ANON_FLAG)
        {
            major_status = gss_create_anonymous_cred(
                & local_minor_status,
                &output_cred_handle,
                cred_usage);            
        }
        else
        {
            major_status = gss_acquire_cred(& local_minor_status,
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
            /* SLANG - chain minor status */
#error
            return_value = major_status;
            goto done;
        }

        context->cred_handle = output_cred_handle;
        context->cred_obtained = 1;
    }
    else
    {
        context->cred_handle = cred_handle;
        context->cred_obtained = 0;
    }

    globus_gsi_cred_handle_get_handle_attrs(
        context->cred_handle->cred_handle, & handle_attrs);
    globus_gsi_cred_handle_attrs_get_ca_cert_dir(handle_attrs, certdir);

    if (certdir)
    {
        context->callback_data.certdir = certdir;
    }
    else
    {
#error need to return error here
    }

    globus_free(certdir);

    /* setup the SSL  for the gss_shuffle routine */
  
    globus_gsi_cred_get_ssl_context(context->cred_handle->cred_handle,
                                    & ssl_context);

    context->gss_ssl = SSL_new(ssl_context);

    SSL_CTX_free(ssl_context);

    if (context->gss_ssl == NULL)
    {
#error need to add error here
        return_value = GSS_S_FAILURE;
        goto done;
    }

    if (cred_usage == GSS_C_ACCEPT)
    {
        SSL_set_ssl_method(context->gss_ssl,SSLv23_method());
        SSL_set_options(context->gss_ssl,SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1);
    }
    else
    {
        SSL_set_ssl_method(context->gss_ssl,SSLv3_method());
    }

    SSL_set_ex_data(context->gss_ssl, GLOBUS_GSI_VERIFY_CALLBACK_DATA_IDX, 
                    (char *)& context->callback_data); 

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
        3, (stderr,"SSL is at %p\n", context->gss_ssl));
    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        3, (stderr,"SSL_set_app_data to pvd %p\n", context->pvd));
    
    if ((context->gss_rbio = BIO_new(BIO_s_mem())) == NULL)
    {
        return_value = GSS_S_FAILURE;
        goto done;
    }

    if ((context->gss_wbio = BIO_new(BIO_s_mem())) == NULL)
    {
        return_value = GSS_S_FAILURE;
        goto done;
    }

    if ((context->gss_sslbio = BIO_new(BIO_f_ssl())) == NULL)
    {
        return_value = GSS_S_FAILURE;
        goto done;
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
        
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (stderr,"Ciphers available:\n"));
        sk=(STACK *)SSL_get_ciphers(context->gss_ssl);
        for (i=0; i<sk_num(sk); i++)
        {
            SSL_CIPHER_description((SSL_CIPHER *)sk_value(sk,i),
                                   buff,256);
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                3, (stderr,buff));
        }
    }

    return_value = GSS_S_COMPLETE;

 done:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;

    return return_value;
}


/**********************************************************************
Function:  gss_put_token()

Description:
	Called by init_sec_context and accept_sec_context.
	An input token is placed in the SSL read BIO

Parameters:
   
Returns:
**********************************************************************/
OM_uint32
gss_put_token(
    OM_uint32                           minor_status,
    const gss_ctx_id_desc*              context_handle,
    BIO *                               bio,
    const gss_buffer_t                  input_token)
{
    BIO *                               read_bio;
    OM_uint32                           return_value;
    static char *                       _function_name_ =
        "gss_put_token";

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
        3, (stderr,"input token: len=%d",input_token->length));

    if (input_token->length > 0)
    {
        BIO_write(read_bio,
                  input_token->value,
                  input_token->length);

        GLOBUS_I_GSI_GSSAPI_DEBUG_FNPRINTF(
            3, (stderr, input_token->length,
                "value=%s\n", input_token->value));
    }
    else
    {
#error /* add error thingy here */
        return_value = GSS_S_DEFECTIVE_TOKEN;
        goto done;
    }

    return_value = GSS_S_COMPLETE;

 done:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;

    return return_value;
}


/**********************************************************************
Function:  gss_get_token()

Description:
	Called by init_sec_context and accept_sec_context.
	An output token is created from the  SSL write BIO,

Parameters:
   
Returns:
**********************************************************************/
OM_uint32
gss_get_token(
    OM_unt32 *                          minor_status,
    const gss_ctx_id_desc*              context_handle,
    BIO *                               bio,
    const gss_buffer_t                  output_token)
{
    OM_uint32                           return_value;
    BIO *                               write_bio;

    static char *                       _function_name_ =
        "gss_get_token";
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

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
            output_token->length = 0 ;
#error /* add error thingy here */
            GSSerr(GSSERR_F_GSS_HANDSHAKE, GSSERR_R_OUT_OF_MEMORY);
            return_value = GSS_S_FAILURE;
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

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;

    return return_value;
}

/**********************************************************************
Function:  gss_handshake

Description:
	Called by init_sec_context and accept_sec_context.
 	the BIO_handshake is done again which causes the SSL 
	session to start or continue its handshake process,
	and when it waits return. 

Parameters:
   
Returns:
**********************************************************************/

OM_uint32    
gss_handshake(
    OM_unt32 *                          minor_status,
    gss_ctx_id_desc *                   context_handle)
{
    OM_uint32 major_status = 0;
    int rc;
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    /*
	 * do the BIO_do_handshake which may produce output,
	 * and endup waiting for input
	 * when completed without error, connection established
	 */
    rc = BIO_do_handshake(context_handle->gss_sslbio);
    if (rc <= 0) {
        if (!BIO_should_retry(context_handle->gss_sslbio) || 
            !BIO_should_read(context_handle->gss_sslbio)) {

            /* problem! */

            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (stderr,"disp=%d,level=%d,desc=%d,left=%d\n",
                    context_handle->gss_ssl->s3->alert_dispatch,
                    context_handle->gss_ssl->s3->send_alert[0],
                    context_handle->gss_ssl->s3->send_alert[1],
                    context_handle->gss_ssl->s3->wbuf.left));
			
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (stderr,"SSL_get_error = %d\n",
                    SSL_get_error(context_handle->gss_ssl, rc)));

            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (stderr,"shutdown=%d\n",
                    SSL_get_shutdown(context_handle->gss_ssl)));
#endif
            /* checks for ssl alert 42 */
            if (ERR_peek_error() == 
                ERR_PACK(ERR_LIB_SSL,SSL_F_SSL3_READ_BYTES,
                         SSL_R_SSLV3_ALERT_BAD_CERTIFICATE))
            {
                ERR_clear_error();
                GSSerr(GSSERR_F_GSS_HANDSHAKE,GSSERR_R_REMOTE_CERT_VERIFY_FAILED);
            }
            else
            {
                GSSerr(GSSERR_F_GSS_HANDSHAKE,GSSERR_R_HANDSHAKE);
            }

            major_status = GSS_S_DEFECTIVE_CREDENTIAL;
        }
    }

    if (!GSS_ERROR(major_status)) {
        if (rc > 0) {
            major_status = GSS_S_COMPLETE ; 

            /*
             * Set  GSS_C_CONF_FLAG if cipher uses encryption
             * which is at least 56 bit. SSL defines a number
             * of different levels, we need to map to a single GSS
             * flag. See the s3_lib.c for list of ciphers. 
             * This could be changed to SSL_MIDUM or SSL_HIGH 
             * if a site wants higher protection. 
             */

            if ((context_handle->gss_ssl->session->cipher->algo_strength
                 & SSL_STRONG_MASK) >= SSL_LOW) {
                context_handle->ret_flags |= GSS_C_CONF_FLAG;
            }

            {
                char buff[256];

                GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                    2, (stderr,"SSL handshake finished\n"));
                GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                    2, (stderr,"cred_usage=%d\n",
                        context_handle->cred_handle->cred_usage));
                GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                    2, (stderr,"Cipher being used:\n"));
                SSL_CIPHER_description(
                    context_handle->gss_ssl->session->cipher,
                    buff,256);
                GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                    2, (stderr,buff));
            }
        } else {
            major_status = GSS_S_CONTINUE_NEEDED ;
        }
    }
  
    return major_status ;
}

/**********************************************************************
Function:  gss_retrieve_peer

Description:
	Called after the handshake has completed sucessfully,
	and gets the subject name, so it can be returned to the
	call of the GSSAPI init_sec_context or accept_sec_context. 

Parameters:
   
Returns:
**********************************************************************/


OM_uint32
gss_retrieve_peer(
    OM_uint32                           minor_status,
    gss_ctx_id_desc *                   context_handle,
    const gss_cred_usage_t              cred_usage) 
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    X509 *                              peer_cert = NULL;
    STACK_OF(X509) *                    peer_cert_chain = NULL;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex;
    X509 *                              cert;
    ASN1_OBJECT *                       asn1_obj;
    ASN1_OCTET_STRING *                 asn1_oct_string;
    int                                 i;
    int                                 j = 0;
    int                                 k;
    int                                 cert_count;
    char *                              subgroup;

    static char *                       _function_name_ =
        "gss_retrieve_peer";
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
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

        result = globus_gsi_cred_set_cert(
            context_handle->peer_cred_handle->cred_handle, 
            peer_cert);

        if(result != GLOBUS_SUCCESS)
        {
#error add error object
        }

        result = globus_gsi_cred_callback_get_peer_cert_chain(
            context_handle->callback_data,
            & peer_cert_chain);

        if(result != GLOBUS_SUCCESS)
        {
#error do error here
        }

        result = globus_gsi_cred_set_cert_chain(
            context->peer_cred_handle->cred_handle, 
            peer_cert_chain);

        sk_X509_pop_free(peer_cert_chain);

        if(result != GLOBUS_SUCCESS)
        {
#error do error here
        }

        result = globus_gsi_cred_get_subject_name(
            context->peer_cred_handle->cred_handle,
            & context->peer_cred_handle->globusid->x509n);

        if(result != GLOBUS_SUCCESS)
        {
#error do error here
        }

        if(result = context->peer_cred_handle->globusid->x509n == NULL)
        {
#error add error object
            GSSerr(GSSERR_F_GSS_RETRIEVE_PEER, GSSERR_R_PROCESS_CERT);
            major_status = GSS_S_FAILURE;
            goto err;
        }

        result = globus_gsi_cred_get_base_name(
            context->peer_cred_handle->globusid->x509n);

        if(result != GLOBUS_SUCCESS)
        {
#error add error object
        }

        /* debug statement */
        { 
            char * s;
            s = X509_NAME_oneline(context->peer_cred_handle->globusid->x509n,
                                  NULL,
                                  0);
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (stderr, "X509 subject after proxy : %s\n", s));
            free(s);
        }

        cert_count = context_handle->callback_data.cert_depth;

        result = globus_gsi_cred_get_group_name(
            context_handle->peer_cred_handle->cred_handle,
            & context->peer_cred_handle->globusid->group,
            & context->peer_cred_handle->globusid->group_types);
    
        if(result != GLOBUS_SUCCESS)
        {
#error add error here
        }
    }    
    major_status = GSS_S_COMPLETE;

 err:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}

OM_uint32
gss_create_anonymous_cred(
    OM_unit32 *                         minor_status,
    gss_cred_id_t *                     output_cred_handle,
    const gss_cred_usage_t              cred_usage)
{
    gss_cred_id_desc *                  newcred;
    OM_uint32                           major_status = GSS_S_FAILURE;
    OM_uint32                           local_minor_status;

    static char *                       _function_name_ =
        "gss_create_anonymous_cred";
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    
    newcred = (gss_cred_id_desc*) malloc(sizeof(gss_cred_id_desc));

    if (newcred == NULL)
    {
        GSSerr(GSSERR_F_ACQUIRE_CRED, GSSERR_R_OUT_OF_MEMORY);
        return GSS_S_FAILURE ;
    }

    newcred->cred_usage = cred_usage;

    globus_gsi_cred_handle_init(& newcred->cred_handle, NULL);

    newcred->globusid = (gss_name_desc*) malloc(sizeof(gss_name_desc)) ;

    if (newcred->globusid == NULL)
    {
#error add error object
        GSSerr(GSSERR_F_ACQUIRE_CRED, GSSERR_R_OUT_OF_MEMORY);
        goto err;
    }
    
    newcred->globusid->name_oid = GSS_C_NT_ANONYMOUS;

    newcred->globusid->x509n = NULL;

    newcred->globusid->group = NULL;

    newcred->globusid->group_types = NULL;
    
    if (!(newcred->pcd = proxy_cred_desc_new()))
    {
#error add error object
        GSSerr(GSSERR_F_ACQUIRE_CRED, GSSERR_R_OUT_OF_MEMORY);
        goto err;
    }
    
    *output_cred_handle = newcred;
    
    major_status = GSS_S_COMPLETE;
    
err:
    gss_release_cred(& local_minor_status, (gss_cred_id_t *) & newcred);

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}

/**********************************************************************
Function:  gss_create_and_fill_cred

Description:
	Called by acquire_cred and accept_sec_context for a delegate.
	Setup the credential including the SSL_CTX

Parameters:
   
Returns:
**********************************************************************/

OM_uint32 
gss_create_and_fill_cred(
    OM_uint32 *                         minor_status,
    gss_cred_id_t *                     output_cred_handle_P,
    const gss_cred_usage_t              cred_usage,
    X509 *                              ucert,
    EVP_PKEY *                          upkey,
    STACK_OF(X509) *                    cert_chain,
    BIO *                               bp) 
{
    gss_cred_id_desc **                 output_cred_handle = 
        (gss_cred_id_desc**) output_cred_handle_P ;
    OM_uint32                           major_status = GSS_S_NO_CRED;
    OM_uint32                           local_minor_status;
    gss_cred_id_desc *                  newcred;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex;
    X509 *                              cert;
    X509 *                              previous_cert;
    ASN1_OBJECT *                       asn1_obj;
    ASN1_OCTET_STRING *                 asn1_oct_string;
    int                                 status;
    int                                 i;
    int                                 j = 0;
    int                                 k;
    int                                 cert_count;
    char *                              subgroup;

    static char *                       _function_name_ =
        "gss_create_and_fill_cred";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    *output_cred_handle = NULL;

    newcred = (gss_cred_id_desc*) malloc(sizeof(gss_cred_id_desc)) ;

    if (newcred == NULL)
    {
        GSSerr(GSSERR_F_ACQUIRE_CRED, GSSERR_R_OUT_OF_MEMORY);
        return GSS_S_FAILURE ;
    }

    newcred->cred_usage = cred_usage;
    newcred->globusid = NULL;
    
    result = globus_gsi_cred_handle_init(newcred->cred_handle, NULL);

    if (result != GLOBUS_SUCCESS)
    {
#error add error obj
        GSSerr(GSSERR_F_ACQUIRE_CRED, GSSERR_R_OUT_OF_MEMORY);
        major_status = GSS_S_FAILURE;
        goto err;
    }

    /* delegated certificate, save in pcd */

    if(bp)
    {
        result = globus_gsi_cred_read_bio(newcred->cred_handle,
                                          bp);
        if(result != GLOBUS_SUCCESS)
        {
#error add error obj
        }
    }
    else {

        if (ucert)
        {
            result = globus_gsi_cred_set_cert(newcred->cred_handle, ucert);
            if(result != GLOBUS_SUCCESS)
            {
#error add error obj
            }
        }

        if (upkey)
        {
            result = globus_gsi_cred_set_key(newcred->cred_handle, upkey);
            if(result != GLOBUS_SUCCESS)
            {
#error add error obj
            }
        }
    
        if (cert_chain)
        {
            /* Delegated credential is a proxy */
            result = globus_gsi_cred_set_cert_chain(newcred->cred_handle, 
                                                    cert_chain);
            if(result != GLOBUS_SUCCESS)
            {
#error add error obj
            }
        }
    }

    /*
     * get the globusid, which is the subject name - any proxy entries
     */

    newcred->globusid = (gss_name_desc*) malloc(sizeof(gss_name_desc)) ;
    if (newcred->globusid == NULL)
    {
#error add error obj
        GSSerr(GSSERR_F_ACQUIRE_CRED, GSSERR_R_OUT_OF_MEMORY);
        major_status = GSS_S_FAILURE;
        goto err;
    }
    newcred->globusid->name_oid = GSS_C_NO_OID;

    result = globus_gsi_cred_get_subject(newcred->cred_handle, 
                                & newcred->globusid->x509n);

    if (result != GLOBUS_SUCCESS)
    {
#error add error obj stuff
        GSSerr(GSSERR_F_ACQUIRE_CRED,GSSERR_R_PROCESS_CERT);
        major_status = GSS_S_FAILURE;
        goto err;
    }

    /* now strip off any /CN=proxy entries */

    result = globus_gsi_cred_get_base_name(newcred->globusid->x509n);
    if(result != GLOBUS_SUCCESS)
    {
#error add error
    }

    globus_gsi_cred_get_group_name(newcred->cred_handle,
                                   & newcred->globusid->group,
                                   & newcred->globusid->group_types);

    *output_cred_handle = newcred;
    
    major_status = GSS_S_COMPLETE;
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    return major_status;
    
err:

    gss_release_cred(& local_minor_status, (gss_cred_id_t *) &newcred);
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    
    return major_status;
}

int gss_verify_extensions_callback(
    globus_gsi_cred_callback_data_t     callback_data,
    X509_EXTENSION *                    extension)
{
    gss_OID_set                         extension_oids;
    ASN1_OBJECT *                       extension_obj;
    int                                 i;
    int                                 return_val;
    gss_OID_desc                        oid;

    static char *                       _function_name_ =
        "gss_verify_extensions_callback";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    extension_oids = (gss_OID_set) callback_data->extension_oids;

    if(extension_oids == GSS_C_NO_OID_SET)
    {
        return_val = 0;
        goto exit;
    }
    
    extension_obj = X509_EXTENSION_get_object(extension);

    for(i=0;i<extension_oids->count;i++)
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







