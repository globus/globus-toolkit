
/**********************************************************************

import_sec_context.c:

Description:
	GSSAPI routine to import the security context
	See: <draft-ietf-cat-gssv2-cbind-04.txt>

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
#include <openssl/crypto.h>
#include <string.h>
#include <openssl/rand.h>
#if SSLEAY_VERSION_NUMBER < 0x0090600fL
#define OPENSSL_malloc Malloc
#endif
/*
 * inorder to define a number of low level ssl routines
 * we need to include non installed header
 * #include <ssl_locl.h>
 * We will define the four routines here. 
 */

int ssl3_setup_buffers(SSL *s); 
int ssl_init_wbio_buffer(SSL *s, int push);

#if SSLEAY_VERSION_NUMBER >= 0x00904100L
int ssl_cipher_get_evp(SSL_SESSION *s,const EVP_CIPHER **enc,
                       const EVP_MD **md, SSL_COMP **comp);
#else
int ssl_cipher_get_evp(SSL_CIPHER *c, EVP_CIPHER **enc, EVP_MD **md);
#endif

void ssl3_cleanup_key_block(SSL *s);

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/**********************************************************************
Function:   gss_import_sec_context()   

Description:
    get a sec context based on the input token. 

Parameters:
	
Returns:
**********************************************************************/


OM_uint32 
GSS_CALLCONV gss_import_sec_context(
    OM_uint32 *                         minor_status ,
    const gss_buffer_t                  interprocess_token,
    gss_ctx_id_t *                      context_handle_P) 
{
#ifdef WIN32
    return GSS_S_UNAVAILABLE;
#else
    OM_uint32                           major_status = 0;
    OM_uint32                           minor_status2 = 0;
    gss_ctx_id_desc *                   context = GSS_C_NO_CONTEXT;
    SSL *                               s;
    SSL_SESSION *                       session = NULL;
    SSL_CIPHER *                        cipher;
    STACK_OF(SSL_CIPHER) *              sk;
    BIO *                               bp = NULL;
    X509 *                              peer_cert;
    unsigned char *                     cp;
    unsigned char                       ibuf[4];
    long                                len;
    long                                version;
    gss_cred_usage_t                    cred_usage;
    long                                cipher_id;
    long                                Time=time(NULL);
    int                                 i;

#ifdef DEBUG
    fprintf(stderr,"import_sec_context:\n");
#endif /* DEBUG */

    *minor_status = 0;

    /* module activation if not already done by calling
     * globus_module_activate
     */
    
    globus_thread_once(
        &once_control,
        (void (*)(void))globus_i_gsi_gssapi_module.activation_func);

    if (interprocess_token == NULL || 
        interprocess_token == GSS_C_NO_BUFFER || 
        context_handle_P == NULL)
    {
        GSSerr(GSSERR_F_IMPORT_SEC, GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_DEFECTIVE_TOKEN;
        goto err;
    }

    /*DEE should work for BOTH, for now do accept */
    /*DEE need to check, and return err otherwise */

    /* Open mem bio for reading the session */


    if ((bp = BIO_new(BIO_s_mem())) == NULL)
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }
        
    /* write the input token to the BIO so we can read it back */

    BIO_write(bp,interprocess_token->value,
              interprocess_token->length);

    /* 
     * get some of our gss specific info
     */

    BIO_read(bp,(char *)ibuf,4); /* get version */
    cp = ibuf;
    n2l(cp,version);
    if (version > 1)
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    BIO_read(bp,(char *)ibuf,4); /* get cred_usage */
    cp = ibuf;
    n2l(cp,cred_usage);
        
#ifdef DEBUG
    fprintf(stderr,"CredUsage=%d\n",cred_usage);
#endif
    /*
     * We know we are using SSLv3, and which ciphers
     * are available. We could get this from the 
     * imported session. 
     */

    major_status =
        gss_create_and_fill_context(&context,
                                    GSS_C_NO_CREDENTIAL,
                                    cred_usage,
                                    0);

    if (GSS_ERROR(major_status))
    {
        *minor_status = gsi_generate_minor_status();
        goto err;
    }

    /*
     * We need to do what the s3_srvr.c ssl_accept would do
     * during the initial handshake to get the SSL 
     * control blocks setup. But we also need to 
     * have them setup so the client does not know
     * we have started over. 
     * This is more the a renegociate, as the client does not
     * know we have transfered the context to another process. 
     */ 

    /* For simplicity and comparing to the SSLeay code use s */

    s = context->gs_ssl;

    RAND_add((unsigned char *)&Time,sizeof(Time),
             .5 /* .5 byte or 4 bits of entrophy */);

    ERR_clear_error();

    if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s);
    /* s->in_handshake = 1; */

    /* Now part of the for loop in s3_srvr.c */
    /* case SSL_ST_ACCEPT: */

    /* we do this here, and later, since SSLeay-0.9.0 has a problem*/
    if (!ssl3_setup_buffers(s))
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if (!ssl_init_wbio_buffer(s,0))
    {  /* we don't push here! */
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err; 
    } 

    /* Read the session */

    session = SSL_SESSION_new();
    session = d2i_SSL_SESSION_bio(bp,NULL);

    if (!session)
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_NO_CONTEXT;
        goto err;
    }
        
    /* get number of peer certs  (version 1 has 0 or 1) */

    BIO_read(bp,(char *)ibuf,4);
    cp = ibuf;
    n2l(cp,len);

    if(len)
    {
        context->pvd.cert_chain = sk_X509_new_null();

        for(i=1;i<len;i++)
        {
            peer_cert = d2i_X509_bio(bp,NULL);
            
            if (!peer_cert)
            {
                GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
                *minor_status = gsi_generate_minor_status();
                major_status = GSS_S_NO_CONTEXT;
                goto err;
            }
            
            sk_X509_push(context->pvd.cert_chain, peer_cert);
            context->pvd.cert_depth++;
        }

        peer_cert = d2i_X509_bio(bp,NULL);

        if (!peer_cert)
        {
            GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_NO_CONTEXT;
            goto err;
        }

        session->peer = peer_cert;

        sk_X509_push(context->pvd.cert_chain, X509_dup(peer_cert));

        context->pvd.cert_depth++;
    }

    /* need to set cipher from cipher_id in the session*/

    sk = SSL_get_ciphers(s);
    if ((session->cipher_id & 0xff000000) == 0x02000000)
    {
        cipher_id = session->cipher_id & 0xffffff;
    }
    else
    {
        cipher_id = session->cipher_id & 0xffff;
    }

    session->cipher = NULL;
    for (i=0; i<sk_SSL_CIPHER_num(sk); i++)
    {
        cipher = sk_SSL_CIPHER_value(sk,i);
        if (cipher->id == session->cipher_id)
        {
            session->cipher = cipher;
            break;
        }
    }
    
    if (!(session->cipher))
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_NO_CIPHER);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_NO_CONTEXT;
        goto err;
    }

#ifdef DEBUG
    SSL_SESSION_print_fp(stderr,session);
#endif
        
    SSL_set_session(s,session);
        
    if (!ssl3_setup_buffers(s))
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if (BIO_pending(bp) < 2*SSL3_RANDOM_SIZE)
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_NO_CONTEXT;
        goto err;
    }
    BIO_read(bp,(char*)&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
    BIO_read(bp,(char*)&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);        
                

#ifdef DEBUG
    {
        int j;
        fprintf(stderr,"client_random=");
        for (j=0; j<SSL3_RANDOM_SIZE; j++)
        {
            fprintf(stderr,"%02X",s->s3->client_random[j]);
        }
        fprintf(stderr,"\nserver_random =");
        for (j=0; j<SSL3_RANDOM_SIZE; j++)
        {
            fprintf(stderr,"%02X",s->s3->server_random[j]);
        }
        fprintf(stderr,"\n");
    }
#endif
    s->shutdown = 0;

    s->s3->tmp.new_cipher =
        s->session->cipher;
        
    /* read the tmp.key_block */
        
    if (BIO_pending(bp) < 4)
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BAD_LEN);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_NO_CONTEXT;
        goto err;
    }

    BIO_read(bp,(char*)ibuf,4); /* get length */
    cp = ibuf;
    n2l(cp,len);

    if (BIO_pending(bp) < len)
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BAD_LEN);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_NO_CONTEXT;
        goto err;
    }

    if ((s->s3->tmp.key_block = (unsigned char *)OPENSSL_malloc (len)) == NULL)
    {
        GSSerr(GSSERR_F_IMPORT_SEC, GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }
                
    s->s3->tmp.key_block_length = len;
    BIO_read(bp,(char*)s->s3->tmp.key_block,s->s3->tmp.key_block_length);

#ifdef DEBUG
    {
        int j;
        fprintf(stderr,"tmp.key_block_length=%d\ntmp.key_block=",
                s->s3->tmp.key_block_length);
        for (j=0; j<s->s3->tmp.key_block_length; j++)
        {
            fprintf(stderr,"%02X",s->s3->tmp.key_block[j]);
        }
        fprintf(stderr,"\n");
    }
#endif

#if SSLEAY_VERSION_NUMBER >= 0x00904100L
    if (!ssl_cipher_get_evp(s->session,
                            &s->s3->tmp.new_sym_enc,
                            &s->s3->tmp.new_hash,
                            (SSL_COMP **) &s->s3->tmp.new_compression))
    {
#else
    if (!ssl_cipher_get_evp(s->session->cipher,
                            &s->s3->tmp.new_sym_enc,
                            &s->s3->tmp.new_hash))
    {
#endif
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = GSSERR_R_IMPEXP_BIO_SSL;
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if (!s->method->ssl3_enc->change_cipher_state(
            s,
            SSL3_CHANGE_CIPHER_SERVER_WRITE))
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = GSSERR_R_IMPEXP_BIO_SSL;
        major_status = GSS_S_FAILURE;
        goto err;
    }

#if SSLEAY_VERSION_NUMBER >= 0x00904100L
    if (!ssl_cipher_get_evp(s->session,
                            &s->s3->tmp.new_sym_enc,
                            &s->s3->tmp.new_hash,
                            (SSL_COMP **) &s->s3->tmp.new_compression))
    {
#else
    if (!ssl_cipher_get_evp(s->session->cipher,
                            &s->s3->tmp.new_sym_enc,
                            &s->s3->tmp.new_hash))
    {
#endif
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = GSSERR_R_IMPEXP_BIO_SSL;
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    if (!s->method->ssl3_enc->change_cipher_state(
            s,
            SSL3_CHANGE_CIPHER_SERVER_READ))
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = GSSERR_R_IMPEXP_BIO_SSL;
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    s->hit = 1;
    
    s->state = SSL_ST_OK;
    ssl3_cleanup_key_block(s); /* will free the one we read */
    
    len = BIO_pending(bp);
    if (len != 8 + 8 + EVP_MAX_IV_LENGTH + EVP_MAX_IV_LENGTH)
    {
        GSSerr(GSSERR_F_IMPORT_SEC,GSSERR_R_IMPEXP_BAD_LEN);
        *minor_status = GSSERR_R_IMPEXP_BAD_LEN;
        major_status = GSS_S_NO_CONTEXT;
    }
    
    BIO_read(bp,(char*)&(s->s3->write_sequence[0]),8);
    BIO_read(bp,(char*)&(s->s3->read_sequence[0]),8);
    BIO_read(bp,(char*)&(s->enc_write_ctx->iv[0]),EVP_MAX_IV_LENGTH);
    BIO_read(bp,(char*)&(s->enc_read_ctx->iv[0]),EVP_MAX_IV_LENGTH);
    
#ifdef DEBUG
    {
        int j;
        fprintf(stderr,"write_sequence=");
        for (j=0; j<8; j++)
        {
            fprintf(stderr,"%02X",s->s3->write_sequence[j]);
        }
        fprintf(stderr,"\nread_sequence =");
        for (j=0; j<8; j++)
        {
            fprintf(stderr,"%02X",s->s3->read_sequence[j]);
        }
        fprintf(stderr,"\nwrite_iv=");
        for (j=0; j<EVP_MAX_IV_LENGTH; j++)
        {
            fprintf(stderr,"%02X",s->enc_write_ctx->iv[j]);
        }
        fprintf(stderr,"\nread_iv =");
        for (j=0; j<EVP_MAX_IV_LENGTH; j++)
        {
            fprintf(stderr,"%02X",s->enc_read_ctx->iv[j]);
        }
        fprintf(stderr,"\n");
    }
#endif

    gs_retrieve_peer(context, cred_usage);
    
    s->new_session=0;
    s->init_num=0;
    
    s->in_handshake = 0;
    
    *context_handle_P = context;
    context = GSS_C_NO_CONTEXT;
    major_status = GSS_S_COMPLETE;

err:
    BIO_free(bp);
    if (context)
    {
        gss_delete_sec_context(&minor_status2,
                               (gss_ctx_id_t *)&context,
                               GSS_C_NO_BUFFER);
    }

#ifdef DEBUG
    fprintf(stderr,"import_sec_context:maj=%d,min=%d\n",
            major_status,*minor_status);
#endif
    
    return major_status;
#endif /* WIN32 */
}
    
