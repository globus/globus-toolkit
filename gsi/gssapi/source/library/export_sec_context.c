
/**********************************************************************

export_sec_context.c:

Description:
	GSSAPI routine to export the security context
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
#include <string.h>

/* 
 * We need to include a non installed header file
 * #include <ssl_locl.h>
 * But for now we will include the two routines here
 */

int ssl3_setup_key_block(SSL *s);
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
Function:   gss_export_sec_context()   

Description:
    Saves the important info about the session, converts
	it to a token, then deletes the context. 

Parameters:
	
Returns:
**********************************************************************/


OM_uint32 
GSS_CALLCONV gss_export_sec_context(
    OM_uint32 *                         minor_status ,
    gss_ctx_id_t *                      context_handle_P ,
    gss_buffer_t                        interprocess_token) 
{
    
#ifdef WIN32
    return GSS_S_UNAVAILABLE;
#else
    OM_uint32                           major_status = 0;
    gss_ctx_id_desc *                   context;
    int                                 len = -1;
    int                                 i;
    int                                 peer_cert_count;
    SSL_SESSION *                       session = NULL;
    SSL *                               s;
    BIO *                               bp = NULL;
    unsigned char *                     cp;
    unsigned char                       ibuf[4];
    OM_uint32                           cred_usage;
	

#ifdef DEBUG
    fprintf(stderr,"export_sec_context:\n");
#endif /* DEBUG */

    *minor_status = 0;

    context = *context_handle_P;

    if (context_handle_P == NULL || 
        context == (gss_ctx_id_t) GSS_C_NO_CONTEXT)
    {
        GSSerr(GSSERR_F_EXPORT_SEC,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto end;
    }

    if (interprocess_token == NULL ||
        interprocess_token ==  GSS_C_NO_BUFFER)
    {
        GSSerr(GSSERR_F_EXPORT_SEC,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto end;
    }

    /* Open mem bio for writing the session */
    
    if ((bp = BIO_new(BIO_s_mem())) == NULL)
    {
        GSSerr(GSSERR_F_EXPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto end;
    }

    /* lock the context mutex */
    
    globus_mutex_lock(&context->mutex);
    
    s = context->gs_ssl;

    interprocess_token->length = 0;

    /*
     * We need to save:
     * version of this routine. 
     * cred_usage, i.e. are we accept or initiate
     * target/source or name
     * Session:  Protocol, cipher, and Master-Key
     * Client-Random
     * Server-Random
     * tmp.key_block: client and server Mac_secrets
     * write_sequence
     * read_sequence
     * write iv
     * read iv
     */ 
    
    /* version number */
    cp = ibuf;
    l2n(1,cp);
    BIO_write(bp,(char *)ibuf,4);

    /* cred_usage */
    cred_usage = 
        context->locally_initiated ? GSS_C_INITIATE : GSS_C_ACCEPT;
    cp = ibuf;
    l2n(cred_usage,cp);
    BIO_write(bp,(char *)ibuf,4);
	
    /* get session */
    
    session = SSL_get_session(s);
    if (!session)
    {
        GSSerr(GSSERR_F_EXPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto end;
    }

#ifdef DEBUG
    SSL_SESSION_print_fp(stderr, session);
#endif

    i2d_SSL_SESSION_bio(bp, session);

    /* write out the peer certificate and peer cert chain*/

    peer_cert_count = context->callback_data.cert_depth;
    
    cp = ibuf;
    l2n(peer_cert_count, cp);
    BIO_write(bp, (char *)ibuf, 4);
    
    for(i=0; i < peer_cert_count; i++)
    {
        i2d_X509_bio(bp,
                     sk_X509_value(
                         context->callback_data.cert_chain, i));
    }
	
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

    BIO_write(bp,(char *)&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
    BIO_write(bp,(char *)&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
    
    /* need to get the tmp.key_block so we can save it
     * It will have the IVs but they are initial rather
     * then the current IVs we want
     */
    
    ssl3_setup_key_block(s); 
	
#ifdef DEBUG
    {
        int j;
        fprintf(stderr,"tmp.key_block_length=%d\ntmp.key_block=",
				s->s3->tmp.key_block_length);
        for (j=0; j<s->s3->tmp.key_block_length; j++)
        {
            fprintf(stderr,"%02X",s->s3->tmp.key_block[j]);
        }
        fprintf(stderr,"\nwrite_sequence=");
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
        for (j=0; j<8; j++)
        {
            fprintf(stderr,"%02X",s->enc_write_ctx->iv[j]);
        }
        fprintf(stderr,"\nread_iv =");
        for (j=0; j<8; j++)
        {
            fprintf(stderr,"%02X",s->enc_read_ctx->iv[j]);
        }
        fprintf(stderr,"\n");
    }
#endif

    cp = ibuf;
    l2n(s->s3->tmp.key_block_length,cp);
    BIO_write(bp,(char *)ibuf,4);
    BIO_write(bp,(char *)s->s3->tmp.key_block,s->s3->tmp.key_block_length);
    BIO_write(bp,(char *)&(s->s3->write_sequence[0]),8);
    BIO_write(bp,(char *)&(s->s3->read_sequence[0]),8);
    BIO_write(bp,(char *)&(s->enc_write_ctx->iv[0]),EVP_MAX_IV_LENGTH);
    BIO_write(bp,(char *)&(s->enc_read_ctx->iv[0]),EVP_MAX_IV_LENGTH);
    
    ssl3_cleanup_key_block(s); /* clean it up */
    
    /* now get it out of the BIO and call it a token */
    
    len = BIO_pending(bp);
    if (len <= 0)
    {
        GSSerr(GSSERR_F_EXPORT_SEC,GSSERR_R_IMPEXP_BIO_SSL);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto end;
    }

    cp = (unsigned char *)malloc(len);

    if (!cp)
    {
        GSSerr(GSSERR_F_EXPORT_SEC, GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_NO_CONTEXT;
        goto end;
    }
    
    BIO_read(bp,(char *)cp,len);
    
    interprocess_token->length = len;
    interprocess_token->value = cp;
    major_status = GSS_S_COMPLETE;

    /* unlock the context mutex */
    
    globus_mutex_unlock(&context->mutex);
    
    /* Now delete the GSS context as per RFC */
#ifndef __CYGWIN__	 
    major_status = gss_delete_sec_context(minor_status,
                                          context_handle_P,
                                          GSS_C_NO_BUFFER);
    if (GSS_ERROR(major_status))
    {
        *minor_status = gsi_generate_minor_status();
    }
#endif /* !__CYGWIN */
    
end:
    BIO_free(bp);

#ifdef DEBUG
    fprintf(stderr,"export_sec_context:maj=%d, len=%d\n",
			major_status, len);
#endif

    return major_status;
#endif /* WIN32 */
}
