/*********************************************************************

wrap.c:

Description:
    GSSAPI routine to take a buffer, calculate a MIC 
         which is returned as a token. We will use the SSL
        protocol here. 
        

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

#include "globus_gssapi_config.h"
#include "gssapi.h"
#include "gssutils.h"
#include "gssapi_ssleay.h"
#include <string.h>

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/
 
static unsigned char ssl3_pad_1[48]={
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
    0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 };

static unsigned char ssl3_pad_2[48]={
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
    0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c };

static int ssl3_mac(
    SSL *                               ssl,
    unsigned char *                     md,
    int                                 send)
{
    SSL3_RECORD *                       rec;
    unsigned char *                     mac_sec;
    unsigned char *                     seq;
    EVP_MD_CTX                          md_ctx;
    const EVP_MD *                      hash;
    unsigned char *                     p;
    unsigned char                       rec_char;
    unsigned int                        md_size;
    int                                 npad;
    int                                 i;

    if (send)
    {
        rec= &(ssl->s3->wrec);
        mac_sec= &(ssl->s3->write_mac_secret[0]);
        seq= &(ssl->s3->write_sequence[0]);
        hash=ssl->write_hash;
    }
    else
    {
        rec= &(ssl->s3->rrec);
        mac_sec= &(ssl->s3->read_mac_secret[0]);
        seq= &(ssl->s3->read_sequence[0]);
        hash=ssl->read_hash;
    }

    md_size=EVP_MD_size(hash);
    npad=(48/md_size)*md_size;

    /* Chop the digest off the end :-) */

    EVP_DigestInit(  &md_ctx, (EVP_MD *) hash);
    EVP_DigestUpdate(&md_ctx,mac_sec,md_size);
    EVP_DigestUpdate(&md_ctx,ssl3_pad_1,npad);
    EVP_DigestUpdate(&md_ctx,seq,8);
    rec_char=rec->type;
    EVP_DigestUpdate(&md_ctx,&rec_char,1);
    p=md;
    s2n(rec->length,p);
    EVP_DigestUpdate(&md_ctx,md,2);
    EVP_DigestUpdate(&md_ctx,rec->input,rec->length);
    EVP_DigestFinal( &md_ctx,md,NULL);

    EVP_DigestInit(  &md_ctx, (EVP_MD *) hash);
    EVP_DigestUpdate(&md_ctx,mac_sec,md_size);
    EVP_DigestUpdate(&md_ctx,ssl3_pad_2,npad);
    EVP_DigestUpdate(&md_ctx,md,md_size);
    EVP_DigestFinal( &md_ctx,md,&md_size);

    for (i=7; i>=0; i--)
        if (++seq[i]) break;
    
    return(md_size);
}

/*********************************************************************
Function:       gss_wrap_size_limit

Description:
        Return the max size allowed.
Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_wrap_size_limit(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    int                                 conf_req_flag,
    gss_qop_t                           qop_req,
    OM_uint32                           req_output_size,
    OM_uint32 *                         max_input_size)
{
    gss_ctx_id_desc *                   context =
        (gss_ctx_id_desc *)context_handle;
    OM_uint32                           max;
    OM_uint32                           overhead;
 
    *minor_status = 0;
    
    if (context_handle == GSS_C_NO_CONTEXT)
    {
        return GSS_S_NO_CONTEXT;
    }

        /*
         * This may not be correct as SSL is vague about
         * the max size, and there is even a mircsoft hack as well!
         * DEE this may need work. SSL adds 
         * 1024 as overhead for ecnryption and compression. 
         * These appear to be over kill, so our max size may be
         * very low. 
         */

    if (conf_req_flag == 0 
        && qop_req == GSS_C_QOP_GLOBUS_GSSAPI_SSLEAY_BIG)
    {
        overhead = 17 + EVP_MD_size(context->gs_ssl->write_hash); 
        max =  req_output_size - overhead;
        *max_input_size = max;
        
        return GSS_S_COMPLETE;
    }
    else if (conf_req_flag == 0)
    {
        overhead = SSL3_RT_MAX_PACKET_SIZE - SSL3_RT_MAX_PLAIN_LENGTH;
        
        if (req_output_size > SSL3_RT_MAX_PACKET_SIZE)
        {
            max = SSL3_RT_MAX_PACKET_SIZE - overhead;
        }
        else
        {
            max = req_output_size - overhead;
        }
        *max_input_size = max;
        
        return GSS_S_COMPLETE;
    }
    else
    {
        overhead = SSL3_RT_MAX_PACKET_SIZE - SSL3_RT_MAX_PLAIN_LENGTH;
        
        if (req_output_size > SSL3_RT_MAX_PACKET_SIZE)
        {
            max = SSL3_RT_MAX_PACKET_SIZE - overhead;
        }
        else
        {
            max = req_output_size - overhead;
        }
        *max_input_size = max;
        
        return GSS_S_COMPLETE;
    }
}

/**********************************************************************
Function:   gss_wrap

Description:
        Wrap a message for integretry and protection.
        We do this using the SSLv3 routines, by writing to the
        SSL bio, and pulling off the buffer from the back 
        of the write BIO.  But we can't do everything SSL 
        might want, such as control messages, or segment the messages
        here, since we are forced to using the gssapi tokens,
        and can not communicate directly with our peer. 
        So there maybe some failures which would work with true
        SSL. 
        

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_wrap(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    int                                 conf_req_flag,
    gss_qop_t                           qop_req,
    const gss_buffer_t                  input_message_buffer,
    int *                               conf_state,
    gss_buffer_t                        output_message_buffer)
{
    gss_ctx_id_desc *                   context =
        (gss_ctx_id_desc *)context_handle; 
    gss_buffer_desc                     mic_buf_desc;
    gss_buffer_t                        mic_buf =
        (gss_buffer_desc *) &mic_buf_desc;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           minor_status2;
    unsigned char *                     p;
    
    *minor_status = 0;
    output_message_buffer->value = NULL;
    output_message_buffer->length = 0;
    
#ifdef DEBUG
    fprintf(stderr,"gss_warp conf_req_flag=%d qop_req=%d\n",
            conf_req_flag, qop_req);
#endif

    if (context_handle == GSS_C_NO_CONTEXT)
    {
        return GSS_S_NO_CONTEXT;
    }

    /* lock the context mutex */
    
    globus_mutex_lock(&context->mutex);

    
    if(context->ctx_flags & GSS_I_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION)
    {
        time_t                          current_time;

        current_time = time(NULL);

        if(current_time > context->goodtill)
        {
            major_status = GSS_S_CONTEXT_EXPIRED;
            goto err;
        }
    }

    if (conf_req_flag == 0 
        && qop_req == GSS_C_QOP_GLOBUS_GSSAPI_SSLEAY_BIG)
    {
        
        /*
         * Do our integrity protection using the get_mic
         * Allows for large blocks, no encryption. 
         * Not pure SSL.  
         * DEE Should check compatability flag too. 
         */

        /* unlock the context mutex */
        
        globus_mutex_unlock(&context->mutex);
        
        if ((major_status = gss_get_mic(minor_status,
                                        context_handle,
                                        qop_req,
                                        input_message_buffer,
                                        mic_buf)) != GSS_S_COMPLETE)
        {
            return  major_status;
        }

        /* lock the context mutex */
        
        globus_mutex_lock(&context->mutex);
        
        output_message_buffer->value = 
            (char *)malloc(5 + mic_buf->length + 
                           input_message_buffer->length);
        if (output_message_buffer->value == NULL)
        {
            GSSerr(GSSERR_F_WRAP, GSSERR_R_OUT_OF_MEMORY);
            *minor_status = gsi_generate_minor_status();
            gss_release_buffer(&minor_status2, mic_buf);
            major_status = GSS_S_FAILURE;
            goto err;
        }

        output_message_buffer->length = 5 + mic_buf->length + 
            input_message_buffer->length;
        p = output_message_buffer->value;
        *p++ = SSL3_RT_GSSAPI_SSLEAY;
        *p++ = 3;
        *p++ = 0;
        s2n(mic_buf->length,p);
        memcpy(p, mic_buf->value, mic_buf->length);
        p = &p[mic_buf->length];
        memcpy(p, input_message_buffer->value,
               input_message_buffer->length);
        
        if (conf_state)
        {
            *conf_state = 0;
        }
    } 
    else
    {
        int rc;
        rc = SSL_write(context->gs_ssl,
                       input_message_buffer->value,
                       input_message_buffer->length);
        if (rc != input_message_buffer->length)
        {
            char errbuf[256];

            /* problem, did not take the whole buffer */

            GSSerr(GSSERR_F_WRAP,GSSERR_R_WRAP_BIO);
            *minor_status = gsi_generate_minor_status();
            sprintf(errbuf,"\nSSL_write rc=%d length=%d SSLerr=%d",
                    rc,
                    input_message_buffer->length,
                    SSL_get_error(context->gs_ssl, rc));
            ERR_add_error_data(1,errbuf);
            major_status = GSS_S_FAILURE;
            goto err;
        }
        if (conf_state)
        {
            if (context->gs_ssl->session->cipher->algorithms
                & SSL_eNULL)
            {
                *conf_state = 0;
            }
            else
            {
                *conf_state = 1;
            }
        }
        /* get the data from the write BIO */
        
        major_status =  gs_get_token(context,
                                     NULL,
                                     output_message_buffer);
    }
err:
    /* unlock the context mutex */
    
    globus_mutex_unlock(&context->mutex);

    return major_status;
}

/**********************************************************************
Function:   gss_seal

Description:
        Obsolete variant of gss_wrap for V1 compatability


Parameters:

Returns:
**********************************************************************/


OM_uint32 
GSS_CALLCONV gss_seal(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context_handle,
    int                                 conf_req_flag,
    int                                 qop_req,
    gss_buffer_t                        input_message_buffer,
    int *                               conf_state,
    gss_buffer_t                        output_message_buffer)
{
    return gss_wrap(minor_status,
                    context_handle,
                    conf_req_flag,
                    qop_req,
                    input_message_buffer,
                    conf_state,
                    output_message_buffer);
}











