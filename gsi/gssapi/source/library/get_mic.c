/*********************************************************************

get_mic.c:

Description:
    GSSAPI routine to take a buffer, and calculate a MIC 
	 which is returned as a token.

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

#include "gssapi.h"
#include "gssutils.h"
#include "gssapi_ssleay.h"

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
 
/**********************************************************************
Function:   gss_get_mic

Description:
	Produces a  MIC of the date using the ssl seq, secret and hash.

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_get_mic(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    gss_qop_t                           qop_req,
    const gss_buffer_t                  message_buffer,
    gss_buffer_t                        message_token)
{
    
    /* 
     * We can't use the SSL mac methods directly,
     * partly because they only allow a length of
     * 64K, and we want to use larger blocks. 
     * We will add the seq number and 32 bit length 
     * to the mic, and send them as well. 
     * this will allow us to check for out of
     * seq records. 
     * 
     * These have 8 byte sequence number, 4 byte length, md. 
     */
 
    gss_ctx_id_desc *                   context = context_handle; 
    unsigned char *                     mac_sec;
    unsigned char *                     seq;
    unsigned char *                     p;
    EVP_MD_CTX                          md_ctx;
    const EVP_MD *                      hash;
    unsigned int                        md_size;
    int                                 npad;
    int                                 i;
    unsigned char *                     md;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    
    *minor_status = 0;

#ifdef DEBUG
    fprintf(stderr,"get_mic:\n");
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

    
    mac_sec = &(context->gs_ssl->s3->write_mac_secret[0]);
    seq = &(context->gs_ssl->s3->write_sequence[0]);
    hash = context->gs_ssl->write_hash;

    md_size = EVP_MD_size(hash);
    message_token->value = (char *)malloc(12 + md_size);

    if (message_token->value == NULL)
    {
        major_status = GSS_S_FAILURE;
        goto err;
    }

    message_token->length = 12 + md_size;
    p = message_token->value;
    
    for (i=0; i< 8; i++)
    {
        *p++ = seq[i];
    }

    for (i=7; i>=0; i--)
    {
        if (++seq[i]) break;
    }

    l2n(message_buffer->length,p);
    md = p;
    
    npad=(48/md_size)*md_size;
    
    EVP_DigestInit(  &md_ctx, (EVP_MD *) hash);
    EVP_DigestUpdate(&md_ctx,mac_sec,md_size);
    EVP_DigestUpdate(&md_ctx,ssl3_pad_1,npad);
    EVP_DigestUpdate(&md_ctx,message_token->value,12);
    EVP_DigestUpdate(&md_ctx, message_buffer->value,
                     message_buffer->length);
    EVP_DigestFinal( &md_ctx,md,NULL);

#ifdef DEBUG
    {
        unsigned int i;
        unsigned char *p;
        
        fprintf(stderr,"get_mic: len=%d mic:",message_token->length);
        p = message_token->value;
        for (i=0;  i< message_token->length; i++)
        {
            fprintf(stderr,"%2.2X",*p++);
        }
        fprintf(stderr,"\n");
    }
#endif

err:
    /* unlock the context mutex */
    
    globus_mutex_unlock(&context->mutex);

    
    return major_status;
}

/**********************************************************************
Function:   gss_sign

Description:
        Obsolete variant of gss_get_mic for V1 compatability 
Parameters:

Returns:
**********************************************************************/


OM_uint32 
GSS_CALLCONV gss_sign(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context_handle,
    int                                 qop_req,
    gss_buffer_t                        message_buffer,
    gss_buffer_t                        message_token)
    
{
    return  gss_get_mic(minor_status, 
                        context_handle,
                        qop_req,
                        message_buffer,
                        message_token);
}
