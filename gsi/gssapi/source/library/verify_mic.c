/*********************************************************************

verify_mic.c:

Description:
    GSSAPI routine check a buffer against its MIC. 

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

/**********************************************************************
Function:   gss_verify_mic

Description:
        Check a MIC of the date
Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_verify_mic(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_buffer_t                  message_buffer,
    const gss_buffer_t                  token_buffer,
    gss_qop_t *                         qop_state)
{
    gss_ctx_id_desc *                   context = context_handle;
    unsigned char *                     mac_sec;
    unsigned char *                     seq;
    unsigned char *                     p;
    EVP_MD_CTX                          md_ctx;
    const EVP_MD *                      hash;
    unsigned int                        md_size;
    size_t                              len;
    int                                 npad;
    int                                 i;
    int                                 seqtest;
    unsigned char                       md[EVP_MAX_MD_SIZE];
    OM_uint32                           major_status = GSS_S_COMPLETE;

    *minor_status = 0;

    if (context_handle == GSS_C_NO_CONTEXT)
    {
        return GSS_S_NO_CONTEXT;
    }

    if (token_buffer == NULL)
    {
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (token_buffer->value == NULL)
    {
        return GSS_S_DEFECTIVE_TOKEN;
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
        

#ifdef DEBUG
    {
        unsigned int i;
        unsigned char *p;
        fprintf(stderr,"verify_mic: len=%d mic:",
                token_buffer->length);
        p = token_buffer->value;
        for (i=0; i<token_buffer->length;i++)
        {
            fprintf(stderr,"%2.2X",*p++);
        }
        fprintf(stderr,"\n");
    }
#endif
    mac_sec= &(context->gs_ssl->s3->read_mac_secret[0]);
    seq = &(context->gs_ssl->s3->read_sequence[0]);
    hash=context->gs_ssl->read_hash;
    md_size=EVP_MD_size(hash);
    if (token_buffer->length != (md_size + 12))
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        goto err;
    }
    
    p = ((unsigned char *) token_buffer->value) + 8;
    
    n2l(p,len);
    if (message_buffer->length != len)
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        goto err;
    }

    npad=(48/md_size)*md_size;
    
    EVP_DigestInit(  &md_ctx, (EVP_MD *) hash);
    EVP_DigestUpdate(&md_ctx,mac_sec,md_size);
    EVP_DigestUpdate(&md_ctx,ssl3_pad_1,npad);
    EVP_DigestUpdate(&md_ctx,token_buffer->value,12);
    EVP_DigestUpdate(&md_ctx, message_buffer->value,
                     message_buffer->length);
    EVP_DigestFinal( &md_ctx,md,NULL);
    
    if (memcmp(md,((unsigned char *) token_buffer->value)+12,md_size))
    {
        GSSerr(GSSERR_F_VERIFY_MIC,GSSERR_R_BAD_DATE);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_BAD_SIG;
        goto err;
    }

#ifdef DEBUG
    fprintf(stderr,"verify_mic: mic match\n");
#endif
    /*
     * Now test for consistance with the MIC
     */
    
    p = token_buffer->value;
    
    seqtest = 0;
    for (i=0; i<8; i++)
    {   
        if ((seqtest = *p++ - seq[i]))
        {
            break;      
        }
    }
    
    if (seqtest > 0)
    {
        /* missed a token, reset the sequence number */
        p = token_buffer->value;
        for (i=0; i< 8; i++)
        {
            seq[i] = *p++;
        }
        major_status = GSS_S_GAP_TOKEN;
        goto err;
    }
    
    if (seqtest < 0)
    {
        /* old token, may be replay too. */
        return GSS_S_OLD_TOKEN;
    }

    /* got the correct seq number, inc the sequence */

    for (i=7; i>=0; i--)
    {
        if (++seq[i]) break;
    }
err:
    /* unlock the context mutex */
    
    globus_mutex_unlock(&context->mutex);

    return major_status;
} 

/**********************************************************************
Function:   gss_verify

Description:
        Obsolete variant of gss_verify for V1 compatability 

        Check a MIC of the date
Parameters:

Returns:
**********************************************************************/


OM_uint32 
GSS_CALLCONV gss_verify(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context_handle,
    gss_buffer_t                        message_buffer,
    gss_buffer_t                        token_buffer,
    int *                               qop_state)
{
    
    OM_uint32                           major_status;
    gss_qop_t                           tmp_qop_state;
    gss_qop_t *                         ptmp_qop_state = NULL;

    if (qop_state)
    {
        ptmp_qop_state = &tmp_qop_state;
        tmp_qop_state = *qop_state;
    }

    major_status = gss_verify_mic(minor_status,
                                  context_handle,
                                  message_buffer,
                                  token_buffer,
                                  ptmp_qop_state);
    if (qop_state)
    {
        *qop_state = tmp_qop_state;
    }

    return major_status;
}
