/*********************************************************************

unwrap.c

Description:
    GSSAPI routine to unwrap a buffer which may have been
        received and wraped by wrap.c

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

/**********************************************************************
Function:   gss_unwrap

Description:
        Return the data from the wrapped buffer. There may also
        be errors, such as integraty errors. 
        Since we can not communicate directly with our peer,
        we can not do everything SSL could, i.e. return a token
        for example. 

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_unwrap(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_buffer_t                  input_message_buffer,
    gss_buffer_t                        output_message_buffer,
    int *                               conf_state, 
    gss_qop_t *                         qop_state)
{
    gss_ctx_id_desc *                   context =
        (gss_ctx_id_desc *)context_handle; 
    int                                 rc;
    int                                 ssl_error;
    char                                readarea[SSL3_RT_MAX_PLAIN_LENGTH];
    unsigned char *                     p;
    gss_buffer_desc                     mic_buf_desc;
    gss_buffer_t                        mic_buf = &mic_buf_desc;
    gss_buffer_desc                     data_buf_desc;
    gss_buffer_t                        data_buf = &data_buf_desc;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    
    *minor_status = 0;
    output_message_buffer->value = NULL;
    output_message_buffer->length = 0;
    
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

    
    if (qop_state)
    {
        *qop_state = GSS_C_QOP_DEFAULT; 
    }
    
    /*
     * see if the token is a straight SSL packet or 
     * one of ours made by wrap using get_mic
     */

    p = input_message_buffer->value;
    if ( input_message_buffer->length > 17 &&
         *p++ == SSL3_RT_GSSAPI_SSLEAY &&
         *p++ == 3 &&
         *p++ == 0)
    {
        if (qop_state)
        {
            *qop_state = GSS_C_QOP_GLOBUS_GSSAPI_SSLEAY_BIG;
        }

        n2s(p,mic_buf->length);
        mic_buf->value = p; 
        data_buf->value = &p[mic_buf->length];
        p = &p[8]; /* skip the sequence number, point at 32 bit data length */
        n2l(p,data_buf->length);  /* get data length */

#ifdef DEBUG
        fprintf(stderr,
                "gss_unwrap input_len=%d mic_len=%d data_len=%d\n",
                input_message_buffer->length,
                mic_buf->length,
                data_buf->length);
#endif

        if (input_message_buffer->length != 
            (5 + mic_buf->length + data_buf->length))
        {
            major_status = GSS_S_DEFECTIVE_TOKEN;
            goto err;
        }
                
        /*
          gss requires us to copy the data to a new token, as the input
          * token is read only 
          */

        output_message_buffer->value = (char *)malloc(data_buf->length);
        if ( output_message_buffer->value == NULL)
        {
            GSSerr(GSSERR_F_UNWRAP, GSSERR_R_OUT_OF_MEMORY);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_FAILURE;
            goto err;
        }
        output_message_buffer->length = data_buf->length;
        memcpy(output_message_buffer->value, 
               data_buf->value,
               data_buf->length);

        if (conf_state)
        {
            *conf_state = 0;
        }


#ifdef DEBUG
        fprintf(stderr,"gss_unwrap: calling verify_mic\n");
#endif
        major_status = gss_verify_mic(minor_status,
                                      context_handle,
                                      output_message_buffer,
                                      mic_buf,
                                      qop_state);               
    }
    else
    {
        /*
         * data received is straight SSL, insert into SSL input
         * stream, and read from the SSL 
         */

        if (gs_put_token(context,
                         NULL,
                         input_message_buffer) != GSS_S_COMPLETE)
        {
            major_status = GSS_S_DEFECTIVE_TOKEN;
            goto err;
        }

        /* now get the date from SSL. 
         * We don't know how big it is, so assume the max?
         */

        rc = SSL_read(context->gs_ssl, readarea, sizeof(readarea));
        if (rc < 0)
        {
            ssl_error = SSL_get_error(context->gs_ssl, rc);
            
            if(ssl_error == SSL_ERROR_WANT_READ)
            {
                output_message_buffer->value = NULL;
                output_message_buffer->length = 0;
            }
            else
            { 
                char errbuf[256];
                
                /* Problem, we should have some data here! */
                
                GSSerr(GSSERR_F_UNWRAP,GSSERR_R_WRAP_BIO);
                sprintf(errbuf,"\n        SSL_read rc=%d SSLerr=%d",
                        rc,ssl_error);
                ERR_add_error_data(1,errbuf);
                *minor_status = gsi_generate_minor_status();
                major_status = GSS_S_FAILURE;
                goto err;
            }
        }
        else if (rc == 0)
        {
            output_message_buffer->value = NULL;
            output_message_buffer->length = rc;
        }
        else
        {
            if ((output_message_buffer->value = (char *)malloc(rc)) == NULL)
            {
                major_status = GSS_S_FAILURE;
                goto err;
            }
            output_message_buffer->length = rc;
            memcpy(output_message_buffer->value, readarea, rc);
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
    }
err:
    /* unlock the context mutex */
    
    globus_mutex_unlock(&context->mutex);

    return major_status;
}

/**********************************************************************
Function:   gss_unseal

Description:
        Obsolete variant of gss_wrap for V1 compatability 
        allow for non 32 bit integer in qop_state.

        Return the data from the wrapped buffer. There may also
        be errors, such as integraty errors. 
        Since we can not communicate directly with our peer,
        we can not do everything SSL could, i.e. return a token
        for example. 

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_unseal(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context_handle,
    gss_buffer_t                        input_message_buffer,
    gss_buffer_t                        output_message_buffer,
    int *                               conf_state,
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

  major_status = gss_unwrap(minor_status,
                            context_handle,
                            input_message_buffer,
                            output_message_buffer,
                            conf_state,
                            ptmp_qop_state);
  if (qop_state)
  {
      *qop_state = tmp_qop_state;
  }

  return major_status;
}


