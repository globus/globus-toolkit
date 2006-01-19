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
* @file unwrap.c
* @author Sam Lang, Sam Meder
*
* $RCSfile$
* $Revision$
* $Date$
*/
#endif

static char *rcsid = "$Id$";

#include "gssapi.h"
#include "globus_i_gsi_gss_utils.h"
#include "gssapi_openssl.h"
#include <string.h>
#include "ssl_locl.h"

/**
 * @name Unwrap
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 *
 * GSSAPI routine to unwrap a buffer which may have been
 * received and wraped by wrap.c
 *
 * Return the data from the wrapped buffer. There may also
 * be errors, such as integraty errors. 
 * Since we can not communicate directly with our peer,
 * we can not do everything SSL could, i.e. return a token
 * for example. 
 *
 * @param minor_status
 * @param context_handle
 * @param input_message_buffer
 * @param output_message_buffer
 * @param conf_state
 * @param qop_state
 * 
 * @return
 */
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
    char                                readarea[SSL3_RT_MAX_PLAIN_LENGTH];
    unsigned char *                     input_value;
    gss_buffer_desc                     mic_buf_desc;
    gss_buffer_t                        mic_buf = &mic_buf_desc;
    gss_buffer_desc                     data_buf_desc;
    gss_buffer_t                        data_buf = &data_buf_desc;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    time_t                              context_goodtill;
    int                                 ssl_error;
    static char *                       _function_name_ =
        "gss_unwrap";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    output_message_buffer->value = NULL;
    output_message_buffer->length = 0;
    
    if (context_handle == GSS_C_NO_CONTEXT)
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Uninitialized Context")));
        goto exit;
    }

    /* lock the context mutex */
    globus_mutex_lock(&context->mutex);
    
    if(context->ctx_flags & GSS_I_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION)
    {
        time_t                          current_time;

        major_status = 
            globus_i_gsi_gss_get_context_goodtill(&local_minor_status,
                                                  context,
                                                  &context_goodtill);
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CONTEXT);
            goto exit;
        }

        current_time = time(NULL);

        if(current_time > context_goodtill)
        {
            major_status = GSS_S_CONTEXT_EXPIRED;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_EXPIRED_CREDENTIAL,
                (_GGSL("Credential has expired: %s < %s"),
                 ctime(&context_goodtill), ctime(&current_time)));
            goto exit;
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
    input_value = input_message_buffer->value;
    if ( input_message_buffer->length > 17 &&
         *input_value++ == SSL3_RT_GSSAPI_OPENSSL &&
         *input_value++ == 3 &&
         *input_value++ == 0)
    {
        if (qop_state)
        {
            *qop_state = GSS_C_QOP_GLOBUS_GSSAPI_OPENSSL_BIG;
        }

        N2S(input_value, mic_buf->length);
        input_value += 2;
        mic_buf->value = input_value; 
        data_buf->value = input_value + mic_buf->length;

        /* skip the sequence number, point at 32 bit data length */
        input_value += GSS_SSL3_WRITE_SEQUENCE_SIZE; 

        /* get data length */
        N2L(input_value, data_buf->length);  
        input_value += 4;

        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream,
                "gss_unwrap input_len=%u mic_len=%u data_len=%u\n",
                input_message_buffer->length,
                mic_buf->length,
                data_buf->length));

        if (input_message_buffer->length != 
            (5 + mic_buf->length + data_buf->length))
        {
            major_status = GSS_S_DEFECTIVE_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                (_GGSL("Couldn't create input message buffer")));
            goto exit;
        }
                
        /* gss requires us to copy the data to a new token, as the input
         * token is read only 
         */

        output_message_buffer->value = (char *) malloc(data_buf->length);
        if (output_message_buffer->value == NULL)
        {
            GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        output_message_buffer->length = data_buf->length;
        memcpy(output_message_buffer->value, 
               data_buf->value, 
               data_buf->length);

        if (conf_state)
        {
            *conf_state = GSS_INTEGRITY_ONLY;
        }

        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream,
                "gss_unwrap: calling verify_mic\n"));

        major_status = gss_verify_mic(&local_minor_status,
                                      context_handle,
                                      output_message_buffer,
                                      mic_buf,
                                      qop_state);               
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_MIC);
            goto exit;
        }
    }
    else
    {
        /* data received is straight SSL, insert into SSL input
         * stream, and read from the SSL 
         */
        major_status = globus_i_gsi_gss_put_token(&local_minor_status,
                                                  context,
                                                  NULL,
                                                  input_message_buffer);
        if (GSS_ERROR(major_status))
        {
            major_status = GSS_S_DEFECTIVE_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL);
            goto exit;
        }

        /* now get the data from SSL. 
         * We don't know how big it is, so assume the max?
         */
        while((rc = SSL_read(context->gss_ssl, 
                             readarea, sizeof(readarea))) > 0)
        {
            void * realloc_ptr;

            realloc_ptr = realloc(
                output_message_buffer->value,
                rc + output_message_buffer->length);

            if(realloc_ptr == NULL)
            {
                GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
                major_status = GSS_S_FAILURE;

                /* free allocated mem */
                if(output_message_buffer->value)
                { 
                    free(output_message_buffer->value);
                }
                
                goto exit;
                
            }

            output_message_buffer->value = realloc_ptr;

            memcpy(((char *) output_message_buffer->value) +
                   output_message_buffer->length,
                   readarea,
                   rc);
            
            output_message_buffer->length += rc;
        }
        
        if (rc < 0)
        {
            ssl_error = SSL_get_error(context->gss_ssl, rc);
            
            if(!(ssl_error == SSL_ERROR_WANT_READ))
            {
                /* Problem, we should have some data here! */
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status, 
                    GLOBUS_GSI_GSSAPI_ERROR_WRAP_BIO,
                    (_GGSL("SSL_read rc=%d"), rc));
                major_status = GSS_S_FAILURE;

                /* free allocated mem */
                if(output_message_buffer->value)
                { 
                    free(output_message_buffer->value);
                }

                goto exit;
            }
        }

        if(GLOBUS_I_GSI_GSSAPI_DEBUG(3))
        {
            BIO *                       debug_bio;
            fprintf(globus_i_gsi_gssapi_debug_fstream,
                    "output message: length = %u\n"
                    "                value  = \n",
                    output_message_buffer->length);
        
            debug_bio = BIO_new_fp(globus_i_gsi_gssapi_debug_fstream, 
                                   BIO_NOCLOSE);
            BIO_dump(debug_bio, 
                     output_message_buffer->value,
                     output_message_buffer->length);
            BIO_free(debug_bio);
        }

        if (conf_state)
        {
            if (context->gss_ssl->session->cipher->algorithms & SSL_eNULL)
            {
                *conf_state = GSS_INTEGRITY_ONLY;
            }
            else
            {
                *conf_state = GSS_CONFIDENTIALITY;
            }
        }
    }

 exit:

    /* unlock the context mutex */
    globus_mutex_unlock(&context->mutex);
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Unseal
 * @ingroup globus_gsi_gssapi
 */
/**
 * Obsolete variant of gss_wrap for V1 compatability 
 * allow for non 32 bit integer in qop_state.
 *
 * Return the data from the wrapped buffer. There may also
 * be errors, such as integraty errors. 
 * Since we can not communicate directly with our peer,
 * we can not do everything SSL could, i.e. return a token
 * for example. 
 *
 * @param minor_status
 * @param context_handle
 * @param input_message_buffer
 * @param output_message_buffer
 * @param conf_state
 * @param qop_state
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_unseal(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context_handle,
    gss_buffer_t                        input_message_buffer,
    gss_buffer_t                        output_message_buffer,
    int *                               conf_state,
    int *                               qop_state)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
        
    static char *                       _function_name_ =
        "gss_unseal";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

  major_status = gss_unwrap(&local_minor_status,
                            context_handle,
                            input_message_buffer,
                            output_message_buffer,
                            conf_state,
                            (gss_qop_t *) qop_state);

  if(GSS_ERROR(major_status))
  {
      GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
          minor_status, local_minor_status,
          GLOBUS_GSI_GSSAPI_ERROR_ENCRYPTING_MESSAGE);
  }

  GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
  return major_status;
}
/* @} */
