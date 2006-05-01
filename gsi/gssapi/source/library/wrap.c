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
 * @file wrap.c
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
 * @name Wrap Size Limit
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * GSSAPI routine to take a buffer, calculate a MIC 
 * which is returned as a token. We will use the SSL
 * protocol here. 
 * 
 * @param minor_status
 * @param context_handle
 * @param conf_req_flags
 * @param qop_req
 * @param req_output_size
 * @param max_input_size
 *
 * @return
 */
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
    OM_uint32                           major_status = GSS_S_COMPLETE;
    static char *                       _function_name_ =
        "gss_wrap_size_limit";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
 
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;
    
    if (context_handle == GSS_C_NO_CONTEXT)
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid context handle passed to function")));
        goto exit;
    }
    
    /* This may not be correct as SSL is vague about
     * the max size, and there is even a mircsoft hack as well!
     * DEE this may need work. SSL adds 
     * 1024 as overhead for ecnryption and compression. 
     * These appear to be over kill, so our max size may be
     * very low. 
     */

    if (conf_req_flag == 0 
        && qop_req == GSS_C_QOP_GLOBUS_GSSAPI_OPENSSL_BIG)
    {
        overhead = 17 + EVP_MD_size(context->gss_ssl->write_hash); 
        max = req_output_size - overhead;
        *max_input_size = max;

    }
    else 
    {
        overhead = SSL3_RT_MAX_PACKET_SIZE - SSL3_RT_MAX_PLAIN_LENGTH;

        max = req_output_size -
            (req_output_size / SSL3_RT_MAX_PACKET_SIZE + 1) * overhead;

        *max_input_size = max;
        
    }

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Wrap
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * 
 * Wrap a message for integretry and protection.
 * We do this using the SSLv3 routines, by writing to the
 * SSL bio, and pulling off the buffer from the back 
 * of the write BIO.  But we can't do everything SSL 
 * might want, such as control messages, or segment the messages
 * here, since we are forced to using the gssapi tokens,
 * and can not communicate directly with our peer. 
 * So there maybe some failures which would work with true
 * SSL. 
 *
 * @param minor_status
 * @param context_handle
 * @param conf_req_flag
 * @param qop_req
 * @param input_message_buffer
 * @param conf_state
 * @param output_message_buffer
 *
 * @return
 */
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
    OM_uint32                           local_minor_status;
    unsigned char *                     message_value;
    time_t                              context_goodtill;
    static char *                       _function_name_ =
        "gss_wrap";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if(GLOBUS_I_GSI_GSSAPI_DEBUG(3))
    {
        BIO *                           debug_bio;
        fprintf(globus_i_gsi_gssapi_debug_fstream,
                "input message: length = %u\n"
                "               value = \n",
                input_message_buffer->length);

        debug_bio = BIO_new_fp(globus_i_gsi_gssapi_debug_fstream,
                               BIO_NOCLOSE);
        BIO_dump(debug_bio,
                 input_message_buffer->value,
                 input_message_buffer->length);
    }

    output_message_buffer->value = NULL;
    output_message_buffer->length = 0;

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        2, (globus_i_gsi_gssapi_debug_fstream,
            "gss_wrap conf_req_flag=%d qop_req=%d\n",
            conf_req_flag, (int) qop_req));

    if (context_handle == GSS_C_NO_CONTEXT)
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid context handle passed to function")));
        goto exit;
    }

    /* lock the context mutex */
    
    globus_mutex_lock(&context->mutex);

    if(context->ctx_flags & GSS_I_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION)
    {
        time_t                          current_time;

        current_time = time(NULL);

        major_status = globus_i_gsi_gss_get_context_goodtill(
            &local_minor_status,
            context,
            &context_goodtill);
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CONTEXT);
            goto unlock_mutex_error;
        }

        if(current_time > context_goodtill)
        {
            major_status = GSS_S_CONTEXT_EXPIRED;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_EXPIRED_CREDENTIAL,
                (_GGSL("Expired credential: %s < %s"), 
                 ctime(&context_goodtill), ctime(&current_time)));
            goto unlock_mutex_error;
        }
    }

    if (conf_req_flag == GSS_INTEGRITY_ONLY &&
        qop_req == GSS_C_QOP_GLOBUS_GSSAPI_OPENSSL_BIG)
    {
        /* unlock the context mutex */
        globus_mutex_unlock(&context->mutex);
        
        major_status = gss_get_mic(&local_minor_status,
                                   context_handle,
                                   qop_req,
                                   input_message_buffer,
                                   mic_buf);
        if (GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_MIC);
            goto unlock_mutex_error;
        }

        /* lock the context mutex */
        globus_mutex_lock(&context->mutex);
        
        output_message_buffer->value = 
            (char *) malloc(5 + mic_buf->length + 
                           input_message_buffer->length);
        if (output_message_buffer->value == NULL)
        {
            GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
            gss_release_buffer(&local_minor_status, mic_buf);
            major_status = GSS_S_FAILURE;
            goto unlock_mutex_error;
        }

        output_message_buffer->length = 5 + mic_buf->length + 
            input_message_buffer->length;
        message_value = output_message_buffer->value;
        *message_value++ = SSL3_RT_GSSAPI_OPENSSL;
        *message_value++ = 3;
        *message_value++ = 0;
        S2N(mic_buf->length, message_value);
        message_value += 2;
        memcpy(message_value, mic_buf->value, mic_buf->length);
        message_value = message_value + mic_buf->length;
        memcpy(message_value, input_message_buffer->value,
               input_message_buffer->length);
        
        if (conf_state)
        {
            *conf_state = GSS_INTEGRITY_ONLY;
        }
    } 
    else
    {
        int rc;
        rc = SSL_write(context->gss_ssl,
                       input_message_buffer->value,
                       input_message_buffer->length);
        if (rc != input_message_buffer->length)
        {
            /* problem, did not take the whole buffer */

            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WRAP_BIO,
                (_GGSL("SSL failed wrapping entire message: "
                 "SSL_write wrote %d bytes, should be %d bytes"),
                 rc, input_message_buffer->length));
            major_status = GSS_S_FAILURE;
            goto unlock_mutex_error;
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

        /* get the data from the write BIO */
        major_status =  globus_i_gsi_gss_get_token(&local_minor_status,
                                                   context,
                                                   NULL,
                                                   output_message_buffer);
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL);
            goto unlock_mutex_error;
        }
    }

 unlock_mutex_error:

    globus_mutex_unlock(&context->mutex);

 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Seal
 * @ingroup globus_gsi_gssapi
 *
 * Obsolete variant of gss_wrap for V1 compatability
 *
 * @param minor_status
 * @param context_handle
 * @param conf_req_flag
 * @param qop_req
 * @param input_message_buffer
 * @param conf_state
 * @param output_message_buffer
 *
 * @return
 */
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
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    static char *                       _function_name_ =
        "gss_seal";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    major_status = gss_wrap(&local_minor_status,
                            context_handle,
                            conf_req_flag,
                            qop_req,
                            input_message_buffer,
                            conf_state,
                            output_message_buffer);
    
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, &local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_ENCRYPTING_MESSAGE);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */
