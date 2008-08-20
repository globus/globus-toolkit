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
 * @file gss_verify_mic
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/* borrowed from OpenSSL's s3_enc.c
 */
static unsigned char ssl3_pad_1[48]={
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 };

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#include "gssapi.h"
#include "globus_i_gsi_gss_utils.h"
#include "gssapi_openssl.h"
#include <string.h>

#include <time.h>

/**
 * @name Verify MIC
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Check a MIC of the data
 *
 * @param minor_status
 * @param context_handle
 * @param message_buffer
 * @param token_buffer
 * @param qop_state
 * 
 * @return
 */
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
    unsigned char *                     token_value;
    EVP_MD_CTX                          md_ctx;
    const EVP_MD *                      hash;
    unsigned int                        md_size;
    int                                 npad;
    int                                 index;
    int                                 buffer_len;
    int                                 seqtest;
    time_t                              context_goodtill;
    unsigned char                       md[EVP_MAX_MD_SIZE];
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;

    static char *                       _function_name_ = 
        "gss_verify_mic";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if (context_handle == GSS_C_NO_CONTEXT)
    {
        major_status =  GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid context handle (GSS_C_NO_CONTEXT) passed to function")));
        goto exit;
    }

    if (token_buffer == NULL)
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid token_buffer (NULL) passed to function")));
        goto exit;
    }

    if (token_buffer->value == NULL)
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid token_buffer (value param is NULL) passed to function")));
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
            goto exit;
        }

        if(current_time > context_goodtill)
        {
            major_status = GSS_S_CONTEXT_EXPIRED;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_EXPIRED_CREDENTIAL,
                (_GGSL("Credential expired: %s < %s"),
                 ctime(&context_goodtill), ctime(&current_time)));
            goto exit;
        }
    }

    /* DEBUG BLOCK */
    {
        int                             debug_index;
        unsigned char *                 debug_token_value;

        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream,
                "verify_mic: len=%u mic:",
                token_buffer->length));
        debug_token_value = token_buffer->value;

        for (debug_index = 0; 
             debug_index < token_buffer->length; 
             debug_index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%2.2X", (*(debug_token_value++) & 0xff)));
        }

        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\n");
    }

    mac_sec = context->gss_ssl->s3->read_mac_secret;
    seq = context->gss_ssl->s3->read_sequence;
    hash = context->gss_ssl->read_hash;

    md_size = EVP_MD_size(hash);
    if (token_buffer->length != (GSS_SSL_MESSAGE_DIGEST_PADDING + md_size))
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
            (_GGSL("Token length of %d does not match "
             "size of message digest %d"),
             token_buffer->length, 
             (GSS_SSL_MESSAGE_DIGEST_PADDING + md_size)));
        goto exit;
    }
    
    token_value = ((unsigned char *) token_buffer->value) + 
                  GSS_SSL3_WRITE_SEQUENCE_SIZE;
    
    N2L(token_value, buffer_len);
    token_value += 4;

    if (message_buffer->length != buffer_len)
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
            (_GGSL("Message buffer length of %d does not match "
             "expected length of %d in token"),
             message_buffer->length,
             buffer_len));
        goto exit;
    }

    npad = (48 / md_size) * md_size;
    
    EVP_DigestInit(&md_ctx, (EVP_MD *) hash);
    EVP_DigestUpdate(&md_ctx, mac_sec, md_size);
    EVP_DigestUpdate(&md_ctx, ssl3_pad_1, npad);
    EVP_DigestUpdate(&md_ctx, token_buffer->value, 
                     GSS_SSL_MESSAGE_DIGEST_PADDING);
    EVP_DigestUpdate(&md_ctx, message_buffer->value, 
                     message_buffer->length);
    EVP_DigestFinal(&md_ctx, md, NULL);
    
    if (memcmp(md, ((unsigned char *) token_buffer->value) + 
               GSS_SSL_MESSAGE_DIGEST_PADDING, md_size))
    {
        major_status = GSS_S_BAD_SIG;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_MIC,
            (_GGSL("Message digest and token's contents are not equal")));
        goto exit;
    }

    /*
     * Now test for consistance with the MIC
     */    
    token_value = token_buffer->value;
    
    seqtest = 0;
    for (index = 0; index < GSS_SSL3_WRITE_SEQUENCE_SIZE; index++)
    {   
        if ((seqtest = *token_value++ - seq[index]))
        {
            break;      
        }
    }
    
    if (seqtest > 0)
    {
        /* missed a token, reset the sequence number */
        token_value = token_buffer->value;
        for (index = 0; index < GSS_SSL3_WRITE_SEQUENCE_SIZE; index++)
        {
            seq[index] = *token_value++;
        }
        major_status = GSS_S_GAP_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
            (_GGSL("Missing write sequence at index: %d in the token"),
             index));
        goto exit;
    }
    
    if (seqtest < 0)
    {
        /* old token, may be replay too. */
        major_status = GSS_S_OLD_TOKEN;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
            (_GGSL("Token is too old")));
        goto exit;
    }

    /* got the correct seq number, increment the sequence */
    for (index = (GSS_SSL3_WRITE_SEQUENCE_SIZE - 1); index >= 0; index--)
    {
        if (++seq[index]) break;
    }

exit:

    /* unlock the context mutex */
    globus_mutex_unlock(&context->mutex);

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
} 
/* @} */

/**
 * @name Verify
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Obsolete variant of gss_verify for V1 compatability 
 * Check a MIC of the date
 *
 * @param minor_status
 * @param context_handle
 * @param massage_buffer
 * @param token_buffer
 * @param qop_state
 * 
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_verify(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context_handle,
    gss_buffer_t                        message_buffer,
    gss_buffer_t                        token_buffer,
    int *                               qop_state)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    static char *                       _function_name_ =
        "gss_verify";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    major_status = gss_verify_mic(&local_minor_status,
                                  context_handle,
                                  message_buffer,
                                  token_buffer,
                                  (gss_qop_t *) qop_state);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_MIC);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */
