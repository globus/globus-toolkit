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
 * @file verify_mic.c
 * @author Sam Lang, Sam Meder
 */

/* borrowed from OpenSSLs s3_enc.c
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

static
OM_uint32
globus_l_gss_verify_mic_old(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const EVP_MD *                      hash,
    const EVP_CIPHER *                  cipher,
    const gss_buffer_t                  message_buffer,
    const gss_buffer_t                  token_buffer,
    gss_qop_t *                         qop_state);

static
OM_uint32
globus_l_gss_verify_mic_new(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const EVP_MD *                      hash,
    const EVP_CIPHER *                  cipher,
    const gss_buffer_t                  message_buffer,
    const gss_buffer_t                  token_buffer,
    gss_qop_t *                         qop_state);

/**
 * @brief Verify MIC
 * @ingroup globus_gsi_gssapi
 * @details
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
    const EVP_MD *                      hash = NULL;
    const EVP_CIPHER *                  evp_cipher = NULL;
    time_t                              context_goodtill;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;

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
    if (globus_i_gsi_gssapi_debug_level >= 2)
    {
        unsigned char *                 debug_token_value;

        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream,
                "verify_mic: len=%zd mic:",
                token_buffer->length));
        debug_token_value = token_buffer->value;

        for (int debug_index = 0; 
             debug_index < token_buffer->length; 
             debug_index++)
        {
            GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                    "%2.2X", (*(debug_token_value++) & 0xff)));
        }

        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "\n");
    }
    major_status = globus_i_gss_get_hash(
            minor_status,
            context_handle,
            &hash,
            &evp_cipher);

    if (major_status!= GSS_S_COMPLETE)
    {
        goto unlock_mutex;
    }

    major_status = GSS_S_FAILURE;
    if (g_OID_equal(context_handle->mech, gss_mech_globus_gssapi_openssl)
        || globus_i_accept_backward_compatible_mic)
    {
        major_status = globus_l_gss_verify_mic_old(
                minor_status,
                context_handle,
                hash,
                evp_cipher,
                message_buffer,
                token_buffer,
                qop_state);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10000100L
    if (major_status == GSS_S_FAILURE || major_status == GSS_S_BAD_SIG)
    {
        major_status = globus_l_gss_verify_mic_new(
                minor_status,
                context_handle,
                hash,
                evp_cipher,
                message_buffer,
                token_buffer,
                qop_state);
    }
#endif


unlock_mutex:
exit:

    /* unlock the context mutex */
    globus_mutex_unlock(&context->mutex);

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}

static
OM_uint32
globus_l_gss_verify_mic_old(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const EVP_MD *                      hash,
    const EVP_CIPHER *                  cipher,
    const gss_buffer_t                  message_buffer,
    const gss_buffer_t                  token_buffer,
    gss_qop_t *                         qop_state)
{
    OM_uint32                           major_status = GSS_S_FAILURE;
    unsigned char *                     mac_sec = NULL;
    unsigned char *                     seq = NULL;
    int                                 seqtest = 0;
    int                                 md_size = 0;
    const unsigned char *               token_value = NULL;
    int                                 buffer_len = 0;
    int                                 npad = 0;
    EVP_MD_CTX *                        md_ctx = NULL;
    unsigned char                       md[EVP_MAX_MD_SIZE] = {0};

    if (hash != NULL)
    {
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                "verify_mic: verifying OLD MIC\n"));

        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        {
            mac_sec = context_handle->gss_ssl->s3->read_mac_secret;
            seq = context_handle->gss_ssl->s3->read_sequence;
        }
        #endif
        if (mac_sec == NULL || seq == NULL)
        {
            GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
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

        md_ctx = EVP_MD_CTX_create();
        EVP_DigestInit(md_ctx, (EVP_MD *) hash);
        EVP_DigestUpdate(md_ctx, mac_sec, md_size);
        EVP_DigestUpdate(md_ctx, ssl3_pad_1, npad);
        EVP_DigestUpdate(md_ctx, token_buffer->value, 
                         GSS_SSL_MESSAGE_DIGEST_PADDING);
        EVP_DigestUpdate(md_ctx, message_buffer->value, 
                         message_buffer->length);
        EVP_DigestFinal(md_ctx, md, NULL);
        EVP_MD_CTX_destroy(md_ctx);

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
         * Now test for consistency with the MIC
         */    
        token_value = token_buffer->value;

        seqtest = 0;
        for (int i = 0; i < GSS_SSL3_WRITE_SEQUENCE_SIZE; i++)
        {   
            if ((seqtest = *token_value++ - seq[i]))
            {
                break;      
            }
        }

        if (seqtest > 0)
        {
            /* missed a token, reset the sequence number */
            token_value = token_buffer->value;
            for (int i = 0; i < GSS_SSL3_WRITE_SEQUENCE_SIZE; i++)
            {
                seq[i] = *token_value++;
            }
            /* increment the sequence */
            for (int i = (GSS_SSL3_WRITE_SEQUENCE_SIZE - 1); i >= 0; i--)
            {
                if (++seq[i]) break;
            }
            major_status = GSS_S_GAP_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                (_GGSL("Gap in token sequence numbers")));
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
        for (int i = (GSS_SSL3_WRITE_SEQUENCE_SIZE - 1); i >= 0; i--)
        {
            if (++seq[i]) break;
        }
        major_status = GSS_S_COMPLETE;
    }

exit:
    return major_status;
}

static
OM_uint32
globus_l_gss_verify_mic_new(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const EVP_MD *                      hash,
    const EVP_CIPHER *                  cipher,
    const gss_buffer_t                  message_buffer,
    const gss_buffer_t                  token_buffer,
    gss_qop_t *                         qop_state)
{
    OM_uint32                           major_status = GSS_S_FAILURE;
    unsigned char *                     mac_sec = NULL;
    uint64_t                            message_sequence = 0;
    int                                 md_size = 0;
    const unsigned char *               token_value = NULL;
    int                                 buffer_len = 0;
    int                                 npad = 0;
    EVP_MD_CTX *                        md_ctx = NULL;
    unsigned char                       md[EVP_MAX_MD_SIZE] = {0};

    if (hash != NULL)
    {
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
                2, (globus_i_gsi_gssapi_debug_fstream,
                "verify_mic: verifying MICv2\n"));

        #if OPENSSL_VERSION_NUMBER >= 0x10000100L
        {
            mac_sec = context_handle->mac_key;
        }
        #endif

        if (mac_sec == NULL)
        {
            GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
            major_status = GSS_S_FAILURE;
            goto exit;
        }
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

        token_value = ((unsigned char *) token_buffer->value)
                + sizeof(uint64_t);

        N2L(token_value, buffer_len);

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

        md_ctx = EVP_MD_CTX_create();
        EVP_DigestInit(md_ctx, (EVP_MD *) hash);
        EVP_DigestUpdate(md_ctx, mac_sec, md_size);
        EVP_DigestUpdate(md_ctx, ssl3_pad_1, npad);
        EVP_DigestUpdate(md_ctx, token_buffer->value, 
                         GSS_SSL_MESSAGE_DIGEST_PADDING);
        EVP_DigestUpdate(md_ctx, message_buffer->value, 
                         message_buffer->length);
        EVP_DigestFinal(md_ctx, md, NULL);
        EVP_MD_CTX_destroy(md_ctx);

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
         * Now test for consistency with the MIC
         */    
        token_value = token_buffer->value;

        N2U64(token_value, message_sequence);
        if (message_sequence > context_handle->mac_read_sequence)
        {
            /* missed a token, reset the sequence number */
            context_handle->mac_read_sequence = message_sequence+1;

            major_status = GSS_S_GAP_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                (_GGSL("Gap in token sequence numbers")));
            goto exit;
        }
        else if (message_sequence < context_handle->mac_read_sequence)
        {
            /* old token, may be replay too. */
            major_status = GSS_S_OLD_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                (_GGSL("Token is too old")));
            goto exit;
        }
        else
        {
            /* got the correct seq number, increment the sequence */
            context_handle->mac_read_sequence++;
            major_status = GSS_S_COMPLETE;
        }
    }
#ifdef EVP_CIPH_GCM_MODE
    else if (cipher != NULL
        && EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
    {
        size_t                          iv_len=EVP_CIPHER_iv_length(cipher);
        unsigned char                   iv[iv_len];
        const unsigned char            *intag = NULL;
        unsigned char                   outtag[16] = {0};
        uint64_t                        message_sequence = 0;

        /*
         * Message Token:
         * 8 byte sequence (big endian)
         * 4 byte input length (big endian)
         * 16 byte mac
         */
        if (token_buffer->length != (8 + 4 + 16))
        {
            major_status = GSS_S_DEFECTIVE_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                (_GGSL("Token length of %d does not match "
                 "size of message digest %d"),
                 token_buffer->length, 
                 (8+4+16)));
            goto exit;
        }

        /* IV is 8 byte sequence followed the first n bytes from mac_iv_fixed */
        memcpy(iv, token_buffer->value, 8);
        memcpy(iv + 8, context_handle->mac_iv_fixed, iv_len - 8);

        token_value = token_buffer->value;
        token_value += 8;
        N2L(token_value, buffer_len);

        token_value += 4;
        intag = token_value;

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
        major_status = globus_i_gssapi_gsi_gmac(
                minor_status,
                cipher,
                iv,
                context_handle->mac_key,
                message_buffer,
                outtag);
        /*
         * Now test for consistency with the MIC
         */    
        if (memcmp(intag, outtag, 16) != 0)
        {
            major_status = GSS_S_BAD_SIG;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_MIC,
                (_GGSL("Message digest and token's contents are not equal")));
            goto exit;
        }

        /* Check for sequence violations */
        token_value = token_buffer->value;
        N2U64(token_value, message_sequence);

        if (message_sequence > context_handle->mac_read_sequence)
        {
            /* missed a token, reset the sequence number */
            context_handle->mac_read_sequence = message_sequence+1;

            major_status = GSS_S_GAP_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                (_GGSL("Gap in token sequence numbers")));
            goto exit;
        }
        else if (message_sequence < context_handle->mac_read_sequence)
        {
            /* old token, may be replay too. */
            major_status = GSS_S_OLD_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                (_GGSL("Token is too old")));
            goto exit;
        }
        else
        {
            /* got the correct seq number, increment the sequence */
            context_handle->mac_read_sequence++;
            major_status = GSS_S_COMPLETE;
        }
    }
#endif

exit:
    return major_status;
}



/**
 * @brief Verify
 * @ingroup globus_gsi_gssapi
 * @details
 * Obsolete variant of gss_verify for V1 compatibility 
 * Check a MIC of the date
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
GSS_CALLCONV gss_verify(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context_handle,
    gss_buffer_t                        message_buffer,
    gss_buffer_t                        token_buffer,
    int *                               qop_state)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;

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
/* gss_verify() */
