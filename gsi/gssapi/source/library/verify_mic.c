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
    int                                 hash_nid = NID_undef;
    int                                 cipher_nid = NID_undef;
    unsigned char *                     mac_sec;
    unsigned char *                     seq;
    unsigned char *                     token_value;
    EVP_MD_CTX *                        md_ctx = NULL;
    const EVP_MD *                      hash = NULL;
    const EVP_CIPHER *                  evp_cipher = NULL;
    const SSL_CIPHER *                  cipher = NULL;
    unsigned int                        md_size;
    int                                 npad;
    int                                 index;
    int                                 buffer_len;
    int                                 seqtest;
    time_t                              context_goodtill;
    unsigned char                       md[EVP_MAX_MD_SIZE];
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
        int                             debug_index;
        unsigned char *                 debug_token_value;

        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream,
                "verify_mic: len=%zd mic:",
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

    #if OPENSSL_VERSION_NUMBER < 0x10000000L
    hash_nid = EVP_MD_type(context->gss_ssl->read_hash);
    #elif OPENSSL_VERSION_NUMBER < 0x10100000L
    if (context->gss_ssl->read_hash->digest != NULL)
    {
        hash_nid = EVP_MD_CTX_type(context->gss_ssl->read_hash);
    }
    if (context->gss_ssl->enc_read_ctx != NULL)
    {
        cipher_nid = EVP_CIPHER_CTX_nid(context->gss_ssl->enc_read_ctx);
    }
    #else
    cipher = SSL_get_current_cipher(context->gss_ssl);
    hash_nid = SSL_CIPHER_get_digest_nid(cipher);
    if (hash_nid == NID_undef && SSL_CIPHER_is_aead(cipher))
    {
        cipher_nid = SSL_CIPHER_get_cipher_nid(
                SSL_get_current_cipher(context->gss_ssl));
    }
    #endif

    if (hash_nid != NID_undef)
    {
        hash = EVP_get_digestbynid(hash_nid);
    }

    if (hash == NULL && cipher_nid != NID_undef)
    {
        evp_cipher = EVP_get_cipherbynid(cipher_nid);
    }

    if (hash != NULL)
    {
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (globus_i_backward_compatible_mic)
        {
            mac_sec = context->gss_ssl->s3->read_mac_secret;
            seq = context->gss_ssl->s3->read_sequence;
        }
        else
        #endif
        {
            #if OPENSSL_VERSION_NUMBER >= 0x10000100L
                mac_sec = context->mac_key;
            #else
                GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
                major_status = GSS_S_FAILURE;
                goto unlock_mutex;
            #endif
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
        
        if (globus_i_backward_compatible_mic)
        {
            token_value = ((unsigned char *) token_buffer->value) + 
                          GSS_SSL3_WRITE_SEQUENCE_SIZE;
        }
        else
        {
            #if OPENSSL_VERSION_NUMBER >= 0x10000100L
            token_value = ((unsigned char *) token_buffer->value) +
                            sizeof(context_handle->mac_read_sequence);
            #else
                assert(OPENSSL_VERSION_NUMBER >= 0x10000100L);
            #endif
        }
        
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
        
        if (globus_i_backward_compatible_mic)
        {
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
                /* increment the sequence */
                for (index = (GSS_SSL3_WRITE_SEQUENCE_SIZE - 1); index >= 0; index--)
                {
                    if (++seq[index]) break;
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
        }
        else
        {
            #if OPENSSL_VERSION_NUMBER >= 0x10000100L
            uint64_t                    message_sequence = 0;

            N2U64(token_value, message_sequence);
            if (message_sequence > context->mac_read_sequence)
            {
                /* missed a token, reset the sequence number */
                context->mac_read_sequence = message_sequence+1;

                major_status = GSS_S_GAP_TOKEN;
                GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                    (_GGSL("Missing write sequence at index: %d in the token"),
                     index));
                goto exit;
            }
            else if (message_sequence < context->mac_read_sequence)
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
                context->mac_read_sequence++;
            }
            #else
            assert(OPENSSL_VERSION_NUMBER >= 0x10000100L);
            #endif
        }
    }
#ifdef EVP_CIPH_GCM_MODE
    else if (evp_cipher != NULL
        && EVP_CIPHER_mode(evp_cipher) == EVP_CIPH_GCM_MODE)
    {
        size_t                          iv_len=EVP_CIPHER_iv_length(evp_cipher);
        unsigned char                   iv[iv_len];
        unsigned char                  *intag = NULL;
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
        memcpy(iv + 8, context->mac_iv_fixed, iv_len - 8);

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
                evp_cipher,
                iv,
                context->mac_key,
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
            goto unlock_mutex;
        }

        /* Check for sequence violations */
        token_value = token_buffer->value;
        N2U64(token_value, message_sequence);

        if (message_sequence > context->mac_read_sequence)
        {
            /* missed a token, reset the sequence number */
            context->mac_read_sequence = message_sequence+1;

            major_status = GSS_S_GAP_TOKEN;
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL,
                (_GGSL("Missing write sequence at index: %d in the token"),
                 index));
            goto exit;
        }
        else if (message_sequence < context->mac_read_sequence)
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
            context->mac_read_sequence++;
        }
    }
#endif
    else
    {
        /* Shouldn't happen: some error occurred */
        GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
        major_status = GSS_S_FAILURE;

        goto unlock_mutex;
    }

unlock_mutex:
exit:

    /* unlock the context mutex */
    globus_mutex_unlock(&context->mutex);

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
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
