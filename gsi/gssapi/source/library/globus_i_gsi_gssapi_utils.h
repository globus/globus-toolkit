#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_gsi_gssutils.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef _GSSUTILS_H
#define _GSSUTILS_H

#include "gssapi.h"
#include "gssapi_openssl.h"

#define GLOBUS_I_GSI_GSSAPI_MALLOC_ERROR(_MIN_RESULT_)     \ 
    {                                                      \
        char *                          _tmp_str_ =        \
        globus_l_gsi_gssapi_error_strings[                 \
            GLOBUS_GSI_GSSAPI_OUT_OF_MEMORY];              \
        *_MIN_RESULT_ = (OM_uint32) globus_error_put(      \
            globus_error_wrap_errno_error(                 \
                GLOBUS_GSI_GSSAPI_MODULE,                  \
                errno,                                     \
                GLOBUS_GSI_GSSAPI_OUT_OF_MEMORY,           \
                "%s:%d: %s: %s",                           \
                __FILE__, __LINE__, _function_name_,       \
                _tmp_str_));                               \
        globus_libc_free(_tmp_str_);


OM_uint32
globus_i_gsi_gss_copy_name_to_name(
    OM_uint32 *                         minor_status,
    gss_name_desc **                    output,
    const gss_name_desc *               input);

OM_uint32
globus_i_gsi_gss_create_and_fill_context(
    OM_uint32 *                         minor_status,
    gss_ctx_id_desc **                  context_handle,
    gss_cred_id_desc *                  cred_handle,
    const gss_cred_usage_t              cred_usage,
    OM_uint32                           req_flags);

OM_uint32
globus_i_gsi_gss_create_anonymous_cred(
    OM_uint32 *                         minor_status,
    gss_cred_id_t *                     output_cred_handle,
    const gss_cred_usage_t              cred_usage);

OM_uint32
globus_i_gsi_gss_cred_read_bio(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     cred_id_handle,
    BIO *                               bp);

OM_uint32
globus_i_gsi_gss_cred_read(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     cred_handle,
    const char *                        desired_subject);

OM_uint32
globus_i_gsi_gss_cred_set(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     cred_handle,
    X509 *                              ucert,
    EVP_PKEY *                          upkey,
    STACK_OF(X509) *                    cert_chain);

OM_uint32
globus_i_gsi_gss_create_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_usage_t              cred_usage,
    gss_cred_id_t *                     output_cred_handle_P,
    globus_gsi_cred_handle_t            cred_handle);

int globus_i_gsi_gss_verify_extensions_callback(
    proxy_verify_desc *                 pvd,
    X509_EXTENSION *                    extension);

/* following added for ssleay */

OM_uint32
globus_i_gsi_gss_handshake(
    OM_uint32 *                         minor_status,
    gss_ctx_id_desc*                    context_handle);

OM_uint32
globus_i_gsi_gss_get_token(
    const gss_ctx_id_desc *             context_handle,
    BIO *                               bio,
    const gss_buffer_t                  output_token);

OM_uint32
globus_i_gsi_gss_put_token(
    const gss_ctx_id_desc *             context_handle,
    BIO *                               bio,
    const gss_buffer_t                  input_token);

OM_uint32
globus_i_gsi_gss_retrieve_peer(
    gss_ctx_id_desc *                   context_handle,
    const gss_cred_usage_t              cred_usage);
#endif /* _GSSUTILS_H */

char *
globus_i_gsi_gssapi_create_string(
    const char *                        format,
    ...);
