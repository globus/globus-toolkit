#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_gsi_credential.h
 * Globus GSI Credential Library
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#include "globus_gsi_credential.h"

#ifndef GLOBUS_I_INCLUDE_GSI_CREDENTIAL_H
#define GLOBUS_I_INCLUDE_GSI_CREDENTIAL_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

#define CRED_F_HANDLE_ATTRS_INIT "globus_gsi_cred_handle_attrs_init"


#define GLOBUS_GSI_CRED_OPENSSL_ERROR_RESULT(_ERRORTYPE_) \
    globus_i_gsi_credential_openssl_error_result( \
        _ERRORTYPE_, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        NULL)

#define GLOBUS_GSI_CRED_ERROR_RESULT(_ERRORTYPE_) \
    globus_i_gsi_credential_error_result( \
        _ERRORTYPE_, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        NULL)

#define GLOBUS_GSI_CRED_ERROR_CHAIN_RESULT(_TOP_RESULT_, _ERRORTYPE_) \
    globus_i_gsi_credential_error_chain_result( \
        _TOP_RESULT_, \
        _ERRORTYPE_, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        NULL)

/**
 * Handle attributes.
 * @ingroup globus_gsi_credential_handle_attrs
 */

/**
 * GSI Credential handle attributes implementation
 * @ingroup globus_gsi_credential_handle
 * @internal
 *
 * This structure contains immutable attributes
 * of a credential handle
 */
typedef struct globus_l_gsi_cred_handle_attrs_s
{
    /* the filename of the CA certificate directory */
    char *                              ca_cert_dir;
    /* the order to search in for a certificate */
    globus_gsi_cred_type_t *            search_order; /*{PROXY,USER,HOST}*/
} globus_i_gsi_cred_handle_attrs_t;

/**
 * GSI Credential handle implementation
 * @ingroup globus_gsi_credential_handle
 * @internal
 *
 * Contains all the state associated with a credential handle, including
 * 
 * @see globus_credential_handle_init(), globus_credential_handle_destroy()
 */
typedef struct globus_l_gsi_cred_handle_s
{
    /** The credential's signed certificate */ 
    X509 *                              cert;
    /** The private key of the credential */
    EVP_PKEY *                          key;
    /** The chain of signing certificates */
    STACK_OF(X509) *                    cert_chain;
    /** The immutable attributes of the credential handle */
    globus_gsi_cred_handle_attrs_t      attrs;

} globus_i_gsi_cred_handle_t;

int
globus_i_gsi_X509_check_issued(
    X509_STORE_CTX *                    ctx,
    X509 *                              x,
    X509 *                              issuer);

int
globus_i_gsi_X509_verify_cert_callback(
    X509_STORE_CTX *                    ctx);

globus_result_t
globus_i_gsi_credential_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...);

globus_object_t *
globus_i_gsi_credential_openssl_error_construct(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap);

globus_result_t
globus_i_gsi_credential_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...);

globus_object_t *
globus_i_gsi_credential_error_construct(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap);

globus_result_t
globus_i_gsi_credential_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...);

globus_object_t *
globus_i_gsi_credential_error_chain_construct(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap);

EXTERN_C_END

#endif /* GLOBUS_I_INCLUDE_GSI_CREDENTIAL_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

