#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_gsi_proxy.h
 * Globus GSI Proxy Library
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */

#include "globus_gsi_proxy.h"
#include "proxycertinfo.h"

#ifndef GLOBUS_I_INCLUDE_GSI_PROXY_H
#define GLOBUS_I_INCLUDE_GSI_PROXY_H

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

#define GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(_ERRORTYPE_) \
    globus_i_gsi_proxy_openssl_error_result( \
        _ERRORTYPE_, \
        __FILE__, \
        _FUNCTION_NAME_, \
        __LINE__, \
        NULL)

#define GLOBUS_GSI_PROXY_ERROR_RESULT(_ERRORTYPE_) \
    globus_i_gsi_proxy_error_result( \
        _ERRORTYPE_, \
        __FILE__, \
        _FUNCTION_NAME_, \
        __LINE__, \
        NULL)

#define GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(_TOP_RESULT_, _ERRORTYPE_) \
    globus_i_gsi_proxy_error_chain_result( \
        _TOP_RESULT_, \
        _ERRORTYPE_, \
        __FILE__, \
        _FUNCTION_NAME_, \
        __LINE__, \
        NULL)

#include "globus_gsi_proxy_constants.h"
extern char * globus_l_gsi_proxy_error_strings[GLOBUS_GSI_PROXY_ERROR_LAST];
/**
 * Handle attributes.
 * @ingroup globus_gsi_credential_handle_attrs
 */

/**
 * GSI Proxy handle attributes implementation
 * @ingroup globus_gsi_proxy_handle
 * @internal
 *
 * This structure contains the attributes
 * of a proxy handle.
 */
typedef struct globus_l_gsi_proxy_handle_attrs_s
{
    /** 
     * The size of the keys to generate for
     * the certificate request
     */
    int                                 key_bits;
    /**
     * The initial prime to use for creating
     * the key pair
     */
    int                                 init_prime;

} globus_i_gsi_proxy_handle_attrs_t;

/**
 * GSI Proxy handle implementation
 * @ingroup globus_gsi_proxy_handle
 * @internal
 *
 * This structure contains all of the state associated with a proxy
 * handle.
 *
 * @see globus_proxy_handle_init(), globus_proxy_handle_destroy()
 */

typedef struct globus_l_gsi_proxy_handle_s
{
    /** The proxy request */
    X509_REQ *                          req;
    /** The proxy private key */
    EVP_PKEY *                          proxy_key;
    /** Proxy handle attributes */
    globus_gsi_proxy_handle_attrs_t     attrs;
    /** The proxy cert info extension used in the operations */
    PROXYCERTINFO *                     proxy_cert_info;    
    /**
     * The signing algorithm to use for 
     * generating the proxy certificate
     */
    EVP_MD *                            signing_algorithm;
    /**
     * The number of minutes the proxy certificate
     * is valid for
     */
    int                                 time_valid;
    /**
     * The clock skew (in seconds) allowed 
     * for the proxy certificate.  The skew
     * adjusts the validity time of the proxy cert.
     */
    int                                 clock_skew;

} globus_i_gsi_proxy_handle_t;


/* used for printing the status of a private key generating algorithm */
void 
globus_i_gsi_proxy_create_private_key_cb(
    BIO *                               output);

void 
globus_i_gsi_proxy_create_private_key_cb(
    BIO *                               output);

globus_result_t
globus_i_gsi_proxy_set_pc_times(
    X509 *                              new_pc, 
    X509 *                              issuer_cert,
    int                                 clock_skew,
    int                                 time_valid);

globus_result_t
globus_i_gsi_proxy_set_subject(
    X509 *                              new_pc, 
    X509 *                              issuer_cert,
    char *                              common_name);

globus_result_t
globus_i_gsi_proxy_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...);

globus_object_t *
globus_i_gsi_proxy_openssl_error_construct(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap);

globus_result_t
globus_i_gsi_proxy_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...);

globus_object_t *
globus_i_gsi_proxy_error_construct(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap);

globus_result_t
globus_i_gsi_proxy_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...);

globus_object_t *
globus_i_gsi_proxy_error_chain_construct(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap);


EXTERN_C_END

#endif /* GLOBUS_I_INCLUDE_GSI_PROXY_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
