#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_gsi_proxy.h
 * Globus GSI Proxy Library
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

/**
 * Handle attributes.
 * @ingroup globus_gsi_proxy_handle_attrs
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
 * @see globus_proxy_handle_handle_init(), globus_ftp_proxy_handle_destroy()
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

EXTERN_C_END

#endif /* GLOBUS_I_INCLUDE_GSI_PROXY_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
