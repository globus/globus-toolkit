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

#ifndef GLOBUS_L_INCLUDE_GSI_PROXY_H
#define GLOBUS_L_INCLUDE_GSI_PROXY_H

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
 * GSI Proxy handle implementation
 * @ingroup globus_gsi_proxy_handle
 * @internal
 *
 * This structure contains all of the state associated with a proxy
 * handle.
 *
 * @see globus_proxy_handle_handle_init(), globus_ftp_proxy_handle_destroy()
 */

typedef struct globus_l_proxy_handle_s
{
    /** The proxy request */
    X509_REQ *                          req;
    /** The proxy private key */
    EVP_KEY *                           proxy_key;
    /** Proxy handle attributes */
    globus_l_proxy_req_handle_attrs_t * attrs;
    /** The proxy cert info extension used in the operations */
    PROXYCERTINFO *                     proxy_cert_info;    
}
globus_l_proxy_handle_t;

/**
 * Handle attributes.
 * @ingroup globus_gsi_proxy_handle_attrs
 */

typedef struct globus_l_proxy_handle_attrs_s
{
}
globus_l_proxy_handle_attrs_t;

/* used for printing the status of a private key generating algorithm */
void globus_i_gsi_proxy_create_private_key_cb(BIO *);

EXTERN_C_END

#endif /* GLOBUS_L_INCLUDE_FTP_CLIENT_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
