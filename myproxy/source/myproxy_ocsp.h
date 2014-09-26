/*
 * myproxy_ocsp.h - verify certificate status via OCSP
 */
#ifndef __MYPROXY_OCSP_H
#define __MYPROXY_OCSP_H

#include <openssl/ssl.h>

/*
 * Set configuration value.
 * Return 0 on success, -1 on error (setting verror).
 */
int myproxy_ocsp_set_responder(const char *url);
int myproxy_ocsp_set_responder_cert(const char *path);
int myproxy_ocsp_set_policy(const char *policy);
int myproxy_ocsp_set_signer(X509 *sign_cert, EVP_PKEY *sign_key);
int myproxy_ocsp_set_times(long skew, long maxage);

/*
 * Verify certificate status via OCSP.
 * Return 1 if revoked, 0 if valid, <0 on error (setting verror).
*/
int myproxy_ocsp_verify(X509 *cert, X509 *issuer);

#endif
