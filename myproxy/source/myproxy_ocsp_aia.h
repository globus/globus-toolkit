/*
 * myproxy_ocsp_aia.h - OCSP AIA extension handlign
 */
#ifndef __MYPROXY_OCSP_AIA_H
#define __MYPROXY_OCSP_AIA_H

#include <openssl/x509v3.h>

char *myproxy_get_aia_ocsp_uri(X509 *cert);

#endif
