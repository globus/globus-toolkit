#ifndef HEADER_PROXYCERTINFO_H
#define HEADER_PROXYCERTINFO_H

/**
 * @anchor globus_gsi_proxy_ssl_api
 * @mainpage Globus GSI Proxy SSL API
 *
 * The globus_gsi_proxy_ssl library provides the ability
 * to create a PROXYCERTINFO extension to be included in
 * an X509 certificate.  The current specification for the
 * extension is described in the Internet Draft 
 * Document: draft-ietf-pkix-proxy-01.txt
 * 
 * The library conforms to the ASN1 implementation in
 * the OPENSSL library (formerly SSLeay), and provides
 * an interface to convert from a DER encoded PROXYCERTINFO
 * to its internal structure and vice-versa.
 */

#include "signature.h"
#include "proxyrestriction.h"
#include "proxygroup.h"

#include <openssl/asn1.h>
#include <openssl/x509.h>

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

/**
 * @defgroup proxycertinfo ProxyCertInfo
 * 
 * @author Sam Meder
 * @author Sam Lang
 * 
 * The proxycertinfo.h file defines a method of
 * maintaining information about proxy certificates.
 */

#define PROXYCERTINFO_OID               "1.3.6.1.4.1.3536.1.222"
#define PROXYCERTINFO_SN                "PROXYCERTINFO"
#define PROXYCERTINFO_LN                "Proxy Certificate Info Extension"

/**
 * Used for error checking
 */
#define ASN1_F_PROXYCERTINFO_NEW                         430
#define ASN1_F_D2I_PROXYCERTINFO                         431


/* data structures */

/**
 * @ingroup proxycertinfo
 *
 * This typedef maintains information about a proxy
 * certificate.
 *
 * @note NOTE: The API provides functions to manipulate
 * the fields of a PROXYCERTINFO.  Accessing the fields
 * directly is not a good idea.
 *
 * 
 * @param pC a boolean value, it indicates whether or not the 
 * certificate is a proxy certificate: if the certificate is a proxy 
 * certificate, the pC field MUST be TRUE; otherwise, the pC field MUST 
 * be FALSE.
 * @param path_length an optional field in the ANS.1 DER encoding, 
 * it specifies the maximum depth of the path of Proxy Certificates 
 * that can be signed by this End Entity Certificate or Proxy Certificate.
 * @param restriction an optional field in the ANS.1 DER encoding,
 * specifies restrictions on the use of this certificate.  If the 
 * certificate is not a Proxy Certificate (i.e, if the pC field is 
 * FALSE), then the restriction field will not be present.
 * @param group defines which group the proxy is to be in
 * @param issuer_signature holds the signature of the certificate
 * that signed this proxy certificate (issued it)
 */
struct PROXYCERTINFO_st
{
    ASN1_INTEGER *                      version;
    ASN1_BOOLEAN *                      pC;                       
    ASN1_INTEGER *                      path_length;       /* [ OPTIONAL ] */
    PROXYRESTRICTION *                  restriction;       /* [ OPTIONAL ] */
    PROXYGROUP *                        group;             /* [ OPTIONAL ] */
    X509_SIG *                          issuer_signature;  /* [ OPTIONAL ] */
};

typedef struct PROXYCERTINFO_st PROXYCERTINFO;

DECLARE_STACK_OF(PROXYCERTINFO)
DECLARE_ASN1_SET_OF(PROXYCERTINFO)

/* macros */

#define d2i_PROXYCERTINFO_bio(bp, pci) \
    (PROXYCERTINFO *) ASN1_d2i_bio((char *(*)()) PROXYCERTINFO_new, \
    (char *(*)()) d2i_PROXYCERTINFO, \
    (bp), (unsigned char **) pci)

#define i2d_PROXYCERTINFO_bio(bp, pci) \
                ASN1_i2d_bio(i2d_PROXYCERTINFO, bp, \
		(unsigned char *)pci)

/* functions */
    
ASN1_METHOD * PROXYCERTINFO_asn1_meth();

PROXYCERTINFO * PROXYCERTINFO_new();

void PROXYCERTINFO_free(
    PROXYCERTINFO *                     cert_info);

PROXYCERTINFO * PROXYCERTINFO_dup(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_cmp(
    const PROXYCERTINFO *               a,
    const PROXYCERTINFO *               b);

int PROXYCERTINFO_print(
    BIO *                               bp,
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_print_fp(
    FILE *                              fp,
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_group(
    PROXYCERTINFO *                     cert_info,
    PROXYGROUP *                        group);

ASN1_BOOLEAN * PROXYCERTINFO_get_pC(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_pC(
    PROXYCERTINFO *                     cert_info,
    ASN1_BOOLEAN                        pC);

int PROXYCERTINFO_set_version(
    PROXYCERTINFO *                     cert_info,
    long                                version);

long PROXYCERTINFO_get_version(
    PROXYCERTINFO *                     cert_info);

PROXYGROUP * PROXYCERTINFO_get_group(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_restriction(
    PROXYCERTINFO *                     cert_info,
    PROXYRESTRICTION *                  restriction);

PROXYRESTRICTION * PROXYCERTINFO_get_restriction(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_path_length(
    PROXYCERTINFO *                     cert_info,
    long                                path_length);

long PROXYCERTINFO_get_path_length(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_issuer_signature(
    PROXYCERTINFO *                     cert_info,
    X509_SIG *                          signature);

X509_SIG * PROXYCERTINFO_get_issuer_signature(
    PROXYCERTINFO *                     cert_info);

int i2d_PROXYCERTINFO(
    PROXYCERTINFO *                     cert_info,
    unsigned char **                    a);

PROXYCERTINFO * d2i_PROXYCERTINFO(
    PROXYCERTINFO **                    cert_info,
    unsigned char **                    a,
    long                                length);

X509V3_EXT_METHOD * PROXYCERTINFO_x509v3_ext_meth();

STACK_OF(CONF_VALUE) * i2v_PROXYCERTINFO(
    struct v3_ext_method *              method,
    PROXYCERTINFO *                     ext,
    STACK_OF(CONF_VALUE) *              extlist);

EXTERN_C_END

#endif /* HEADER_PROXYCERTINFO_H */

