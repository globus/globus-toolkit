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

#ifndef HEADER_PROXYCERTINFO_H
#define HEADER_PROXYCERTINFO_H

/**
 * @file proxycertinfo.h
 * 
 * @author Sam Meder
 * @author Sam Lang
 */
#ifndef GLOBUS_GLOBAL_DOCUMENT_SET
/**
 * @mainpage Globus GSI Proxy SSL API
 * @copydoc globus_gsi_proxy_ssl_api
 */
#endif

/**
 * @defgroup globus_gsi_proxy_ssl_api Globus GSI Proxy SSL API
 *
 * The globus_gsi_proxy_ssl library provides the ability
 * to create a PROXYCERTINFO extension for inclusion in
 * an X509 certificate.  The current specification for the
 * extension is described in
 * <a href="http://www.ietf.org/rfc/rfc3820.txt">RFC 3820</a>.
 * 
 * The library conforms to the ASN1 implementation in
 * the OPENSSL library (0.9.6, formerly SSLeay), and provides
 * an interface to convert from a DER encoded PROXYCERTINFO
 * to its internal structure and vice-versa.
 *
 * @section proxycertinfo_section ProxyCertInfo
 * @copydoc proxycertinfo
 * For more information, see the documentation in 
 * @link proxycertinfo ProxyCertInfo @endlink
 * @section proxypolicy_section ProxyPolicy
 * @copydoc proxypolicy
 * For more information, see the documentation in 
 * @link proxypolicy ProxyPolicy @endlink
 */

#include "proxypolicy.h"
#include <openssl/asn1.h>
#include <openssl/x509.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup proxycertinfo ProxyCertInfo
 * @ingroup globus_gsi_proxy_ssl_api
 * 
 * The proxycertinfo.h file defines a method of
 * maintaining information about proxy certificates.
 */

#define PROXYCERTINFO_OLD_OID           "1.3.6.1.4.1.3536.1.222"
#define PROXYCERTINFO_OID               "1.3.6.1.5.5.7.1.14"
#define PROXYCERTINFO_SN                "PROXYCERTINFO"
#define PROXYCERTINFO_LN                "Proxy Certificate Info Extension"
#define PROXYCERTINFO_OLD_SN            "OLD_PROXYCERTINFO"
#define PROXYCERTINFO_OLD_LN                "Proxy Certificate Info Extension (old OID)"

/*
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
 * @param path_length an optional field in the ANS.1 DER encoding, 
 * it specifies the maximum depth of the path of Proxy Certificates 
 * that can be signed by this End Entity Certificate or Proxy Certificate.
 * @param policy a non-optional field in the ANS.1 DER encoding,
 * specifies policies on the use of this certificate.
 */
struct PROXYCERTINFO_st
{
    ASN1_INTEGER *                      path_length;       /* [ OPTIONAL ] */
    PROXYPOLICY *                       policy;
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
    
#if OPENSSL_VERSION_NUMBER < 0x10000000L
ASN1_METHOD * PROXYCERTINFO_asn1_meth();
#endif

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

int PROXYCERTINFO_set_policy(
    PROXYCERTINFO *                     cert_info,
    PROXYPOLICY *                       policy);

PROXYPOLICY * PROXYCERTINFO_get_policy(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_path_length(
    PROXYCERTINFO *                     cert_info,
    long                                path_length);

long PROXYCERTINFO_get_path_length(
    PROXYCERTINFO *                     cert_info);

int i2d_PROXYCERTINFO(
    PROXYCERTINFO *                     cert_info,
    unsigned char **                    a);

PROXYCERTINFO * d2i_PROXYCERTINFO(
    PROXYCERTINFO **                    cert_info,
    unsigned char **                    a,
    long                                length);

int i2d_PROXYCERTINFO_OLD(
    PROXYCERTINFO *                     cert_info,
    unsigned char **                    a);

PROXYCERTINFO * d2i_PROXYCERTINFO_OLD(
    PROXYCERTINFO **                    cert_info,
    unsigned char **                    a,
    long                                length);

X509V3_EXT_METHOD * PROXYCERTINFO_x509v3_ext_meth();

X509V3_EXT_METHOD * PROXYCERTINFO_OLD_x509v3_ext_meth();

STACK_OF(CONF_VALUE) * i2v_PROXYCERTINFO(
    struct v3_ext_method *              method,
    PROXYCERTINFO *                     ext,
    STACK_OF(CONF_VALUE) *              extlist);

#ifdef __cplusplus
}
#endif

#endif /* HEADER_PROXYCERTINFO_H */
