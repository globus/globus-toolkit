
#ifndef HEADER_SIGNATURE_H
#define HEADER_SIGNATURE_H

/**
 * @defgroup signature Signature
 *
 * @author Sam Meder
 * @author Sam Lang
 * 
 * The signature set of functions
 * provides an interface
 * to a signature used by proxy certificates
 *
 * @see Internet Draft Document: draft-ietf-pkix-proxy-01.txt
 * for further information
 */

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

ASN1_METHOD * X509_SIG_asn1_meth();

X509_SIG * X509_SIG_dup(
    X509_SIG *                          signature);

int X509_SIG_cmp(
    const X509_SIG *                    a,
    const X509_SIG *                    b);

int X509_SIG_print(
    BIO *                               bp,
    X509_SIG *                          signature);

int X509_SIG_print_fp(
    FILE *                              fp,
    X509_SIG *                          signature);

EVP_MD * X509_SIG_get_algorithm(
    X509_SIG *                          signature);

int X509_SIG_set_signature(
    X509_SIG *                          signature,
    X509 *                              cert);

unsigned char * X509_SIG_get_signature(
    X509_SIG *                          signature,
    long *                              length);

int i2d_X509_SIG(
    X509_SIG *                          signature,
    unsigned char **                    buffer);

X509_SIG * d2i_X509_SIG(
    X509_SIG **                         signature,
    unsigned char **                    buffer,
    long                                length);

STACK_OF(CONF_VALUE) * i2v_X509_SIG(
    struct v3_ext_method *              method,
    X509_SIG *                          sig,
    STACK_OF(CONF_VALUE) *              extlist);

EXTERN_C_END

#endif // HEADER_SIGNATURE_H
