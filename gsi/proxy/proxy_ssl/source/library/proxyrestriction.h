
#ifndef HEADER_PROXYRESTRICTION_H
#define HEADER_PROXYRESTRICTION_H

/**
 * @defgroup proxyrestriction ProxyRestriction
 *
 * @author Sam Meder
 * @author Sam Lang
 *
 * The proxyrestriction set of data structures
 * and functions provides an interface to generating
 * a PROXYRESTRICTION structure which is maintained as
 * a field in the PROXYCERTINFO structure,
 * and ultimately gets written to a DER encoded string.
 *
 * @see Further Information about proxy restrictions
 * is available in the Internet Draft Document:
 * 
 * draft-ietf-pkix-proxy-01.txt
 */

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

#define PROXYRESTRICTION_OID               "1.3.6.1.4.1.3536.1.224"
#define PROXYRESTRICTION_SN                "PROXYRESTRICTION"
#define PROXYRESTRICTION_LN                "Proxy Restriction"

/* Used for error handling */
#define ASN1_F_PROXYRESTRICTION_NEW                      450
#define ASN1_F_D2I_PROXYRESTRICTION                      451

/* data structures */

/**
 * @ingroup proxyrestriction
 *
 * @note NOTE: The API provides functions to manipulate
 * the fields of a PROXYRESTRICTION.  Accessing the fields
 * directly will not work.
 *
 * This typedef maintains information about the restrictions
 * that have been placed on a proxy certificate
 *
 * @param policy_language defines which policy language
 * is to be used to define the restrictions
 * @param policy the policy that determines the restrictions
 * on a certificate
 */
struct PROXYRESTRICTION_st
{
    ASN1_OBJECT *                       policy_language;
    ASN1_OCTET_STRING *                 policy;
};

typedef struct PROXYRESTRICTION_st PROXYRESTRICTION;

DECLARE_STACK_OF(PROXYRESTRICTION)
DECLARE_ASN1_SET_OF(PROXYRESTRICTION)

/* functions */

ASN1_METHOD * PROXYRESTRICTION_asn1_meth();

PROXYRESTRICTION * PROXYRESTRICTION_new();

void PROXYRESTRICTION_free();

PROXYRESTRICTION * PROXYRESTRICTION_dup(
    PROXYRESTRICTION *                  restriction);

int PROXYRESTRICTION_cmp(
    const PROXYRESTRICTION *            a,
    const PROXYRESTRICTION *            b);

int PROXYRESTRICTION_print(
    BIO *                               bp,
    PROXYRESTRICTION *                  restriction);

int PROXYRESTRICTION_print_fp(
    FILE *                              fp,
    PROXYRESTRICTION *                  restriction);

int PROXYRESTRICTION_set_policy_language(
    PROXYRESTRICTION *                  restriction,
    ASN1_OBJECT *                       policy_language);

ASN1_OBJECT * PROXYRESTRICTION_get_policy_language(
    PROXYRESTRICTION *                  restriction);

int PROXYRESTRICTION_set_policy(
    PROXYRESTRICTION *                  restriction,
    unsigned char *                     policy,
    int                                 length);

unsigned char * PROXYRESTRICTION_get_policy(
    PROXYRESTRICTION *                  restriction,
    int *                               length);

int i2d_PROXYRESTRICTION(
    PROXYRESTRICTION *                  restriction,
    unsigned char **                    a);

PROXYRESTRICTION * d2i_PROXYRESTRICTION(
    PROXYRESTRICTION **                 restriction,
    unsigned char **                    a,
    long                                length);

X509V3_EXT_METHOD * PROXYRESTRICTION_x509v3_ext_meth();

STACK_OF(CONF_VALUE) * i2v_PROXYRESTRICTION(
    struct v3_ext_method *              method,
    PROXYRESTRICTION *                  ext,
    STACK_OF(CONF_VALUE) *              extlist);

EXTERN_C_END

#endif /* HEADER_PROXYRESTRICTION_H */
