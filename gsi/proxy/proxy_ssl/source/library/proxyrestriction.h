
#ifndef HEADER_PROXYRESTRICTION_H
#define HEADER_PROXYRESTRICTION_H

#ifdef __cplusplus
extern "C" {
#endif

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

/* Used for error handling */
#define ASN1_F_PROXYRESTRICTION_NEW                      450
#define ASN1_F_D2I_PROXYRESTRICTION                      451

/* data structures */

/**
 * @ingroup proxyrestriction
 * @tupedef PROXYRESTRICTION
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
    unsigned char **                    buffer);

PROXYRESTRICTION * d2i_PROXYRESTRICTION(
    PROXYRESTRICTION **                 restriction,
    unsigned char **                    buffer,
    long                                length);

#ifdef __cplusplus
}
#endif

#endif /* HEADER_PROXYRESTRICTION_H */
