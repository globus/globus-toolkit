#include "signature.h"
#include "proxyrestriction.h"
#include "proxygroup.h"

/* data structures */

typedef struct
{
    ASN1_BOOLEAN *                      pC;                       
    ASN1_INTEGER *                      path_length;
    PROXYRESTRICTION *                  restriction;
    PROXYGROUP *                        group;
    X509_SIGNATURE *                    issuer_signature;
} PROXYCERTINFO;



/* functions */

ASN1_METHOD * PROXYCERTINFO_asn1_method();

PROXYCERTINFO * PROXYCERTINFO_new();

void PROXYCERTINFO_free();

PROXYCERTINFO * PROXYCERTINFO_dup(
    PROXYCERTINFO *                     cert_info);

PROXYCERTINFO * PROXYCERTINFO_cmp(
    const PROXYCERTINFO *               a,
    const PROXYCERTINFO *               b);

int PROXYCERTINFO_print(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_print_fp(
    FILE *                              fp,
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_group(
    PROXYCERTINFO *                     cert_info,
    PROXYGROUP *                        group);

PROXYGROUP * PROXYCERTINFO_get_group(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_restriction(
    PROXYCERTINFO *                     cert_info,
    PROXYRESTRICTION *                  restriction);

PROXYRESTRICTION * PROXYCERTINFO_get_restriction(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_path_length(
    PROXYCERTINFO *                     cert_info,
    int                                 path_length);

int PROXYCERTINFO_get_path_length(
    PROXYCERTINFO *                     cert_info);

int PROXYCERTINFO_set_issuer_cert_digest(
    PROXYCERTINFO *                     cert_info,
    MESSAGEDIGEST *                     cert_digest);

MESSAGEDIGEST * PROXYCERTINFO_get_issuer_cert_digest(
    PROXYCERTINFO *                     cert_info);

int i2d_PROXYCERTINFO(
    PROXYCERTINFO *                     cert_info,
    unsigned char **                    buffer);

PROXYCERTINFO * d2i_PROXYCERTINFO(
    PROXYCERTINFO **                    cert_info,
    unsigned char **                    buffer,
    long                                length);







