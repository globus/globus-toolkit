/* data structures */

typedef struct
{
    ASN1_OBJECT *                       policy_language;
    ASN1_OCTET_STRING *                 policy;
} PROXYRESTRICTION;

/* functions */

ASN1_METHOD * PROXYRESTRICTION_asn1_method();

PROXYRESTRICTION * PROXYRESTRICTION_new();

void PROXYRESTRICTION_free();

PROXYRESTRICTION * PROXYRESTRICTION_dup(
    PROXYRESTRICTION *                  restriction);

PROXYRESTRICTION * PROXYRESTRICTION_cmp(
    const PROXYRESTRICTION *            a,
    const PROXYRESTRICTION *            b);

int PROXYRESTRICTION_print(
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
    PROXYRESTRICTION *                  restriction
    int *                               length);

int i2d_PROXYRESTRICTION(
    PROXYRESTRICTION *                  restriction,
    unsigned char **                    buffer);

PROXYRESTRICTION * d2i_PROXYRESTRICTION(
    PROXYRESTRICTION **                 restriction,
    unsigned char **                    buffer,
    long                                length);

