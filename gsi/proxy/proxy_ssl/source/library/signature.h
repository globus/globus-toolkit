
/* data structures */

typedef struct
{
    ASN1_BIT_STRING *                   signature;
    X509_ALGOR *                        algorithm;
} X509_SIGNATURE;

/* functions */

ASN1_METHOD * X509_SIGNATURE_asn1_method();

X509_SIGNATURE * X509_SIGNATURE_new();

void X509_SIGNATURE_free();

X509_SIGNATURE * X509_SIGNATURE_dup(
    X509_SIGNATURE *                    signature);

X509_SIGNATURE * X509_SIGNATURE_cmp(
    const X509_SIGNATURE *              a,
    const X509_SIGNATURE *              b);

int X509_SIGNATURE_print(
    X509_SIGNATURE *                    signature);

int X509_SIGNATURE_print_fp(
    FILE *                              fp,
    X509_SIGNATURE *                    signature);

EVP_MD * X509_SIGNATURE_get_algorithm(
    X509_SIGNATURE *                    signature);

int X509_SIGNATURE_set_signature(
    X509_SIGNATURE *                    signature,
    X509 *                              cert);

unsigned char * X509_SIGNATURE_get_signature(
    X509_SIGNATURE *                    signature,
    long *                              length);

int i2d_X509_SIGNATURE(
    X509_SIGNATURE *                    signature,
    unsigned char **                    buffer);

X509_SIGNATURE * d2i_X509_SIGNATURE(
    X509_SIGNATURE **                   signature,
    unsigned char **                    buffer,
    long                                length);




