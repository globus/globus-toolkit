
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>

#include "proxy_ssl_internal.h"
#include "proxyrestriction.h"

ASN1_METHOD * PROXYRESTRICTION_asn1_meth()
{
    static ASN1_METHOD proxyrestriction_asn1_meth =
    {
        (int (*)())   i2d_PROXYRESTRICTION,
        (char *(*)()) d2i_PROXYRESTRICTION,
        (char *(*)()) PROXYRESTRICTION_new,
        (void (*)())  PROXYRESTRICTION_free
    };
    return (&proxyrestriction_asn1_meth);
}

PROXYRESTRICTION * PROXYRESTRICTION_new()
{
    ASN1_CTX                            c;
    PROXYRESTRICTION *                  ret;

    ret = NULL;

    M_ASN1_New_Malloc(ret, PROXYRESTRICTION);
    M_ASN1_New(ret->policy_language, ASN1_OBJECT_new);
    M_ASN1_New(ret->policy,          M_ASN1_OCTET_STRING_new);
    return (ret);
    M_ASN1_New_Error(ASN1_F_PROXYRESTRICTION_NEW);
}

void PROXYRESTRICTION_free(
    PROXYRESTRICTION *                  restriction)
{
    if(restriction == NULL) return;
    ASN1_OBJECT_free(restriction->policy_language);
    M_ASN1_OCTET_STRING_free(restriction->policy);
    OPENSSL_free(restriction);
}

PROXYRESTRICTION * PROXYRESTRICTION_dup(
    PROXYRESTRICTION *                  restriction)
{
    return ((PROXYRESTRICTION *) ASN1_dup((int (*)())i2d_PROXYRESTRICTION,
                                          (char *(*)())d2i_PROXYRESTRICTION,
                                          (char *)restriction));
}

int PROXYRESTRICTION_cmp(
    const PROXYRESTRICTION *            a,
    const PROXYRESTRICTION *            b)
{
    
    if((a->policy_language->nid == b->policy_language->nid) &&
       ASN1_STRING_cmp((ASN1_STRING *)a->policy, (ASN1_STRING *)b->policy))
    {
        return 1;
    }
    return 0;
}

int PROXYRESTRICTION_print(
    BIO *                               bp,
    PROXYRESTRICTION *                  restriction)
{
    int                                 ret,
                                        tmpret;

    ret = BIO_printf(bp, "PROXYRESTRICTION::PolicyLanguage: %s, %s, %d\n", 
                     restriction->policy_language->ln,
                     restriction->policy_language->sn,
                     restriction->policy_language->nid);
    if(ret < 0) { return ret; }

    tmpret = BIO_dump(bp,
                      restriction->policy_language->data,
                      restriction->policy_language->length);
    if(tmpret < 0) { return tmpret; }
    ret += tmpret;

    tmpret = BIO_printf(bp, "PROXYRESTRICTION::Policy: ");
    if(tmpret < 0) { return tmpret; }
    ret += tmpret;

    tmpret = ASN1_STRING_print(bp, (ASN1_STRING *) restriction->policy);
    if(tmpret < 0) { return tmpret; }
    ret += tmpret;
    
    tmpret = BIO_printf(bp, "\n");
    if(tmpret < 0) { return tmpret; }
    
    return (ret + tmpret);
}

int PROXYRESTRICTION_print_fp(
    FILE *                              fp,
    PROXYRESTRICTION *                  restriction)
{
    int                                 ret;

    BIO * bp = BIO_new(BIO_s_file());    
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    ret = PROXYRESTRICTION_print(bp, restriction);
    BIO_free(bp);

    return (ret);
}

int PROXYRESTRICTION_set_policy_language(
    PROXYRESTRICTION *                  restriction,
    ASN1_OBJECT *                       policy_language)
{
    if(policy_language != NULL) 
    {
        ASN1_OBJECT_free(restriction->policy_language);
        restriction->policy_language = OBJ_dup(policy_language);
        return 1;
    }
    return 0;
}
    
ASN1_OBJECT * PROXYRESTRICTION_get_policy_language(
    PROXYRESTRICTION *                  restriction)
{
    return restriction->policy_language;
}

int PROXYRESTRICTION_set_policy(
    PROXYRESTRICTION *                  restriction,
    unsigned char *                     policy,
    int                                 length)
{
    if(policy != NULL)
    {
        ASN1_OCTET_STRING_set(restriction->policy, policy, length);
        return 1;
    }
    return 0;
}

unsigned char * PROXYRESTRICTION_get_policy(
    PROXYRESTRICTION *                  restriction,
    int *                               length)
{
    (*length) = restriction->policy->length;
    return restriction->policy->data;
}

int i2d_PROXYRESTRICTION(
    PROXYRESTRICTION *                  a,
    unsigned char **                    pp)
{
    M_ASN1_I2D_vars(a);

    M_ASN1_I2D_len(a->policy_language,
                   i2d_ASN1_OBJECT);
    M_ASN1_I2D_len(a->policy,
                   i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(a->policy_language, i2d_ASN1_OBJECT);
    M_ASN1_I2D_put(a->policy, i2d_ASN1_OCTET_STRING);

    M_ASN1_I2D_finish();
}

PROXYRESTRICTION * d2i_PROXYRESTRICTION(
    PROXYRESTRICTION **                 a,
    unsigned char **                    pp,
    long                                length)
{
    M_ASN1_D2I_vars(a, PROXYRESTRICTION *, PROXYRESTRICTION_new);
    
    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();
    M_ASN1_D2I_get(ret->policy_language, d2i_ASN1_OBJECT);
    M_ASN1_D2I_get(ret->policy, d2i_ASN1_OCTET_STRING);
    M_ASN1_D2I_Finish(a, 
                      PROXYRESTRICTION_free, 
                      ASN1_F_D2I_PROXYRESTRICTION);
}
