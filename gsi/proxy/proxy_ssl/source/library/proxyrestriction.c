
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
    ASN1_CTX c;
    PROXYRESTRICTION * ret = NULL;
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
    M_ASN1_OBJECT_free(restriction->policy_language);
    M_ASN1_OCTECT_STRING_free(restriction->policy);
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
    int ret;
    ret  = ASN1_OBJECT_cmp(a->policy_language, b->policy_language);
    ret &= ASN1_OCTECT_STRING_cmp(a->policy, b->policy);
    return (ret);
}

int PROXYRESTRICTION_print(
    PROXYRESTRICTION *                  restriction)
{
    return PROXYRESTRICTION_print_fp(stdout, restriction);
}

int PROXYRESTRICTION_print_fp(
    FILE *                              fp,
    PROXYRESTRICTION *                  restriction)
{
    BIO * bp;
    int ret;
    
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    ret  = ASN1_OBJECT_print(bp, restriction->policy_language);
    ret &= ASN1_OCTECT_STRING_print(bp, restriction->policy);
    return (ret);
}

int PROXYRESTRICTION_set_policy_language(
    PROXYRESTRICTION *                  restriction,
    ASN1_OBJECT *                       policy_language)
{
    if(policy_language != NULL) 
    {
	restriction->policy_language = policy_language;
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
    PROXYRESTRICTION *                  restriction,
    unsigned char **                    buffer)
{
    unsigned char ** pp = buffer;
    M_ASN1_I2D_vars(restriction);
    M_ASN1_I2D_len(restriction->policy_language,
		   i2d_ASN1_OBJECT);
    M_ASN1_I2D_len(restriction->policy,
		   i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(restriction->policy_language, i2d_ASN1_OBJECT);
    M_ASN1_I2D_put(restriction->policy, i2d_ASN1_OCTET_STRING);
    M_ASN1_I2D_finish();
}

PROXYRESTRICTION * d2i_PROXYRESTRICTION(
    PROXYRESTRICTION **                 restriction,
    unsigned char **                    buffer,
    long                                length)
{
    unsigned char ** pp = buffer;
    
    M_ASN1_D2I_vars(restriction, PROXYRESTRICTION *, PROXYRESTRICTION_new);
    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();
    M_ASN1_D2I_get(ret->policy_language, d2i_ASN1_OBJECT);
    M_ASN1_D2I_get(ret->policy, d2i_ASN1_OCTET_STRING);
    M_ASN1_D2I_Finish(restriction, 
		      PROXYRESTRICTION_free, 
		      ASN1_F_D2I_PROXYRESTRICTION);
}
