
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>

#include "proxyrestriction.h"

/**
 * @name Get a method for ASN1 conversion
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *  
 * Creates an ASN1_METHOD structure, which contains
 * pointers to routines that convert any PROXYRESTRICTION
 * structure to its associated ASN1 DER encoded form
 * and vice-versa.
 *
 * @return the ASN1_METHOD object
 */

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
/* PROXYRESTRICTION_asn1_meth() */
/* @} */


/**
 * @name New
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Allocates and initializes a new PROXYRESTRICTION structure.
 *
 * @return pointer to the new PROXYRESTRICTION
 */
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
/* PROXYRESTRICTION_new() */
/* @} */


/**
 * @name Free
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Frees a PROXYRESTRICTION
 *
 * @param restriction the proxy restriction to free
 */
void PROXYRESTRICTION_free(
    PROXYRESTRICTION *                  restriction)
{
    if(restriction == NULL) return;
    ASN1_OBJECT_free(restriction->policy_language);
    M_ASN1_OCTET_STRING_free(restriction->policy);
    OPENSSL_free(restriction);
}
/* PROXYRESTRICTION_free() */
/* @} */


/**
 * @name Duplicate
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 * 
 * Makes a copy of the proxyrestriction - this function
 * allocates space for a new PROXYRESTRICTION, so the
 * returned PROXYRESTRICTION must be freed when
 * its no longer needed
 *
 * @param restriction the proxy restriction to copy
 *
 * @return the new PROXYRESTRICTION
 */
PROXYRESTRICTION * PROXYRESTRICTION_dup(
    PROXYRESTRICTION *                  restriction)
{
    return ((PROXYRESTRICTION *) ASN1_dup((int (*)())i2d_PROXYRESTRICTION,
                                          (char *(*)())d2i_PROXYRESTRICTION,
                                          (char *)restriction));
}
/* PROXYRESTRICTION_dup() */
/* @} */


/**
 * @name Compare
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Compares two PROXYRESTRICTION structs for equality
 * This function first compares the policy language numeric
 * id's, if they're equal, it then compares the two policies.
 *
 * @return 1 if equal, 0 if not
 */
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
/* @} */


/**
 * @name Print to a BIO stream
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Prints the PROXYRESTRICTION struct using the BIO stream
 *
 * @param bp the BIO stream to print to
 * @param restriction the PROXYRESTRICTION to print
 *
 * @return the number of bytes printed, -1 or -2 on error
 */
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
/* @} */


/**
 * @name Print to a File Stream
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Prints the PROXYRESTRICTION to the file stream FILE*
 *
 * @param fp the FILE* stream to print to
 * @param restriction the PROXYRESTRICTION to print
 *
 * @return number of bytes printed, -2 or -1 on error
 */
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
/* @} */


/**
 * @name Set the Policy Language Field
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Sets the policy language of the PROXYRESTRICTION
 *
 * @param restriction the PROXYRESTRICTION to set the policy language of
 * @param policy_language the policy language to set it to
 *
 * @return 1 on success, 0 on error
 */
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
/* @} */

/**
 * @name Get the Policy Language Field
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 * 
 * Gets the policy language of the PROXYRESTRICTION
 *
 * @param restriction the proxy restriction to get the policy language
 * of
 * 
 * @return the policy language as an ASN1_OBJECT
 */    
ASN1_OBJECT * PROXYRESTRICTION_get_policy_language(
    PROXYRESTRICTION *                  restriction)
{
    return restriction->policy_language;
}
/* @} */

/**
 * @name Set the Policy Field
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Sets the policy of the PROXYRESTRICTION
 *
 * @param restriction the proxy restriction to set the policy of
 * @param policy the policy to set it to
 * @param length the lenght of the policy
 *
 * @return 1 on success, 0 on error
 */
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
/* @} */


/**
 * @name Get the Policy Field
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Gets the policy of a PROXYRESTRICTION
 *
 * @param restriction the PROXYRESTRICTION to get the policy of
 * @param length the length of the returned policy - this value
 *        gets set by this function
 *
 * @return the policy
 */
unsigned char * PROXYRESTRICTION_get_policy(
    PROXYRESTRICTION *                  restriction,
    int *                               length)
{
    (*length) = restriction->policy->length;
    return restriction->policy->data;
}
/* @} */


/**
 * @name Convert from Internal to DER encoded form
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Converts a PROXYRESTRICTION from its internal structure
 * to a DER encoded form
 *
 * @param a the PROXYRESTRICTION to convert
 * @param pp the buffer to put the DER encoding in
 *
 * @return the length of the DER encoding in bytes
 */
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
/* @} */


/**
 * @name Convert from DER encoded form to Internal
 */
/* @{ */
/**
 * @ingroup proxyrestriction
 *
 * Converts the PROXYRESTRICTION from its DER encoded form
 * to an internal PROXYRESTRICTION structure
 *
 * @param a the PROXYRESTRICTION struct to set
 * @param pp the DER encoding to get the PROXYRESTRICTION from
 * @param length the length of the DER encoding
 * 
 * @return the resulting PROXYRESTRICTION in its internal structure
 * form - this variable has been allocated using _new routines, 
 * so it needs to be freed once its no longer used
 */
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
/* @} */
