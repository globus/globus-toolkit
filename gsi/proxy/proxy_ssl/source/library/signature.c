
#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <string.h>
#include "signature.h"

/**
 * @name Method for ASN1 Conversion Functions
 */
/* @{ */
/**
 * @ingroup signature
 * Creates an ASN1_METHOD structure, which contains pointers 
 * to routines that convert any X509_SIG structure to DER 
 * encoded form and vice-versa.
 *
 * @return the ASN1_METHOD object 
 */
ASN1_METHOD * X509_SIG_asn1_method() 
{
    static ASN1_METHOD x509_signature_meth = 
    {
        (int (*)())    i2d_X509_SIG,
        (char *(*)())  d2i_X509_SIG,
        (char *(*)())  X509_SIG_new,
        (void (*)())   X509_SIG_free
    };
    return (&x509_signature_meth);
}
/* @} */

/**
 * @name Duplicate
 */
/* @{ */
/**
 * @ingroup signature
 * Makes a copy of the X509_SIG
 * 
 * @param signature pointer to the X509_SIG
 * structure to be copied
 *
 * @return a pointer to the copied X509_SIG
 * structure
 */
X509_SIG * X509_SIG_dup(
    X509_SIG *                    signature)
{
    return ((X509_SIG *) ASN1_dup((int (*)())i2d_X509_SIG,
                                  (char *(*)())d2i_X509_SIG,
                                  (char *)signature));
}
/* @} */


/**
 * @name Compare
 */
/* @{ */
/**
 * @ingroup signature
 * Compares two X509_SIG structures
 *
 * @param a pointer to the first X509_SIG structure
 * @param b pointer to the second X509_SIG structure
 *
 * @return an integer - the result of the comparison.  
 * If the two signatures are equal, 0 is returned,
 * 1 otherwise
 */
int X509_SIG_cmp(
    const X509_SIG *                    a,
    const X509_SIG *                    b)
{
    int                                 ret;
    ret  = (OBJ_obj2nid((ASN1_OBJECT *)a->algor) == 
            OBJ_obj2nid((ASN1_OBJECT *)b->algor));
    ret &= ASN1_STRING_cmp(a->digest, b->digest);
    return (ret);
}
/* @} */


/**
 * @name Print to a BIO Stream
 */
/* @{ */
/**
 * @ingroup signature
 * Prints the X509_SIG structure to a BIO
 * 
 * @param bp  a BIO pointer to print to
 * @param signature pointer to the X509_SIG to be printed
 *
 * @return 1 on success, 0 on error
 */
int X509_SIG_print(
    BIO *                               bp,
    X509_SIG *                          signature) 
{
    STACK_OF(CONF_VALUE) *              values = NULL;
    values = i2v_X509_SIG(NULL,
                          signature,
                          values);
    X509V3_EXT_val_prn(bp, values, 0, 1);

    sk_CONF_VALUE_pop_free(values, X509V3_conf_free);
    return 1;
}
/* @} */


/**
 * @name Print to a File Stream
 */
/* @{ */
/**
 * @ingroup signature
 * Prints the X509_SIG structure to a file stream
 *
 * @param fp the file stream (FILE *) to print to
 * @param signature pointer to the X509_SIG to print
 *
 * @return 1 on success, 0 on error
 */
int X509_SIG_print_fp(
    FILE *                              fp,
    X509_SIG *                          signature) {

    int                                 ret;
    BIO *                               bp;
    BIO *                               b64; 
    
    bp = BIO_new(BIO_s_file());
    b64 = BIO_new(BIO_f_base64());

    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    bp = BIO_push(b64, bp);

    ret = X509_SIG_print(bp, signature);

    BIO_free(bp);
    BIO_free(b64);

    return (ret);
}
/* @} */


/**
 * @name Get the Algorithm Field
 */
/* @{ */
/**
 * @ingroup signature
 * Determines the algorithm used to generate the signature
 *
 * @param signature pointer to the X509_SIG
 * structure from which the algorithm is determined
 *
 * @return an EVP_MD structure - this structure provides
 * an interface to all the different envelope signing 
 * algorithms
 *
 * @note NOTE: This function determines which algorithm
 * is being used, based on the currently available 
 * signing algorithms implemented by openssl.  As
 * more algorithms become available, this function
 * will have to be updated.  The algorithms currently
 * available are: md2, md4, md5, sha, sha1, dss, dss1,
 * mdc2, ripemd160
 *
 * @see The openssl code and documentation for further
 * information.
 */
EVP_MD * X509_SIG_get_algorithm(
    X509_SIG *                    signature)
{
    switch(OBJ_obj2nid((ASN1_OBJECT *)signature->algor)) 
    {
        case NID_md2:        return EVP_md2();
        case NID_md4:        return EVP_md4();
        case NID_md5:        return EVP_md5();
        case NID_sha:        return EVP_sha();
        case NID_sha1:       return EVP_sha1();
        case NID_dsaWithSHA: return EVP_dss();
        case NID_dsa:        return EVP_dss1();
        case NID_mdc2:       return EVP_mdc2();
        case NID_ripemd160:  return EVP_ripemd160();
        default:             return EVP_md_null();
    }
}
/* @} */


/**
 * @name Set the Algorithm Field
 */
/* @{ */
/**
 * @ingroup signature
 * Sets the signature value of the X509_SIG structure 
 * from the X509 certificate
 *
 * @param signature pointer to the X509_SIG structure to be set
 * @param cert pointer to the X509 certificate containing the signature 
 * value to set with
 *
 * @return 1 on success, 0 if an error or the signature
 * is NULL
 */
int X509_SIG_set(
    X509_SIG *                          signature,
    X509 *                              cert)
{    
    int                                 ret;

    ret = ASN1_STRING_set(signature->digest,
                          cert->signature->data, 
                          cert->signature->length);
    X509_ALGOR_free(signature->algor);
    signature->algor = X509_ALGOR_dup(cert->sig_alg);
    return (ret);
}
/* @} */


/**
 * @name Get the Signature Field
 */
/* @{ */
/**
 * @ingroup signature
 * Returns the bit string of a signature
 *
 * @param signature the X509_SIG structure to return the bit string of
 * @param length to the length of the bit string - this value gets set
 *
 * @return the bit string in a byte array (char *)
 */
unsigned char * X509_SIG_get_signature(
    X509_SIG *                    signature,
    long *                              length) 
{
    (*length) = signature->digest->length;
    return (unsigned char *) signature->digest->data;
}    
/* @} */

STACK_OF(CONF_VALUE) * i2v_X509_SIG(
    struct v3_ext_method *              method,
    X509_SIG *                          sig,
    STACK_OF(CONF_VALUE) *              extlist)
{
    int                                 sig_nid;
    char                                sig_byte[4];
    char                                sig_ln[128];
    char                                tmp_string[128];
    char *                              sig_string = NULL;
    int                                 sig_length;
    char *                              sig_data = NULL;
    int                                 index;
    
    sig_nid = OBJ_obj2nid(sig->algor->algorithm);
    
    BIO_snprintf(sig_ln, 128, " %s", 
                 (sig_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(sig_nid));
        
    X509V3_add_value(
        "Issuer Signature:", NULL, &extlist);
    X509V3_add_value(
        "    Signature Algorithm", 
        sig_ln,
        &extlist);
        
    sig_length = sig->digest->length;
    sig_data = (char *) sig->digest->data;
    
    memset(tmp_string, 0, 128);
    sig_string = tmp_string;
    memcpy(sig_string, "        ", 8);
    sig_string += 8;
    for(index = 0; index < sig_length; ++index)
    {
        if(index != 0 && (index % 15) == 0)
        {
            sig_string[0] = '\0';
            X509V3_add_value(NULL, tmp_string, &extlist);
            memset(tmp_string, 0, 128);
            sig_string = tmp_string;
            memcpy(sig_string, "        ", 8);
            sig_string += 8;
        }
        
        BIO_snprintf(sig_byte, 4, "%02x%s", 
                     (unsigned char) sig_data[index],
                     ((index + 1) == sig_length) ? "" : ":");
        memcpy(sig_string, sig_byte, 
               ((index + 1) == sig_length) ? 2 : 3);
        if((index + 1) == sig_length)
        {
            sig_string += 2;
        }
        else
        {
            sig_string += 3;
        }
    }
    
    sig_string[0] = '\0';
    X509V3_add_value(NULL, tmp_string, &extlist);

    return extlist;
}
