
#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/evp.h>

#include "signature.h"

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
    const X509_SIG *              a,
    const X509_SIG *              b)
{
    int ret;
    ret  = (OBJ_obj2nid((ASN1_OBJECT *)a->algor) == 
	    OBJ_obj2nid((ASN1_OBJECT *)b->algor));
    ret &= ANS1_BIT_STRING_cmp(a->digest, b->digest);
    return (ret);
}

/**
 * @ingroup signature
 * Prints the X509_SIG structure to stdout
 * 
 * @param signature pointer to the X509_SIG to be printed
 *
 * @return 1 on success, 0 on error
 */
int X509_SIG_print(
    X509_SIG *                    signature) 
{
    return X509_SIG_print_fp(stdout, signature);
}

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
    X509_SIG *                    signature) {

    BIO * bp;
    int ret;
    
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    ret = BIO_fprintf(bp, "Signing Algorithm: %s\n", OBJ_obj2ln(signature->algor));
    ret &= ASN1_STRING_print(bp, (ASN1_STRING *) signature->digest);
    return (ret);
}

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
int X509_SIG_set_signature(
    X509_SIG *                    signature,
    X509 *                              cert)
{    
    return ASN1_BIT_STRING_set(signature->digest,
			       cert->signature->data, 
			       cert->signature->length);
}

/**
 * @ingroup signature
 * Returns the bit string of a signature
 *
 * @param signature the X509_SIG structure to return the bit string of
 * @param pointer to the length of the bit string - this value gets set
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
