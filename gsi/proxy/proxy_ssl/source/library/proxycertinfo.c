
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>

#include "proxy_ssl_internal.h"
#include "proxycertinfo.h"

/**
 * @ingroup proxycertinfo
 * 
 * Creates an ASN1_METHOD structure, which contains
 * pointers to routines that convert any PROXYCERTINFO
 * structure to its associated ASN1 DER encoded form
 * and vice-versa.
 *
 * @return the ASN1_METHOD object
 */
ASN1_METHOD * PROXYCERTINFO_asn1_meth()
{
    static ASN1_METHOD proxycertinfo_asn1_meth =
    {
	(int (*)())   i2d_PROXYCERTINFO,
	(char *(*)()) d2i_PROXYCERTINFO,
	(char *(*)()) PROXYCERTINFO_new,
	(void (*)())  PROXYCERTINFO_free
    };
    return (&proxycertinfo_asn1_meth);
}

/**
 * @ingroup proxycertinfo
 *
 * Allocates and initializes a new PROXYCERTINFO structure.
 *
 * @return pointer to the new PROXYCERTINFO
 */
PROXYCERTINFO * PROXYCERTINFO_new()
{
    PROXYCERTINFO * ret = NULL;
    ASN1_CTX c;
    M_ASN1_New_Malloc(ret, PROXYCERTINFO);
    ret->pC = (ASN1_BOOLEAN *)OPENSSL_malloc(sizeof(ASN1_BOOLEAN));
    *(ret->pC) = 0;
    M_ASN1_New(ret->path_length, M_ASN1_INTEGER_new);
    M_ASN1_New(ret->restriction, PROXYRESTRICTION_new);
    M_ASN1_New(ret->group, PROXYGROUP_new);
    M_ASN1_New(ret->issuer_signature, X509_SIG_new);
    return (ret);
    M_ASN1_New_Error(ASN1_F_PROXYCERTINFO_NEW);
}

/**
 * @ingroup proxycertinfo
 *
 * Frees the PROXYCERTINFO structure
 *
 * @param cert_info pointer to the PROXYCERTINFO structure
 * to be freed.
 */ 
void PROXYCERTINFO_free(
    PROXYCERTINFO *                     cert_info)
{
    if(cert_info == NULL) return;
    OPENSSL_free(cert_info->pC);
    cert_info->pC = NULL;
    PROXYRESTRICTION_free(cert_info->path_length);
    PROXYGROUP_free(cert_info->group);
    X509_SIG_free(cert_info->issuer_signature);
    OPENSSL_free(cert_info);
}

/**
 * @ingroup proxycertinfo
 *
 * Makes a copy of a PROXYCERTINFO structure
 *
 * @param cert_info the PROXYCERTINFO structure to copy
 * 
 * @return the copied PROXYCERTINFO structure
 */
PROXYCERTINFO * PROXYCERTINFO_dup(
    PROXYCERTINFO *                     cert_info)
{
    return ((PROXYCERTINFO *) ASN1_dup((int (*)())i2d_PROXYCERTINFO,
				       (char *(*)())d2i_PROXYCERTINFO,
				       (char *)cert_info));
}

/**
 * @ingroup proxycertinfo
 * 
 * Compares two PROXYCERTINFO structures
 *
 * @param a pointer to the first PROXYCERTINFO structure
 * @param b pointer to the second PROXYCERTINFO structure
 *
 * @return an integer - the result of the comparison.  
 * The comparison compares each of the fields, so if any of those
 * fields are not equal 0 is returned.  a nonzero value is returned
 * otherwise.
 */
int PROXYCERTINFO_cmp(
    const PROXYCERTINFO *               a,
    const PROXYCERTINFO *               b)
{
    int ret;

    ret = (a->pC == b->pC);
    ret &= ASN1_INTEGER_cmp(a->path_length, b->path_length);
    ret &= PROXYRESTRICTION_cmp(a->restriction, b->restriction);
    ret &= PROXYGROUP_cmp(a->group, b->group);
    ret &= X509_SIG_cmp(a->issuer_signature, b->issuer_signature);
    return (ret);
}

/**
 * @ingroup proxycertinfo
 *
 * print the PROXYCERTINFO structure to stdout
 *
 * @param cert_info the PROXYCERTINFO to print
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_print(
    BIO *                               bp,
    PROXYCERTINFO *                     cert_info) 
{
    int ret;
    ret = BIO_printf(bp, 
		      "PROXYCERTINFO::ProxyCertificate: %s\n", 
		      cert_info->pC ? "TRUE" : "FALSE");
    if(cert_info->path_length != NULL)
    {
	ret &= BIO_printf(bp, 
			  "PROXYCERTINFO::ProxyCertificatePathLength: %d\n", 
			  cert_info->path_length);
    }
    if(cert_info->restriction != NULL)
    {
	ret &= PROXYRESTRICTION_print(bp, cert_info->restriction);
    }
    if(cert_info->group)
    {
	ret &= PROXYGROUP_print(bp, cert_info->group);
    }
    if(cert_info->issuer_signature != NULL)
    {
	ret &= X509_SIG_print(bp, cert_info->issuer_signature);
    }
    return (ret);
}

/**
 * @ingroup proxycertinfo
 *
 * print the PROXYCERTINFO structure to the
 * specified file stream
 *
 * @param fp the file stream (FILE *) to print to
 * @param cert_info the PROXYCERTINFO structure to print
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_print_fp(
    FILE *                              fp,
    PROXYCERTINFO *                     cert_info)
{
    int ret;
    BIO * bp = BIO_new(BIO_s_file());
    
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    ret =  PROXYCERTINFO_print(bp, cert_info);
    BIO_free(bp);

    return (ret);
}   

/**
 * @ingroup proxycertinfo
 *
 * Returns the boolean pC value of the PROXYCERTINFO
 * structure
 *
 * @param cert_info the PROXYCERTINFO structure to get the pC value of
 *
 * @return the boolean pC value
 */
ASN1_BOOLEAN * PROXYCERTINFO_get_pC(
    PROXYCERTINFO *                     cert_info)
{
    return cert_info->pC;
}

/**
 * @ingroup proxycertinfo
 * 
 * Sets the boolean pC (proxy cert) value of the PROXYCERTINFO
 * structure
 *
 * @param cert_info the PROXYCERTINFO structure to set
 * @param pC the boolean value to set it to
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_set_pC(
    PROXYCERTINFO *                     cert_info,
    ASN1_BOOLEAN                        pC)
{
    *(cert_info->pC) = pC;
    return 1;
}

/**
 * @ingroup proxycertinfo
 *
 * Sets the group of this PROXYCERTINFO structure
 * Since this is an optional value in the ASN1 encoding
 * it can be set to NULL here - which means that when
 * the PROXYCERTINFO struct is converted to its DER encoded
 * form, the group field won't be included.  
 *
 * This function makes
 * a copy of the PROXYGROUP variable passed in, and
 * the copy becomes the current value for the group field.
 *
 * @param cert_info the PROXYCERTINFO structure to set
 * @param group the group to set it to
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_set_group(
    PROXYCERTINFO *                     cert_info,
    PROXYGROUP *                        group)
{
    PROXYGROUP_free(cert_info->group);
    if(group != NULL)
    {
	cert_info->group = PROXYGROUP_dup(group);
    }
    else
    {
	cert_info->group = NULL;
    }
    return 1;
}

/**
 * @ingroup proxycertinfo
 *
 * Returns the PROXYGROUP of this PROXYCERTINFO
 *
 * @param cert_info the PROXYCERTINFO to get
 * the PROXYGROUP from
 * 
 * @return the PROXYGROUP of the PROXYCERTINFO
 */
PROXYGROUP * PROXYCERTINFO_get_group(
    PROXYCERTINFO *                     cert_info)
{
    return cert_info->group;
}

/**
 * @ingroup proxycertinfo
 *
 * Sets the restriction on the PROXYCERTINFO
 * Since this is an optional field in the
 * ASN1 encoding, this variable can be set
 * to NULL through this function - which
 * means that when the PROXYCERTINFO is encoded
 * the restriction won't be included.
 *
 * @param cert_info the PROXYCERTINFO object
 * to set the restriction of
 * @param restriction the PROXYRESTRICTION
 * to set it to
 *
 * @return 1 if success, 0 if error
 */
int PROXYCERTINFO_set_restriction(
    PROXYCERTINFO *                     cert_info,
    PROXYRESTRICTION *                  restriction)
{
    PROXYRESTRICTION_free(cert_info->restriction);
    if(restriction != NULL)
    {
	cert_info->restriction = PROXYRESTRICTION_dup(restriction);
    }
    else
    {
	cert_info->restriction = NULL;
    }
    return 1;
}

/**
 * @ingroup proxycertinfo
 * 
 * Gets the restriction on the PROXYCERTINFO
 * 
 * @param cert_info the PROXYCERTINFO to get the restriction of
 *
 * @return the PROXYRESTRICTION of the PROXYCERTINFO
 */
PROXYRESTRICTION * PROXYCERTINFO_get_restriction(
    PROXYCERTINFO *                     cert_info)
{
    return cert_info->restriction;
}

/**
 * @ingroup proxycertinfo
 *
 * Sets the path length of the PROXYCERTINFO. The path length specifices 
 * the maximum depth of the path of the Proxy Certificates that
 * can be signed by an End Entity Certificate (EEC) or Proxy Certificate.
 *
 * Since this is an optional field in its ASN1 coded representation,
 * it can be set to NULL through this function - which means
 * that it won't be included in the encoding.
 *
 * @param cert_info the PROXYCERTINFO to set the path length of
 * @param path_length the path length to set it to
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_set_path_length(
    PROXYCERTINFO *                     cert_info,
    long *                               path_length)
{
    if(cert_info != NULL) 
    {
	if(path_length != NULL)
	{
	    return ASN1_INTEGER_set(cert_info->path_length, *path_length);
	}
	else
	{
	    cert_info->path_length = NULL;
	    return 1;
	}
    }
    return 0;
}

/**
 * @ingroup proxycertinfo
 * 
 * Gets the path length of the PROXYCERTINFO.
 *
 * @see PROXYCERTINFO_set_path_length
 *
 * @param cert_info the PROXYCERTINFO to get the path length from
 * 
 * @return the path length of the PROXYCERTINFO
 */
ASN1_INTEGER * PROXYCERTINFO_get_path_length(
    PROXYCERTINFO *                     cert_info)
{
    return cert_info->path_length;
}

/**
 * @ingroup proxycertinfo
 *
 * Sets the signed cert digest of the issuer's cert
 * for a PROXYCERTINFO.  Since this field is optional
 * in the ASN1 encoding, this variable can be set 
 * to NULL - which means that it won't be included
 * in the ASN1 encoding.
 *
 * @param cert_info the PROXYCERTINFO to set the 
 * signed cert digest of
 * @param cert_digest the X509_SIG to set the
 * PROXYCERTINFO issuer's signature to
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_set_issuer_cert_digest(
    PROXYCERTINFO *                     cert_info,
    X509_SIG *                          cert_digest)
{
    X509_SIG_free(cert_info->issuer_signature);
    if(cert_digest != NULL) 
    {
	cert_info->issuer_signature = (X509_SIG *) ASN1_dup((int (*)())   i2d_X509_SIG, 
							    (char *(*)()) d2i_X509_SIG, 
							    (char *)      cert_digest);
    }
    else
    {
	cert_info->issuer_signature = NULL;
    }
    return 1;
}

/**
 * @ingroup proxycertinfo
 *
 * Gets the signed cert digest of the issuer's cert
 * for a PROXYCERTINFO
 *
 * @param cert_info the PROXYCERTINFO to get issuer's  signed
 * cert digest of
 *
 * @return the signed cert digest of the issuer's certificate
 */
X509_SIG * PROXYCERTINFO_get_issuer_cert_digest(
    PROXYCERTINFO *                     cert_info)
{
    return cert_info->issuer_signature;
}
    
/**
 * @ingroup proxycertinfo
 * 
 * Converts the PROXYCERTINFO structure from internal
 * format to a DER encoded ASN.1 string
 *
 * @param cert_info the PROXYCERTINFO structure to convert
 * @param buffer the resulting DER encoded string
 *
 * @return the length of the DER encoded string
 */
int i2d_PROXYCERTINFO(
    PROXYCERTINFO *                     cert_info,
    unsigned char **                    buffer)
{
    unsigned char ** pp = buffer;
    int v1 = 0, v2 = 0, v3 = 0, v4 = 0;

    M_ASN1_I2D_vars(cert_info);
    M_ASN1_I2D_len(*(cert_info->pC),              
		   i2d_ASN1_BOOLEAN);
    M_ASN1_I2D_len_EXP_opt(cert_info->path_length,      
			   i2d_ASN1_INTEGER,
			   0, v1);
    M_ASN1_I2D_len_EXP_opt(cert_info->restriction,      
			   i2d_PROXYRESTRICTION,
			   0, v2);
    M_ASN1_I2D_len_EXP_opt(cert_info->group,
			   i2d_PROXYGROUP,
			   0, v3);
    M_ASN1_I2D_len_EXP_opt(cert_info->issuer_signature,
			   i2d_X509_SIG,
			   0, v4);
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(*(cert_info->pC),
		   i2d_ASN1_BOOLEAN);
    M_ASN1_I2D_put_EXP_opt(cert_info->path_length,
			   i2d_ASN1_INTEGER,
			   0, v1);
    M_ASN1_I2D_put_EXP_opt(cert_info->restriction,
			   i2d_PROXYRESTRICTION,
			   0, v2);
    M_ASN1_I2D_put_EXP_opt(cert_info->group,
			   i2d_PROXYGROUP,
			   0, v3);
    M_ASN1_I2D_put_EXP_opt(cert_info->issuer_signature,
			   i2d_X509_SIG,
			   0, v4);
    M_ASN1_I2D_finish();
}

/**
 * @ingroup
 *
 * Convert from a DER encoded ASN.1 string of a PROXYCERTINFO
 * to its internal structure
 *
 * @param cert_info the resulting PROXYCERTINFO in internal form
 * @param buffer the DER encoded ASN.1 string containing
 * the PROXYCERTINFO 
 * @param the length of the buffer
 *
 * @return the resultingin PROXYCERTINFO in internal form
 */						
PROXYCERTINFO * d2i_PROXYCERTINFO(
    PROXYCERTINFO **                    cert_info,
    unsigned char **                    buffer,
    long                                length)
{
    unsigned char ** pp = buffer;

    M_ASN1_D2I_vars(cert_info, PROXYCERTINFO *, PROXYCERTINFO_new);
    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    if((c.slen != 0) && (M_ASN1_next == (V_ASN1_UNIVERSAL|V_ASN1_BOOLEAN)))
    {
	c.q = c.p;
	if(d2i_ASN1_BOOLEAN(ret->pC, &c.p, c.slen) < 0) goto err;
	c.slen -= (c.p - c.q);
    }

    M_PROXY_ASN1_D2I_get_EXP_opt(ret->path_length, 
				 d2i_ASN1_INTEGER, 
				 ASN1_INTEGER_free);
    M_PROXY_ASN1_D2I_get_EXP_opt(ret->restriction, 
				 d2i_PROXYRESTRICTION, 
				 PROXYRESTRICTION_free);
    M_PROXY_ASN1_D2I_get_EXP_opt(ret->group,
				 d2i_PROXYGROUP,
				 PROXYGROUP_free);
    M_PROXY_ASN1_D2I_get_EXP_opt(ret->issuer_signature, 
				 d2i_X509_SIG,
				 X509_SIG_free);
    M_ASN1_D2I_Finish(cert_info, 
		      PROXYCERTINFO_free, 
		      ASN1_F_D2I_PROXYCERTINFO);
}
