#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file proxycertinfo.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 * $Author$
 */
#endif

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509v3.h>

#include "proxycertinfo.h"

/**
 * @name ASN1_METHOD
 */
/*@{*/
/** 
 * Define the functions required for 
 * manipulating a PROXYCERTINFO and its ASN1 form. 
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
/* PROXYCERTINFO_asn1_meth() */
/*@}*/


/**
 * @name New
 */
/*@{*/
/**
 * Create a new PROXYCERTINFO.
 * @ingroup proxycertinfo
 *
 * Allocates and initializes a new PROXYCERTINFO structure.
 *
 * @return pointer to the new PROXYCERTINFO
 */
PROXYCERTINFO * PROXYCERTINFO_new()
{
    PROXYCERTINFO *                     ret;
    ASN1_CTX                            c;

    ret = NULL;

    M_ASN1_New_Malloc(ret, PROXYCERTINFO);
    memset(ret, (int) NULL, sizeof(PROXYCERTINFO));
    ret->pC = (ASN1_BOOLEAN *)OPENSSL_malloc(sizeof(ASN1_BOOLEAN));
    *(ret->pC) = 1;
    ret->version          = ASN1_INTEGER_new();
    ASN1_INTEGER_set(ret->version, 1);  // current first version of protocol
    ret->path_length      = NULL;
    ret->restriction      = NULL;
    ret->group            = NULL;
    ret->issuer_signature = NULL;
    return (ret);
    M_ASN1_New_Error(ASN1_F_PROXYCERTINFO_NEW);
}
/* PROXYCERTINFO_new() */
/* @} */


/**
 * @name Free.
 */
/* @{ */
/**
 * Free a PROXYCERTINFO.
 * @ingroup proxycertinfo
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
    ASN1_INTEGER_free(cert_info->version);
    ASN1_INTEGER_free(cert_info->path_length);
    PROXYRESTRICTION_free(cert_info->restriction);
    PROXYGROUP_free(cert_info->group);
    X509_SIG_free(cert_info->issuer_signature);
    OPENSSL_free(cert_info);
}
/* PROXYCERTINFO_free */
/* @} */


/**
 * @name Duplicate
 */
/* @{ */
/**
 * Makes a copy of a PROXYCERTINFO.
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
/* PROXYCERINFO_dup() */
/* @} */

/**
 * @name Compare
 */
/* @{ */
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
    if(ASN1_INTEGER_cmp(a->version, b->version) && 
       (a->pC == b->pC) &&
       ASN1_INTEGER_cmp(a->path_length, b->path_length) &&
       PROXYRESTRICTION_cmp(a->restriction, b->restriction) &&
       PROXYGROUP_cmp(a->group, b->group) &&
       X509_SIG_cmp(a->issuer_signature, b->issuer_signature))
    {
        return 1;
    }
    return 0;
}
/* PROXYCERTINFO_cmp() */
/* @} */


/**
 * @name Print to a BIO stream
 */
/* @{ */
/**
 * @ingroup proxycertinfo
 *
 * print the PROXYCERTINFO structure to stdout
 *
 * @param bp the BIO to print to
 * @param cert_info the PROXYCERTINFO to print
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_print(
    BIO *                               bp,
    PROXYCERTINFO *                     cert_info) 
{
    STACK_OF(CONF_VALUE) *              values = NULL;

    values = i2v_PROXYCERTINFO(PROXYCERTINFO_x509v3_ext_meth(),
                               cert_info,
                               values);

    X509V3_EXT_val_prn(bp, values, 0, 1);
    
    sk_CONF_VALUE_pop_free(values, X509V3_conf_free);
    return 1;
}
/* PROXYCERTINFO_print() */
/* @} */


/**
 * @name Print From Stream
 */
/* @{ */
/**
 * @ingroup proxycertinfo
 *
 * print the PROXYCERTINFO structure to the
 * specified file stream
 *
 * @param fp the file stream (FILE *) to print to
 * @param cert_info the PROXYCERTINFO structure to print
 *
 * @return the number of characters printed
 */
int PROXYCERTINFO_print_fp(
    FILE *                              fp,
    PROXYCERTINFO *                     cert_info)
{
    int                                 ret;
    BIO *                               bp;

    bp = BIO_new(BIO_s_file());
    
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    ret =  PROXYCERTINFO_print(bp, cert_info);
    BIO_free(bp);

    return (ret);
}   
/* PROXYCERTINFO_print_fp() */
/* @} */


/**
 * @name Get the Proxy Certificate Field
 */
/* @{ */
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
    if(cert_info)
    {
        return cert_info->pC;
    }
    return NULL;
}
/* PROXYCERTINFO_get_pC() */
/* @} */


/**
 * @name Set the Proxy Certificate Field
 */
/* @{ */
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
/* PROXYCERTINFO_set_pC() */
/* @} */


/**
 * @name Set the Version Field
 */
/* @{ */
/** 
 * @ingroup proxycertinfo
 *
 * Sets the version of the PROXYCERTINFO struct
 * 
 * @param cert_info the PROXYCERTINFO to set the version of
 * @param version the version to set it to
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_set_version(
    PROXYCERTINFO *                     cert_info,
    long                                version)
{
    return ASN1_INTEGER_set(cert_info->version, version);
}
/* PROXYCERTINFO_set_version */
/* @} */

/**
 * @name Get the Version Field
 */
/* @{ */
/**
 * @ingroup proxycertinfo
 *
 * Gets the version of the PROXYCERTINFO structure
 *
 * @param cert_info the PROXYCERTINFO to get the version of
 *
 * @return the version
 */
long PROXYCERTINFO_get_version(
    PROXYCERTINFO *                     cert_info)
{
    if(cert_info)
    {
        return ASN1_INTEGER_get(cert_info->version);
    }
    return -1;
}
/* PROXYCERTINFO_get_version() */
/* @} */


/**
 * @name Set the Group Field
 */
/* @{ */
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
/* PROXYCERTINFO_set_group() */
/* @} */


/**
 * @name Get the Group Field
 */
/* @{ */
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
    if(cert_info)
    {
        return cert_info->group;
    }
    return NULL;
}
/* PROXYCERTINFO_get_group() */
/* @} */


/**
 * @name Set the Restriction Field
 */
/* @{ */
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
/* PROXYCERTINFO_set_restriction() */
/* @} */

/**
 * @name Get the Restriction Field 
 */
/* @{ */
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
    if(cert_info)
    {
        return cert_info->restriction;
    }
    return NULL;
}
/* PROXYCERTINFO_get_restriction() */
/* @} */


/**
 * @name Set the Path Length Field 
 */
/* @{ */
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
 *        if -1 is passed in, the path length gets unset,
 *        which configures the PROXYCERTINFO
 *        to not include the path length in the DER encoding
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_set_path_length(
    PROXYCERTINFO *                     cert_info,
    long                                path_length)
{
    if(cert_info != NULL) 
    {
        if(path_length != -1)
        {
            if(cert_info->path_length == NULL)
            {
                cert_info->path_length = ASN1_INTEGER_new();
            }
            return ASN1_INTEGER_set(cert_info->path_length, path_length);
        }
        else
        {
            if(cert_info->path_length != NULL)
            {
                ASN1_INTEGER_free(cert_info->path_length);
                cert_info->path_length = NULL;
            }
            return 1;
        }
    }
    return 0;
}
/* PROXYCERTINFO_set_path_length() */
/* @} */


/**
 * @name Get Path Length Field
 */
/* @{ */
/**
 * @ingroup proxycertinfo
 * 
 * Gets the path length of the PROXYCERTINFO.
 *
 * @see PROXYCERTINFO_set_path_length
 *
 * @param cert_info the PROXYCERTINFO to get the path length from
 * 
 * @return the path length of the PROXYCERTINFO, or -1 if not set
 */
long PROXYCERTINFO_get_path_length(
    PROXYCERTINFO *                     cert_info)
{
    if(cert_info && cert_info->path_length)
    {
        return ASN1_INTEGER_get(cert_info->path_length);
    }
    else
    {
        return -1;
    }
}
/* PROXYCERTINFO_get_path_length() */
/* @} */

/**
 * @name Set Issuer Signature Field
 */
/* @{ */
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
 * @param signature the X509_SIG to set the
 * PROXYCERTINFO issuer's signature to
 *
 * @return 1 on success, 0 on error
 */
int PROXYCERTINFO_set_issuer_signature(
    PROXYCERTINFO *                     cert_info,
    X509_SIG *                          signature)
{
    X509_SIG_free(cert_info->issuer_signature);
    if(signature != NULL) 
    {
        cert_info->issuer_signature = 
            (X509_SIG *) ASN1_dup((int (*)())   i2d_X509_SIG, 
                                  (char *(*)()) d2i_X509_SIG, 
                                  (char *)      signature);
    }
    else
    {
        cert_info->issuer_signature = NULL;
    }
    return 1;
}
/* PROXYCERTINFO_set_issuer_signature() */
/* @} */


/**
 * @name Get Issuer Signature Field
 */
/* @{ */
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
X509_SIG * PROXYCERTINFO_get_issuer_signature(
    PROXYCERTINFO *                     cert_info)
{
    if(cert_info && cert_info->issuer_signature)
    {
        return (X509_SIG *) 
            ASN1_dup((int (*)())   i2d_X509_SIG,
                     (char *(*)()) d2i_X509_SIG,
                     (char *)      cert_info->issuer_signature);
    }
    
    return NULL;
}
/* PROXYCERTINFO_get_issuer_signature() */
/* @} */

    
/**
 * @name Convert PROXYCERTINFO to DER encoding
 */
/* @{ */
/**
 * @ingroup proxycertinfo
 * 
 * Converts the PROXYCERTINFO structure from internal
 * format to a DER encoded ASN.1 string
 *
 * @param cert_info the PROXYCERTINFO structure to convert
 * @param pp the resulting DER encoded string
 *
 * @return the length of the DER encoded string
 */
int i2d_PROXYCERTINFO(
    PROXYCERTINFO *                     cert_info,
    unsigned char **                    pp)
{
    int                                 v1,
                                        v2,
                                        v3,
                                        v4;

    M_ASN1_I2D_vars(cert_info);
    
    v1 = v2 = v3 = v4 = 0;

    M_ASN1_I2D_len(cert_info->version, i2d_ASN1_INTEGER);
    M_ASN1_I2D_len(*(cert_info->pC), i2d_ASN1_BOOLEAN);

    M_ASN1_I2D_len_EXP_opt(cert_info->path_length,      
                           i2d_ASN1_INTEGER,
                           1, v1);
    M_ASN1_I2D_len_EXP_opt(cert_info->restriction,      
                           i2d_PROXYRESTRICTION, 2, v2);
    M_ASN1_I2D_len_EXP_opt(cert_info->group, 
                           i2d_PROXYGROUP, 3, v3);
    M_ASN1_I2D_len_EXP_opt(cert_info->issuer_signature, 
                           i2d_X509_SIG, 4, v4);
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(cert_info->version, i2d_ASN1_INTEGER);
    M_ASN1_I2D_put(*(cert_info->pC), i2d_ASN1_BOOLEAN);
    M_ASN1_I2D_put_EXP_opt(cert_info->path_length, i2d_ASN1_INTEGER, 1, v1);
    M_ASN1_I2D_put_EXP_opt(cert_info->restriction, 
                           i2d_PROXYRESTRICTION, 2, v2);
    M_ASN1_I2D_put_EXP_opt(cert_info->group, 
                           i2d_PROXYGROUP, 3, v3);
    M_ASN1_I2D_put_EXP_opt(cert_info->issuer_signature,
                           i2d_X509_SIG, 4, v4);
    M_ASN1_I2D_finish();
}
/* i2d_PROXYCERTINFO() */
/* @} */

/**
 * @name Convert a PROXYCERTINFO to internal form
 */
/* @{ */
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
    unsigned char **                    pp,
    long                                length)
{
    M_ASN1_D2I_vars(cert_info, PROXYCERTINFO *, PROXYCERTINFO_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    M_ASN1_D2I_get(ret->version, d2i_ASN1_INTEGER);

    if((c.slen != 0) && (M_ASN1_next == (V_ASN1_UNIVERSAL|V_ASN1_BOOLEAN)))
    {
        c.q = c.p;
        if(d2i_ASN1_BOOLEAN(ret->pC, &c.p, c.slen) < 0) goto err;
        c.slen -= (c.p - c.q);
    }

    M_ASN1_D2I_get_EXP_opt(ret->path_length, 
                           d2i_ASN1_INTEGER, 
                           1);
    M_ASN1_D2I_get_EXP_opt(ret->restriction, 
                           d2i_PROXYRESTRICTION, 
                           2);
    M_ASN1_D2I_get_EXP_opt(ret->group,
                           d2i_PROXYGROUP, 
                           3);
    M_ASN1_D2I_get_EXP_opt(ret->issuer_signature, 
                           d2i_X509_SIG, 
                           4);
    M_ASN1_D2I_Finish(cert_info, 
                      PROXYCERTINFO_free, 
                      ASN1_F_D2I_PROXYCERTINFO);
}
/* d2i_PROXYCERTINFO() */
/* @} */

X509V3_EXT_METHOD * PROXYCERTINFO_x509v3_ext_meth()
{
    static X509V3_EXT_METHOD proxycertinfo_x509v3_ext_meth =
    {
        -1,
        X509V3_EXT_MULTILINE,
        (X509V3_EXT_NEW) PROXYCERTINFO_new,
        (X509V3_EXT_FREE) PROXYCERTINFO_free,
        (X509V3_EXT_D2I) d2i_PROXYCERTINFO,
        (X509V3_EXT_I2D) i2d_PROXYCERTINFO,
        NULL, NULL,
        (X509V3_EXT_I2V) i2v_PROXYCERTINFO,
        NULL,
        NULL, NULL,
        NULL
    };
    return (&proxycertinfo_x509v3_ext_meth);
}

STACK_OF(CONF_VALUE) * i2v_PROXYCERTINFO(
    struct v3_ext_method *              method,
    PROXYCERTINFO *                     ext,
    STACK_OF(CONF_VALUE) *              extlist)
{
    int                                 len = 128;
    char                                tmp_string[128];
    X509_SIG *                          sig = NULL;
    
    if(ext)
    {
        extlist = NULL;
        return extlist;
    }

    snprintf(tmp_string, len, " %lu (0x%lx)", 
             PROXYCERTINFO_get_version(ext),
             PROXYCERTINFO_get_version(ext));

    X509V3_add_value("Version", tmp_string, &extlist);
    X509V3_add_value("Proxy Certificate", 
                     PROXYCERTINFO_get_pC(ext) ? " TRUE" : " FALSE",
                      &extlist);

    if(PROXYCERTINFO_get_path_length(ext) > -1)
    {
        memset(tmp_string, 0, len);
        snprintf(tmp_string, len, " %lu (0x%lx)",
                 PROXYCERTINFO_get_path_length(ext),
                 PROXYCERTINFO_get_path_length(ext));
        X509V3_add_value("Path Length", tmp_string, &extlist);
    }

    if(PROXYCERTINFO_get_restriction(ext))
    {
        i2v_PROXYRESTRICTION(PROXYRESTRICTION_x509v3_ext_meth(),
                             PROXYCERTINFO_get_restriction(ext),
                             extlist);
    }

    if(PROXYCERTINFO_get_group(ext))
    {
        i2v_PROXYGROUP(PROXYGROUP_x509v3_ext_meth(),
                       PROXYCERTINFO_get_group(ext),
                       extlist);
    }

    sig = PROXYCERTINFO_get_issuer_signature(ext);

    if(sig)
    {
        i2v_X509_SIG(NULL,
                     sig,
                     extlist);
        X509_SIG_free(sig);
    }

    return extlist;
}
