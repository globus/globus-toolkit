/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    ret->path_length      = NULL;
    ret->policy           = PROXYPOLICY_new();
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
    ASN1_INTEGER_free(cert_info->path_length);
    PROXYPOLICY_free(cert_info->policy);
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
 * fields are not equal then a nonzero value is returned. Equality
 * is indicated by returning a 0.
 */
int PROXYCERTINFO_cmp(
    const PROXYCERTINFO *               a,
    const PROXYCERTINFO *               b)
{
    if(ASN1_INTEGER_cmp(a->path_length, b->path_length) ||
       PROXYPOLICY_cmp(a->policy, b->policy))
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
                               NULL);

    X509V3_EXT_val_prn(bp, values, 0, 1);
    
    sk_CONF_VALUE_pop_free(values, X509V3_conf_free);
    return 1;
}
/* PROXYCERTINFO_print() */
/* @} */


/**
 * @name Print To Stream
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
 * @name Set the Policy Field
 */
/* @{ */
/**
 * @ingroup proxycertinfo
 *
 * Sets the policy on the PROXYCERTINFO
 * Since this is an optional field in the
 * ASN1 encoding, this variable can be set
 * to NULL through this function - which
 * means that when the PROXYCERTINFO is encoded
 * the policy won't be included.
 *
 * @param cert_info the PROXYCERTINFO object
 * to set the policy of
 * @param policy the PROXYPOLICY
 * to set it to
 *
 * @return 1 if success, 0 if error
 */
int PROXYCERTINFO_set_policy(
    PROXYCERTINFO *                     cert_info,
    PROXYPOLICY *                       policy)
{
    PROXYPOLICY_free(cert_info->policy);
    if(policy != NULL)
    {
        cert_info->policy = PROXYPOLICY_dup(policy);
    }
    else
    {
        cert_info->policy = NULL;
    }
    return 1;
}
/* PROXYCERTINFO_set_policy() */
/* @} */

/**
 * @name Get the Policy Field 
 */
/* @{ */
/**
 * @ingroup proxycertinfo
 * 
 * Gets the policy on the PROXYCERTINFO
 * 
 * @param cert_info the PROXYCERTINFO to get the policy of
 *
 * @return the PROXYPOLICY of the PROXYCERTINFO
 */
PROXYPOLICY * PROXYCERTINFO_get_policy(
    PROXYCERTINFO *                     cert_info)
{
    if(cert_info)
    {
        return cert_info->policy;
    }
    return NULL;
}
/* PROXYCERTINFO_get_policy() */
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
 * @name Convert PROXYCERTINFO to DER encoded form
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
    M_ASN1_I2D_vars(cert_info);

    if(cert_info->path_length)
    { 
        M_ASN1_I2D_len(cert_info->path_length, i2d_ASN1_INTEGER);
    }
    
    M_ASN1_I2D_len(cert_info->policy, i2d_PROXYPOLICY);

    M_ASN1_I2D_seq_total();
    if(cert_info->path_length)
    { 
        M_ASN1_I2D_put(cert_info->path_length, i2d_ASN1_INTEGER);
    }
    M_ASN1_I2D_put(cert_info->policy, i2d_PROXYPOLICY);
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

    M_ASN1_D2I_get_EXP_opt(ret->path_length,
                           d2i_ASN1_INTEGER,
                           1);
    
    M_ASN1_D2I_get_opt(ret->path_length, 
                       d2i_ASN1_INTEGER,
                       V_ASN1_INTEGER);

    M_ASN1_D2I_get(ret->policy,d2i_PROXYPOLICY);

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
        NULL,
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

/**
 * @name Convert old PROXYCERTINFO to DER encoded form
 */
/* @{ */
/**
 * @ingroup proxycertinfo
 * 
 * Converts the old PROXYCERTINFO structure from internal
 * format to a DER encoded ASN.1 string
 *
 * @param cert_info the old PROXYCERTINFO structure to convert
 * @param pp the resulting DER encoded string
 *
 * @return the length of the DER encoded string
 */
int i2d_PROXYCERTINFO_OLD(
    PROXYCERTINFO *                     cert_info,
    unsigned char **                    pp)
{
    int                                 v1;

    M_ASN1_I2D_vars(cert_info);
    
    v1 = 0;

    M_ASN1_I2D_len(cert_info->policy,      
                   i2d_PROXYPOLICY);
    M_ASN1_I2D_len_EXP_opt(cert_info->path_length,      
                           i2d_ASN1_INTEGER,
                           1, v1);

    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(cert_info->policy, i2d_PROXYPOLICY);
    M_ASN1_I2D_put_EXP_opt(cert_info->path_length, i2d_ASN1_INTEGER, 1, v1);
    M_ASN1_I2D_finish();
}
/* i2d_PROXYCERTINFO_OLD() */
/* @} */

/**
 * @name Convert a old PROXYCERTINFO to internal form
 */
/* @{ */
/**
 * @ingroup
 *
 * Convert from a DER encoded ASN.1 string of a old PROXYCERTINFO
 * to its internal structure
 *
 * @param cert_info the resulting old PROXYCERTINFO in internal form
 * @param buffer the DER encoded ASN.1 string containing
 * the old PROXYCERTINFO 
 * @param the length of the buffer
 *
 * @return the resulting old  PROXYCERTINFO in internal form
 */                                             
PROXYCERTINFO * d2i_PROXYCERTINFO_OLD(
    PROXYCERTINFO **                    cert_info,
    unsigned char **                    pp,
    long                                length)
{
    M_ASN1_D2I_vars(cert_info, PROXYCERTINFO *, PROXYCERTINFO_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();

    M_ASN1_D2I_get(ret->policy,d2i_PROXYPOLICY);

    M_ASN1_D2I_get_EXP_opt(ret->path_length,
                           d2i_ASN1_INTEGER,
                           1);

    M_ASN1_D2I_Finish(cert_info, 
                      PROXYCERTINFO_free, 
                      ASN1_F_D2I_PROXYCERTINFO);
}
/* d2i_PROXYCERTINFO() */
/* @} */

X509V3_EXT_METHOD * PROXYCERTINFO_OLD_x509v3_ext_meth()
{
    static X509V3_EXT_METHOD proxycertinfo_x509v3_ext_meth =
    {
        -1,
        X509V3_EXT_MULTILINE,
        NULL,
        (X509V3_EXT_NEW) PROXYCERTINFO_new,
        (X509V3_EXT_FREE) PROXYCERTINFO_free,
        (X509V3_EXT_D2I) d2i_PROXYCERTINFO_OLD,
        (X509V3_EXT_I2D) i2d_PROXYCERTINFO_OLD,
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
    
    if(!ext)
    {
        extlist = NULL;
        return extlist;
    }

    if(extlist == NULL)
    {
        extlist = sk_CONF_VALUE_new_null();
        if(extlist == NULL)
        { 
            return NULL;
        }
    }
    
    if(PROXYCERTINFO_get_path_length(ext) > -1)
    {
        memset(tmp_string, 0, len);
        BIO_snprintf(tmp_string, len, " %lu (0x%lx)",
                     PROXYCERTINFO_get_path_length(ext),
                     PROXYCERTINFO_get_path_length(ext));
        X509V3_add_value("Path Length", tmp_string, &extlist);
    }

    if(PROXYCERTINFO_get_policy(ext))
    {
        i2v_PROXYPOLICY(PROXYPOLICY_x509v3_ext_meth(),
                             PROXYCERTINFO_get_policy(ext),
                             extlist);
    }


    return extlist;
}
