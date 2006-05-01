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


#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include <openssl/objects.h>

#include "proxypolicy.h"

/**
 * @name Get a method for ASN1 conversion
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *  
 * Creates an ASN1_METHOD structure, which contains
 * pointers to routines that convert any PROXYPOLICY
 * structure to its associated ASN1 DER encoded form
 * and vice-versa.
 *
 * @return the ASN1_METHOD object
 */

ASN1_METHOD * PROXYPOLICY_asn1_meth()
{
    static ASN1_METHOD proxypolicy_asn1_meth =
    {
        (int (*)())   i2d_PROXYPOLICY,
        (char *(*)()) d2i_PROXYPOLICY,
        (char *(*)()) PROXYPOLICY_new,
        (void (*)())  PROXYPOLICY_free
    };
    return (&proxypolicy_asn1_meth);
}
/* PROXYPOLICY_asn1_meth() */
/* @} */

/**
 * @name New
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *
 * Allocates and initializes a new PROXYPOLICY structure.
 *
 * @return pointer to the new PROXYPOLICY
 */
PROXYPOLICY * PROXYPOLICY_new()
{
    ASN1_CTX                            c;
    PROXYPOLICY *                       ret;

    ret = NULL;

    M_ASN1_New_Malloc(ret, PROXYPOLICY);
    ret->policy_language = OBJ_nid2obj(OBJ_sn2nid(IMPERSONATION_PROXY_SN));
    ret->policy = NULL;
    return (ret);
    M_ASN1_New_Error(ASN1_F_PROXYPOLICY_NEW);
}
/* PROXYPOLICY_new() */
/* @} */


/**
 * @name Free
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *
 * Frees a PROXYPOLICY
 *
 * @param policy the proxy policy to free
 */
void PROXYPOLICY_free(
    PROXYPOLICY *                       policy)
{
    if(policy == NULL) return;
    ASN1_OBJECT_free(policy->policy_language);
    M_ASN1_OCTET_STRING_free(policy->policy);
    OPENSSL_free(policy);
}
/* PROXYPOLICY_free() */
/* @} */


/**
 * @name Duplicate
 */
/* @{ */
/**
 * @ingroup proxypolicy
 * 
 * Makes a copy of the proxypolicy - this function
 * allocates space for a new PROXYPOLICY, so the
 * returned PROXYPOLICY must be freed when
 * its no longer needed
 *
 * @param policy the proxy policy to copy
 *
 * @return the new PROXYPOLICY
 */
PROXYPOLICY * PROXYPOLICY_dup(
    PROXYPOLICY *                       policy)
{
    return ((PROXYPOLICY *) ASN1_dup((int (*)())i2d_PROXYPOLICY,
                                     (char *(*)())d2i_PROXYPOLICY,
                                     (char *)policy));
}
/* PROXYPOLICY_dup() */
/* @} */


/**
 * @name Compare
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *
 * Compares two PROXYPOLICY structs for equality
 * This function first compares the policy language numeric
 * id's, if they're equal, it then compares the two policies.
 *
 * @return 0 if equal, nonzero if not
 */
int PROXYPOLICY_cmp(
    const PROXYPOLICY *                 a,
    const PROXYPOLICY *                 b)
{
    
    if((a->policy_language->nid != b->policy_language->nid) ||
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
 * @ingroup proxypolicy
 *
 * Prints the PROXYPOLICY struct using the BIO stream
 *
 * @param bp the BIO stream to print to
 * @param policy the PROXYPOLICY to print
 *
 * @return 1 on success, 0 on error
 */
int PROXYPOLICY_print(
    BIO *                               bp,
    PROXYPOLICY *                       policy)
{
    STACK_OF(CONF_VALUE) *              values = NULL;

    values = i2v_PROXYPOLICY(PROXYPOLICY_x509v3_ext_meth(),
                             policy,
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
 * @ingroup proxypolicy
 *
 * Prints the PROXYPOLICY to the file stream FILE*
 *
 * @param fp the FILE* stream to print to
 * @param policy the PROXYPOLICY to print
 *
 * @return number of bytes printed, -2 or -1 on error
 */
int PROXYPOLICY_print_fp(
    FILE *                              fp,
    PROXYPOLICY *                       policy)
{
    int                                 ret;

    BIO * bp = BIO_new(BIO_s_file());    
    BIO_set_fp(bp, fp, BIO_NOCLOSE);
    ret = PROXYPOLICY_print(bp, policy);
    BIO_free(bp);

    return (ret);
}
/* @} */


/**
 * @name Set the Policy Language Field
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *
 * Sets the policy language of the PROXYPOLICY
 *
 * @param policy the PROXYPOLICY to set the policy language of
 * @param policy_language the policy language to set it to
 *
 * @return 1 on success, 0 on error
 */
int PROXYPOLICY_set_policy_language(
    PROXYPOLICY *                       policy,
    ASN1_OBJECT *                       policy_language)
{
    if(policy_language != NULL) 
    {
        ASN1_OBJECT_free(policy->policy_language);
        policy->policy_language = OBJ_dup(policy_language);
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
 * @ingroup proxypolicy
 * 
 * Gets the policy language of the PROXYPOLICY
 *
 * @param policy the proxy policy to get the policy language
 * of
 * 
 * @return the policy language as an ASN1_OBJECT
 */    
ASN1_OBJECT * PROXYPOLICY_get_policy_language(
    PROXYPOLICY *                       policy)
{
    return policy->policy_language;
}
/* @} */

/**
 * @name Set the Policy Field
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *
 * Sets the policy of the PROXYPOLICY
 *
 * @param proxypolicy the proxy policy to set the policy of
 * @param policy the policy to set it to
 * @param length the lenght of the policy
 *
 * @return 1 on success, 0 on error
 */
int PROXYPOLICY_set_policy(
    PROXYPOLICY *                       proxypolicy,
    unsigned char *                     policy,
    int                                 length)
{
    if(policy != NULL)
    {
        unsigned char *                 copy = malloc(length);
        memcpy(copy, policy, length);

        if(!proxypolicy->policy)
        {
            proxypolicy->policy = ASN1_OCTET_STRING_new();
        }
        
        ASN1_OCTET_STRING_set(proxypolicy->policy, copy, length);

    }
    else
    {
        if(proxypolicy->policy)
        {
            ASN1_OCTET_STRING_free(proxypolicy->policy);
        }
    }

    return 1;
}
/* @} */


/**
 * @name Get the Policy Field
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *
 * Gets the policy of a PROXYPOLICY
 *
 * @param policy the PROXYPOLICY to get the policy of
 * @param length the length of the returned policy - this value
 *        gets set by this function
 *
 * @return the policy
 */
unsigned char * PROXYPOLICY_get_policy(
    PROXYPOLICY *                       policy,
    int *                               length)
{
    if(policy->policy)
    { 
        (*length) = policy->policy->length;
        if(*length > 0 && policy->policy->data)
        {
            unsigned char *                 copy = malloc(*length);
            memcpy(copy, policy->policy->data, *length);
            return copy;
        }
    }
    
    return NULL;
}
/* @} */


/**
 * @name Convert from Internal to DER encoded form
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *
 * Converts a PROXYPOLICY from its internal structure
 * to a DER encoded form
 *
 * @param a the PROXYPOLICY to convert
 * @param pp the buffer to put the DER encoding in
 *
 * @return the length of the DER encoding in bytes
 */
int i2d_PROXYPOLICY(
    PROXYPOLICY *                       a,
    unsigned char **                    pp)
{
    M_ASN1_I2D_vars(a);

    M_ASN1_I2D_len(a->policy_language, i2d_ASN1_OBJECT);

    if(a->policy)
    { 
        M_ASN1_I2D_len(a->policy, i2d_ASN1_OCTET_STRING);
    }
    
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_put(a->policy_language, i2d_ASN1_OBJECT);
    if(a->policy)
    { 
        M_ASN1_I2D_put(a->policy, i2d_ASN1_OCTET_STRING);
    }
    M_ASN1_I2D_finish();
}
/* @} */


/**
 * @name Convert from DER encoded form to Internal
 */
/* @{ */
/**
 * @ingroup proxypolicy
 *
 * Converts the PROXYPOLICY from its DER encoded form
 * to an internal PROXYPOLICY structure
 *
 * @param a the PROXYPOLICY struct to set
 * @param pp the DER encoding to get the PROXYPOLICY from
 * @param length the length of the DER encoding
 * 
 * @return the resulting PROXYPOLICY in its internal structure
 * form - this variable has been allocated using _new routines, 
 * so it needs to be freed once its no longer used
 */
PROXYPOLICY * d2i_PROXYPOLICY(
    PROXYPOLICY **                      a,
    unsigned char **                    pp,
    long                                length)
{
    M_ASN1_D2I_vars(a, PROXYPOLICY *, PROXYPOLICY_new);
    
    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();
    M_ASN1_D2I_get(ret->policy_language, d2i_ASN1_OBJECT);

    /* need to try getting the policy using
     *     a) a call expecting no tags
     *     b) a call expecting tags
     * one of which should succeed
     */
    
    M_ASN1_D2I_get_opt(ret->policy,
                       d2i_ASN1_OCTET_STRING,
                       V_ASN1_OCTET_STRING);
    
    M_ASN1_D2I_get_IMP_opt(ret->policy,
                           d2i_ASN1_OCTET_STRING,
                           0,
                           V_ASN1_OCTET_STRING);

    M_ASN1_D2I_Finish(a, 
                      PROXYPOLICY_free, 
                      ASN1_F_D2I_PROXYPOLICY);
}
/* @} */


X509V3_EXT_METHOD * PROXYPOLICY_x509v3_ext_meth()
{
    static X509V3_EXT_METHOD proxypolicy_x509v3_ext_meth =
    {
        -1,
        X509V3_EXT_MULTILINE,
        NULL,
        (X509V3_EXT_NEW) PROXYPOLICY_new,
        (X509V3_EXT_FREE) PROXYPOLICY_free,
        (X509V3_EXT_D2I) d2i_PROXYPOLICY,
        (X509V3_EXT_I2D) i2d_PROXYPOLICY,
        NULL, NULL,
        (X509V3_EXT_I2V) i2v_PROXYPOLICY,
        NULL,
        NULL, NULL,
        NULL
    };
    return (&proxypolicy_x509v3_ext_meth);
}

STACK_OF(CONF_VALUE) * i2v_PROXYPOLICY(
    struct v3_ext_method *              method,
    PROXYPOLICY *                       ext,
    STACK_OF(CONF_VALUE) *              extlist)
{
    char *                              policy = NULL;
    char                                policy_lang[128];
    char *                              tmp_string = NULL;
    char *                              index = NULL;
    int                                 nid;
    int                                 policy_length;

    X509V3_add_value("Proxy Policy:", NULL, &extlist);

    nid = OBJ_obj2nid(PROXYPOLICY_get_policy_language(ext));

    if(nid != NID_undef)
    {
        BIO_snprintf(policy_lang, 128, " %s", OBJ_nid2ln(nid));
    }
    else
    {
        policy_lang[0] = ' ';
        i2t_ASN1_OBJECT(&policy_lang[1],
                        127,
                        PROXYPOLICY_get_policy_language(ext));
    }
    
    X509V3_add_value("    Policy Language", 
                     policy_lang,
                     &extlist);
    
    policy = PROXYPOLICY_get_policy(ext, &policy_length);
    
    if(!policy)
    {
        X509V3_add_value("    Policy", " EMPTY", &extlist);
    }
    else
    {
        X509V3_add_value("    Policy:", NULL, &extlist);

        tmp_string = policy;
        while(1)
        {
            index = strchr(tmp_string, '\n');
            if(!index)
            {
                int                     length;
                unsigned char *         last_string;
                length = (policy_length - (tmp_string - policy)) + 9;
                last_string = malloc(length);
                BIO_snprintf(last_string, length, "%8s%s", "", tmp_string);
                X509V3_add_value(NULL, last_string, &extlist);
                free(last_string);
                break;
            }
            
            *index = '\0';
            
            X509V3_add_value(NULL, tmp_string, &extlist);
            
            tmp_string = index + 1;
        }
        
        free(policy);
    }
    
    return extlist;
}
