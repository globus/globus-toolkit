#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file compare_name.c
 * Globus GSI GSS-API gss_compare_name
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

#include <ctype.h>
#include <string.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @name Local Compare Group
 * @ingroup globus_l_gsi_gssapi
 */
/**
 * Compare the proxy group information in two gss_name_t structures.
 *
 * This function compares the group information contained in two GSS
 * names. The function returns a favorable result if one of the
 * following conditions are met:
 *  - Neither of the names carry any group information.
 *  - One of the names contains group information and none of the
 *    subgroups are untrusted.
 *  - Both names carry group information and subgroups are identical
 *    up to min(number of subgroups in name one, number of subgroups
 *    in name two). Furthermore, all of the remaining "uncompared"
 *    subgroups must be trusted.
 *
 * @param name1
 *        GSS name used in the comparison.
 * @param name2
 *        GSS name used in the comparison.
 *
 * @return
 *       1 if comparison was favorable
 *       0 if it wasn't
 */
static int
gss_l_compare_group(
    const gss_name_desc *               name1,
    const gss_name_desc *               name2)
{
    int                                 index;
    int                                 jindex;
    int                                 result;
    int                                 num_group_elements1;
    int                                 num_group_elements2;

    static char *                       _function_name_ =
        "gss_l_compare_group";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    /* if there are no groups we compare favorably */
    
    if(name1->group == NULL &&
       name1->group_types == NULL &&
       name2->group == NULL &&
       name2->group_types == NULL)
    {
        result = 1;
        goto exit;
    }

    /* if only one cert is in a group we check that it is in a trusted
     * group
     */
    
    if(name1->group != NULL &&
       name1->group_types != NULL &&
       name2->group == NULL &&
       name2->group_types == NULL)
    {
        for(index = 0; index < sk_num(name1->group); index++)
        {
            if(ASN1_BIT_STRING_get_bit(name1->group_types, index))
            {
                result = 0;
                goto exit;
            }
        }
        result = 1;
        goto exit;
    }

    if(name1->group == NULL &&
       name1->group_types == NULL &&
       name2->group != NULL &&
       name2->group_types != NULL)
    {
        for(index = 0; index < sk_num(name2->group); index++)
        {
            if(ASN1_BIT_STRING_get_bit(name2->group_types, index))
            {
                result = 0;
                goto exit;
            }
        }
        result = 1;
        goto exit;
    }

    /* if both certs are in groups we check that the shorter (ie the
     * group with fewest elements) group matches the corresponding
     * part of the other certifcate's group and that the remaining
     * part of the longer group contains only trusted subgroups.
     */
    
    if(name1->group != NULL &&
       name1->group_types != NULL &&
       name2->group != NULL &&
       name2->group_types != NULL)
    {
        num_group_elements1 = sk_num(name1->group);
        num_group_elements2 = sk_num(name2->group);

        if(num_group_elements1 < num_group_elements2)
        {
            jindex = num_group_elements2;
            
            for(index = num_group_elements1 - 1; index >= 0; index--)
            {
                jindex--;
                if(ASN1_BIT_STRING_get_bit(name1->group_types, index) !=
                   ASN1_BIT_STRING_get_bit(name2->group_types, jindex) ||
                   strcmp(sk_value(name1->group, index),
                          sk_value(name2->group, jindex)))
                {
                    result = 0;
                    goto exit;
                }
            }

            for(index = 0; index < num_group_elements2 - num_group_elements1;
                index ++)
            {
                if(ASN1_BIT_STRING_get_bit(name2->group_types, index))
                {
                    result = 0;
                    goto exit;
                }
            }
        }
        else
        {
            jindex = num_group_elements1;
            for(index = num_group_elements2 - 1; index >= 0; index--)
            {
                jindex--;
                if(ASN1_BIT_STRING_get_bit(name1->group_types, jindex) !=
                   ASN1_BIT_STRING_get_bit(name2->group_types, index) ||
                   strcmp(sk_value(name1->group, jindex),
                          sk_value(name2->group, index)))
                {
                    result = 0;
                    goto exit;
                }
            }
            
            for(index = 0; index < num_group_elements1 - num_group_elements2;
                index++)
            {
                if(ASN1_BIT_STRING_get_bit(name1->group_types, index))
                {
                    result = 0;
                    goto exit;
                }
            }
            
        }
        result = 1;
        goto exit;
    }

    result = 0;

 exit:

    GLOBUS_I_GSI_GSSAPI_INTERNAL_DEBUG_EXIT;
    return result;
}
/* @} */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */


/**
 * @name Compare Name
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Compare two names. GSSAPI names in this implementation
 * are pointers to x509 names. 
 *
 * @param minor_status
 *        currently is always set to GLOBUS_SUCCESS
 * @param name1_P
 * @param name2_P
 * @param name_equal
 *
 * @return
 *        currently always returns GSS_S_COMPLETE
 */
OM_uint32 
GSS_CALLCONV gss_compare_name(
    OM_uint32 *                         minor_status,
    const gss_name_t                    name1_P,
    const gss_name_t                    name2_P,
    int *                               name_equal)
{
    X509_NAME_ENTRY *                   ne1;
    X509_NAME_ENTRY *                   ne2;
    unsigned int                        le1;
    unsigned int                        le2;
    unsigned char *                     ce1;
    unsigned char *                     ce2;
    int                                 found_dot = 0;
    int                                 index;
    int                                 common_name_NID;
    const gss_name_desc*                name1 = (gss_name_desc*) name1_P;
    const gss_name_desc*                name2 = (gss_name_desc*) name2_P;
    OM_uint32                           major_status;
    static char *                       _function_name_ =
        "gss_compare_name";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_FAILURE;
    major_status = GSS_S_COMPLETE;
    *name_equal = GSS_NAMES_NOT_EQUAL;

    if ((name1 == NULL && name2 == NULL) ||
        (name1 == GSS_C_NO_NAME && name2 == GSS_C_NO_NAME))
    {
        *name_equal = GSS_NAMES_EQUAL;
        goto exit;
    }
    
    if (name1 == NULL || name2 == NULL ||
        (name1 == GSS_C_NO_NAME || name2 == GSS_C_NO_NAME))
    {
        *name_equal = GSS_NAMES_NOT_EQUAL;
        major_status = GSS_S_COMPLETE;
        goto exit;
    }

    if(name1->x509n == NULL && name2->x509n == NULL &&
       g_OID_equal(name1->name_oid,GSS_C_NT_ANONYMOUS) &&
       g_OID_equal(name2->name_oid,GSS_C_NT_ANONYMOUS))
    {
        *name_equal = GSS_NAMES_EQUAL;
        goto exit;
    }
        
    if (name1->x509n == NULL || name2->x509n == NULL)
    {
        *name_equal = GSS_NAMES_NOT_EQUAL;
        goto exit;
    }

    /* debug block */
    {
        char *                          subject;

        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(2, "Comparing names:\n");
        subject = X509_NAME_oneline(name1->x509n, NULL, 0);
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream, "%s\n", subject));
        globus_libc_free(subject);
        subject = X509_NAME_oneline(name2->x509n, NULL, 0);
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream, "%s\n", subject));
        globus_libc_free(subject);
    }

    /* compare group membership */

    if(!gss_l_compare_group(name1,name2))
    {
        *name_equal = GSS_NAMES_NOT_EQUAL;
        major_status = GSS_S_COMPLETE;
    }
    
    /* 
     * if we are comparing a host based name, we only need to compare
     * the service/FQDN from both
     * It is assumed that the first CN= will have the service/FQDN
     * So find it in each
     * Also if the service is not present, it will be
     * considered to be host, so "host/fqdn" comparies to "fqdn"
     * this allows for certs obtained from other CAs. 
     * Note: import_name takes service@FQDN which gets
     * converted internally to /CN=service/FQDN. 
     *
     * Since DNS names are case insensitive, so is this compare. 
     *
     * Many site use the convention of naming interfaces
     * by having the FQDN in the form host-interface.domain
     * and the client may only know the host-interface.domain
     * name, yet it may receive a target of host.domain
     * So we need host.domain to compare equal to host-interface.domain 
     */

    if (g_OID_equal(name1->name_oid, GSS_C_NT_HOSTBASED_SERVICE)
        || g_OID_equal(name2->name_oid, GSS_C_NT_HOSTBASED_SERVICE))
    {

        GLOBUS_I_GSI_GSSAPI_DEBUG_PRINT(
            2, "Comparing GSS_C_NT_HOSTBASED_SERVICE names\n");

        ne1 = NULL;
        ne2 = NULL;
        common_name_NID = OBJ_txt2nid("CN");
        for (index = 0; index < X509_NAME_entry_count(name1->x509n); index++)
        {
            ne1 = X509_NAME_get_entry(name1->x509n, index);
            if (OBJ_obj2nid(ne1->object) == common_name_NID)
            {
                le1 = ne1->value->length;
                ce1 = ne1->value->data;
                if ( le1 > 5 && !strncasecmp(ce1,(unsigned char*)"host/",5))
                {
                    le1 -= 5;
                    ce1 += 5;
                }
                else if ( le1 > 4 && 
                          !strncasecmp(ce1,(unsigned char*)"ftp/",4))
                {
                    le1 -= 4;
                    ce1 += 4;
                }
                break;
            }
            ne1 = NULL;
        }
        for (index = 0; index < X509_NAME_entry_count(name2->x509n); index++)
        {
            ne2 = X509_NAME_get_entry(name2->x509n, index);
            if (OBJ_obj2nid(ne2->object) == common_name_NID)
            {
                le2 = ne2->value->length;
                ce2 = ne2->value->data;
                if ( le2 > 5 && !strncasecmp(ce2, (unsigned char*)"host/", 5))
                {
                    le2 -= 5;
                    ce2 += 5;
                } 
                else if ( le2 > 4 
                          && !strncasecmp(ce2, (unsigned char*)"ftp/", 4))
                {
                    le2 -= 4;
                    ce2 += 4;
                }
                break;
            }
            ne2 = NULL;
        }

        if (ne1 && ne2)
        {
            if (le1 == le2 && !strncasecmp(ce1,ce2,le1))
            {
                *name_equal = GSS_NAMES_EQUAL;
            }
            else
            {
                while (le1 > 0 && le2 > 0 && 
                       toupper(*ce1) == toupper(*ce2))
                {
                    if(*ce1 == '.')
                    {
                        found_dot = 1;
                    }
                    
                    le1--;
                    le2--;
                    ce1++;
                    ce2++;
                }
                
                if (le1 >0 && le2 > 0 && !found_dot)
                {
                    if ( *ce1 == '.' && *ce2 == '-' )
                    {
                        while( le2 > 0  && *ce2 != '.')
                        {
                            le2--;
                            ce2++;
                        }
                        if (le1 == le2 && !strncasecmp(ce1, ce2, le1))
                        {
                            *name_equal = GSS_NAMES_EQUAL;
                        }
                                                
                    }
                    else
                    {
                        if (*ce2 == '.' && *ce1 == '-')
                        {
                            while(le1 > 0 && *ce1 != '.')
                            { 
                                le1--;
                                ce1++; 
                            }
                            if (le1 == le2 && !strncasecmp(ce1, ce2, le1))
                            {
                                *name_equal = GSS_NAMES_EQUAL;
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
	/* need to compare just the strings, since
	 * an X509_NAME_cmp compares name entries,
	 * and some of the entries may not match
	 * due to extensible NE's (like /Email=...)
	 */
	if(!strcmp(X509_NAME_oneline(name1->x509n, NULL, 0), 
		   X509_NAME_oneline(name2->x509n, NULL, 0)))
        {
            *name_equal = GSS_NAMES_EQUAL;
        }
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        2, (globus_i_gsi_gssapi_debug_fstream, "Compared %d \n", *name_equal));

 exit:
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;

} 
/* gss_compare_name */
/* @} */

