/**********************************************************************

compare_name.c:
Description:
        GSSAPI routine to compare names
        See: <draft-ietf-cat-gssv2-cbind-04.txt>

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <ctype.h>
#include <string.h>

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/**********************************************************************
Function:   my_memccmp

Description:
    Compare two bytes arrays with case insensitive 

Parameters:
        two strings and a length

Returns:
        0 if equal
        not 0 if not equal  
        
**********************************************************************/

static int
my_memccmp(unsigned char *              s1, 
           unsigned char *              s2,
           unsigned int                 n)
{
    unsigned int                        i;
    unsigned char *                     c1;
    unsigned char *                     c2;
    
    c1 = s1;
    c2 = s2;
    i = 0;
    while (i<n)
    {
        if (toupper(*c1) != toupper(*c2))
        {
            return 1;
        }
        c1++;
        c2++;
        i++;
    }
    return 0;
}

/**********************************************************************
Function:   gss_compare_name

Description:
        Compare two names. GSSAPI names in this implementation
        are pointers to x509 names. 

Parameters:

Returns:
**********************************************************************/

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
    int                                 i;
    int                                 j;
    const gss_name_desc*                name1 = (gss_name_desc*) name1_P;
    const gss_name_desc*                name2 = (gss_name_desc*) name2_P;
    
    *minor_status = 0;
    *name_equal = 0; /* set not equal */

    if ((name1 == NULL && name2 == NULL) ||
        (name1 == GSS_C_NO_NAME && name2 == GSS_C_NO_NAME))
    {
        *name_equal = 1;
        return GSS_S_COMPLETE;
    }
    
    if (name1 == NULL || name2 == NULL ||
        (name1 == GSS_C_NO_NAME || name2 == GSS_C_NO_NAME))
    {
        *name_equal = 0;
        return GSS_S_COMPLETE;
    }
    
    if(name1->x509n == NULL && name2->x509n == NULL &&
       g_OID_equal(name1->name_oid,GSS_C_NT_ANONYMOUS) &&
       g_OID_equal(name2->name_oid,GSS_C_NT_ANONYMOUS))
    {
        *name_equal = 1;
        return GSS_S_COMPLETE;
    }
        
    if (name1->x509n == NULL || name2->x509n == NULL)
    {
        *name_equal = 0;
        return GSS_S_COMPLETE;
    }
#ifdef DEBUG
    {
        char *s;

        fprintf(stderr,"Comparing names:\n");
        s = X509_NAME_oneline(name1->x509n,NULL,0);
        fprintf(stderr,"%s\n",s);
        free(s);
        s = X509_NAME_oneline(name2->x509n,NULL,0);
        fprintf(stderr,"%s\n",s);
        free(s);
    }
#endif
        
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
#ifdef DEBUG
        fprintf(stderr,"Comparing GSS_C_NT_HOSTBASED_SERVICE names\n");
#endif
        ne1 = NULL;
        ne2 = NULL;
        j = OBJ_txt2nid("CN");
        for (i=0;i<sk_X509_NAME_ENTRY_num(name1->x509n->entries); i++)
        {
            ne1 = sk_X509_NAME_ENTRY_value(name1->x509n->entries,i);
            if (OBJ_obj2nid(ne1->object) == j)
            {
                le1 = ne1->value->length;
                ce1 = ne1->value->data;
                if ( le1 > 5 && !my_memccmp(ce1,(unsigned char*)"host/",5))
                {
                    le1 -= 5;
                    ce1 += 5;
                }
                else if ( le1 > 4 && !my_memccmp(ce1,(unsigned char*)"ftp/",4))
                {
                    le1 -= 4;
                    ce1 += 4;
                }
                break;
            }
            ne1 = NULL;
        }
        for (i=0;i<sk_X509_NAME_ENTRY_num(name2->x509n->entries); i++)
        {
            ne2 = sk_X509_NAME_ENTRY_value(name2->x509n->entries,i);
            if (OBJ_obj2nid(ne2->object) == j)
            {
                le2 = ne2->value->length;
                ce2 = ne2->value->data;
                if ( le2 > 5 && !my_memccmp(ce2,(unsigned char*)"host/",5))
                {
                    le2 -= 5;
                    ce2 += 5;
                } 
                else if ( le2 > 4 && !my_memccmp(ce2,(unsigned char*)"ftp/",4))
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
            if (le1 == le2 && !my_memccmp(ce1,ce2,le1))
            {
                *name_equal = 1;
            }
            else
            {
                while (le1 > 0 && le2 > 0 && 
                       toupper(*ce1) == toupper(*ce2))
                {
                    le1--;
                    le2--;
                    ce1++;
                    ce2++;
                }
                if (le1 >0 && le2 > 0)
                {
                    if ( *ce1 == '.' && *ce2 == '-' )
                    {
                        while( le2 > 0  && *ce2 != '.')
                        {
                            le2--;
                            ce2++;
                        }
                        if (le1 == le2 && !my_memccmp(ce1,ce2,le1))
                        {
                            *name_equal = 1;
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
                            if (le1 == le2 && !my_memccmp(ce1,ce2,le1))
                            {
                                *name_equal = 1;
                            }
                        }
                    }
                }
            }
        }
        
    }
    else
    {    
        if (!X509_NAME_cmp(name1->x509n, name2->x509n))
        {
            *name_equal = 1 ;
        }
    }
#ifdef DEBUG
    fprintf(stderr,"Compared %d \n", *name_equal);
#endif

    return GSS_S_COMPLETE ;

} /* gss_compare_name */
