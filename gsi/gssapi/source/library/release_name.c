/**********************************************************************

release_name.c:

Description:
    GSSAPI routine to release a name
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
Function:   gss_release_name()

Description:
        Release the gssapi name structure

Parameters:
   
Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_release_name(
    OM_uint32 *                         minor_status,
    gss_name_t *                        name_P)
{
    gss_name_desc** name = (gss_name_desc**) name_P ;
    
    *minor_status = 0;

    if (name == NULL || *name == NULL || *name == GSS_C_NO_NAME)
    {
        return GSS_S_COMPLETE ;
    } 
    
    if ((*name)->x509n)
    {
        X509_NAME_free((*name)->x509n);
    }

    if((*name)->group)
    {
        sk_pop_free((*name)->group,free);
    }

    if((*name)->group_types)
    {
        ASN1_BIT_STRING_free((*name)->group_types); 
    }
    
    free(*name) ;
    *name = GSS_C_NO_NAME ;
    
    return GSS_S_COMPLETE ;
    
} /* gss_release_name */
