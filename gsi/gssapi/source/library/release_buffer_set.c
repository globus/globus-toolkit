/**********************************************************************

release_buffer_set.c:

Description:
    GSSAPI routine to release the contents of a buffer set

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
Function:  gss_release_buffer_set

Description:
	Release the contents of a buffer set

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_release_buffer_set(
    OM_uint32 *                         minor_status,
    gss_buffer_set_t                    buffer_set)
{
    int                                 i;
    
    *minor_status = 0;
        
    if (buffer_set == NULL ||
        buffer_set == GSS_C_NO_BUFFER_SET)
    {
        return GSS_S_COMPLETE ;
    }

    for(i=0;i<buffer_set->count;i++)
    {
        gss_release_buffer(minor_status,
                           &buffer_set->elements[i]);
    }

    free(buffer_set->elements);

    memset(buffer_set,0,sizeof(buffer_set));
    
    return GSS_S_COMPLETE ;

} /* gss_release_buffer_set */

