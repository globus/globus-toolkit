/**********************************************************************

release_buffer.c:

Description:
    GSSAPI routine to release the contents of a buffer
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
Function:  gss_release_buffer

Description:
	Release the contents of a buffer

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_release_buffer
(OM_uint32 *          minor_status,
 gss_buffer_t         buffer
)
{

	*minor_status = 0;
	if (buffer == NULL || buffer == GSS_C_NO_BUFFER) {
		return GSS_S_COMPLETE ;
	}

	if (buffer->value && buffer->length) {
		free(buffer->value);
	}

	buffer->length = (size_t) 0 ;
	buffer->value = NULL;

	return GSS_S_COMPLETE ;

} /* gss_release_buffer */

