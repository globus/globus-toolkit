/*********************************************************************

export_name.c:

Description:
    GSSAPI routine to take an internal name and convert to a form
	which can be used by caller. We do this using the SSLeay 
	x509 oneline routine. which returns /X=y/X=y... form. 

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

#include "gssapi.h"
#include "gssutils.h"
#include "gssapi_ssleay.h"
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
Function:   gss_export_name

Description:
	oProduces a single line version of the internal x509 name
Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_export_name
(OM_uint32 *          minor_status,
 const gss_name_t     input_name_P,
 gss_buffer_t         exported_name
)
{
	const gss_name_desc* input_name = 
		(gss_name_desc*) input_name_P ;

	*minor_status = 0;
	if (!(input_name) || !(input_name->x509n) ||
			!(exported_name)) {
            GSSerr(GSSERR_F_EXPORT_CRED, GSSERR_R_BAD_ARGUMENT);
            *minor_status = gsi_generate_minor_status();
            return GSS_S_FAILURE;
	}

	exported_name->value = X509_NAME_oneline(input_name->x509n,NULL,0);
	exported_name->length = strlen(exported_name->value);
  
	return GSS_S_COMPLETE ;

} /* gss_export_name */
