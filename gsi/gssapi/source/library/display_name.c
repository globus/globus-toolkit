/*********************************************************************

display_name.c:

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

#define GSS_I_ANON_NAME "<anonymous>"

/**********************************************************************
Function:   gss_display_name

Description:
	Produces a single line version of the internal x509 name

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_display_name
(OM_uint32 *          minor_status,
 const gss_name_t     input_name_P,
 gss_buffer_t         output_name,
 gss_OID *            output_name_type
)
{
	const gss_name_desc* input_name = 
		(gss_name_desc*) input_name_P ;

	*minor_status = 0;
	if (!(input_name) ||
            (!(input_name->x509n) &&
             !g_OID_equal(input_name->name_oid,
                          GSS_C_NT_ANONYMOUS)) ||
            !(output_name)) {
            *minor_status = gsi_generate_minor_status();
            return GSS_S_FAILURE;
	}

        if(!g_OID_equal(input_name->name_oid,GSS_C_NT_ANONYMOUS))
        {
            output_name->value = X509_NAME_oneline(input_name->x509n,NULL,0);
            output_name->length = strlen(output_name->value);
        }
        else
        {
            output_name->value = (void *) strdup(GSS_I_ANON_NAME);
            output_name->length = strlen(GSS_I_ANON_NAME);
        }
  
	if (output_name_type)
        {
            *output_name_type = input_name->name_oid;
        }
	return GSS_S_COMPLETE ;

} /* gss_export_name */
