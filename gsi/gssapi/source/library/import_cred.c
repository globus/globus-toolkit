
/**********************************************************************

import_cred.c:

Description:
	GSSAPI routine to import a credential that was
	exported by gss_export_cred.
	This is an experimental routine which is not 
	defined in the GSSAPI RFCs. 

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
#include <string.h>

/* Only build if we have experimential GSSAPI extensions */
/* See gssapi.hin for details */
#ifdef  _HAVE_GSI_EXTENDED_GSSAPI

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
Function:   gss_import_cred()   

Description:
    Import a credential that was exported by gss_export_cred.
	This is intended to allow a multiple use application 
	to checkpoint delegated credentials. 

Parameters:

Returns:
**********************************************************************/


OM_uint32 
GSS_CALLCONV gss_import_cred
(OM_uint32 *                       minor_status,
 const gss_buffer_t                input_token,
 OM_uint32                         time_req,
 const gss_OID_set                 desired_mechs,
 gss_cred_usage_t                  cred_usage,
 gss_cred_id_t *                   cred_handle_P,
 gss_OID_set *                     actual_mechs,
 OM_uint32 *                       time_rec
) 
{
	OM_uint32 major_status = 0;
	BIO * bp = NULL;
	FILE * fp = NULL;
	X509 * ucert = NULL;
	EVP_PKEY * upkey = NULL;
	STACK_OF(X509) * certchain = NULL;
	char * cp;

#ifdef DEBUG
	fprintf(stderr,"import_cred:\n");
#endif /* DEBUG */

    /*
     * We are going to use the SSL error routines, get them
     * initilized early. They may be called more then once.
     */

    ERR_load_gsserr_strings(0);  /* load our gss ones as well */

	*minor_status = 0;

	if (actual_mechs != NULL) {
		major_status = gss_indicate_mechs(minor_status,
						actual_mechs);
		if (major_status != GSS_S_COMPLETE) {
			goto err;
		}
	}

	if (time_rec != NULL) {
		*time_rec = GSS_C_INDEFINITE ;
	}

	if (input_token == NULL ||
			input_token ==  GSS_C_NO_BUFFER ||
			input_token->length < 1) {
		GSSerr(GSSERR_F_IMPORT_CRED,GSSERR_R_IMPEXP_BAD_PARMS);
		*minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
		major_status = GSS_S_FAILURE;
		goto err;
	}

	if (cred_handle_P == NULL ) { 
		 GSSerr(GSSERR_F_IMPORT_CRED,GSSERR_R_IMPEXP_BAD_PARMS);
		*minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
		major_status = GSS_S_FAILURE;
		goto err;
	}
	
	bp = BIO_new(BIO_s_mem());

   	if (input_token->length > 0) {
		BIO_write(bp,
			input_token->value,
			input_token->length);
	} else {
		major_status = GSS_S_DEFECTIVE_TOKEN;
		goto err;
	}
	major_status = gss_create_and_fill_cred(minor_status,
		cred_handle_P,
		cred_usage,
		NULL, NULL, NULL, bp);
	
err:
	if (bp) {
		BIO_free(bp);
	}
	if (fp) {
		fclose(fp);
	}
	return major_status;
}
#endif /*  _HAVE_GSI_EXTENDED_GSSAPI */
