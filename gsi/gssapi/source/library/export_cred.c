
/**********************************************************************

export_cred.c:

Description:
	GSSAPI routine to export a credential
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

/* Only build if we have the extended GSSAPI */
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
Function:   gss_export_cred()   

Description:
    Saves the credential so it can be checkpointed and 
	imported by gss_import_cred

Parameters:
Returns:
**********************************************************************/


OM_uint32 
GSS_CALLCONV gss_export_cred
(OM_uint32 *                       minor_status,
 gss_cred_id_t                     cred_handle_P,
 const gss_OID_set                 desired_mechs,
 gss_cred_usage_t                  cred_usage,
 gss_buffer_t                      output_token
) 
{
	OM_uint32 major_status = 0;
	gss_cred_id_desc * cred_handle = (gss_cred_id_desc *)cred_handle_P;
	BIO * bp = NULL;
	int rc;

#ifdef DEBUG
	fprintf(stderr,"export_cred: \n");
#endif /* DEBUG */

	*minor_status = 0;

	if (output_token == NULL ||
			output_token ==  GSS_C_NO_BUFFER) {
		GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_IMPEXP_BAD_PARMS);
		*minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
		major_status = GSS_S_FAILURE;
		goto err;
	}

	output_token->length = 0;
	output_token->value = NULL;

	if (cred_handle == NULL ) { 
		 GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_IMPEXP_BAD_PARMS);
		*minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
		major_status = GSS_S_FAILURE;
		goto err;
	}

	bp = BIO_new(BIO_s_mem());
	if (rc = proxy_marshal_bp(bp,
				cred_handle->pcd->ucert,	
				cred_handle->pcd->upkey,
				NULL,
			cred_handle->pcd->cert_chain)) {
		GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_EXPORT_FAIL);
		*minor_status = GSSERR_R_EXPORT_FAIL;
		major_status = GSS_S_FAILURE;
		goto err;
	}
		
	output_token->length = BIO_pending(bp);
	if (output_token->length > 0) {
		output_token->value = (char *) malloc(output_token->length);
		if (output_token->value == NULL) {
			output_token->length = 0 ;
			GSSerr(GSSERR_F_EXPORT_CRED, ERR_R_MALLOC_FAILURE);
			return GSS_S_FAILURE;
		}
		BIO_read(bp,
		output_token->value,
		output_token->length);
	} else {
		output_token->value = NULL;
	}
	major_status = GSS_S_COMPLETE;

err:
	if (bp) {
		BIO_free(bp);
	}
	return major_status;
}
#endif /*  _HAVE_GSI_EXTENDED_GSSAPI */
