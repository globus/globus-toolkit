
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
#include <string.h>

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
GSS_CALLCONV gss_export_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    gss_buffer_t                        export_buffer)
{
    OM_uint32                           major_status = 0;
    BIO *                               bp = NULL;
    gss_cred_id_desc *                  cred_desc;

    cred_desc = (gss_cred_id_desc *) cred_handle;
    

#ifdef DEBUG
    fprintf(stderr,"export_cred: \n");
#endif /* DEBUG */

    *minor_status = 0;

    if (export_buffer == NULL ||
        export_buffer ==  GSS_C_NO_BUFFER)
    {
        GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    export_buffer->length = 0;
    export_buffer->value = NULL;

    if (cred_handle == NULL )
    { 
        GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(desired_mech != NULL &&
       desired_mech != (gss_OID) gss_mech_globus_gssapi_ssleay)
    {
        GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_BAD_MECH);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_BAD_MECH;
        goto err;
    }

    if(option_req == 0)
    {
	
        bp = BIO_new(BIO_s_mem());
	
        if (proxy_marshal_bp(bp,
                             cred_desc->pcd->ucert,	
                             cred_desc->pcd->upkey,
                             NULL,
                             cred_desc->pcd->cert_chain))
        {
            GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_EXPORT_FAIL);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_FAILURE;
            goto err;
        }
		
        export_buffer->length = BIO_pending(bp);
		
        if (export_buffer->length > 0)
        {
            export_buffer->value = (char *) malloc(export_buffer->length);
            if (export_buffer->value == NULL)
            {
                export_buffer->length = 0 ;
                *minor_status = gsi_generate_minor_status();
                GSSerr(GSSERR_F_EXPORT_CRED, GSSERR_R_OUT_OF_MEMORY);
                return GSS_S_FAILURE;
            }
			
            BIO_read(bp,
                     export_buffer->value,
                     export_buffer->length);
        }
        else
        {
            export_buffer->value = NULL;
        }

        major_status = GSS_S_COMPLETE;
    }
    else if(option_req == 1)
    {
        if (proxy_marshal_tmp(cred_desc->pcd->ucert,	
                              cred_desc->pcd->upkey,
                              NULL,
                              cred_desc->pcd->cert_chain,
                              &(export_buffer->value)))
        {
            GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_EXPORT_FAIL);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_FAILURE;
            goto err;
        }
        export_buffer->length = strlen(export_buffer->value);
    }
    else
    {
        GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

err:
    if (bp) 
    {
        BIO_free(bp);
    }
    return major_status;
}
#endif /*  _HAVE_GSI_EXTENDED_GSSAPI */
