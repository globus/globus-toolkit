#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file export_cred.c
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <string.h>

/* Only build if we have the extended GSSAPI */
#ifdef  _HAVE_GSI_EXTENDED_GSSAPI

/**
 * @name Export Cred
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Saves the credential so it can be checkpointed and 
 * imported by gss_import_cred
 *
 * @param minor_status
 * @param cred_handle
 * @param desired_mech
 *        Should either be @ref gss_mech_globus_gssapi_openssl or
 *        NULL (in which case gss_mech_globus_gssapi_openssl is
 *        assumed).
 * @param option_req
 * @param export_buffer
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_export_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    gss_buffer_t                        export_buffer)
{
    OM_uint32                           major_status = GLOBUS_SUCCESS;
    BIO *                               bp = NULL;
    gss_cred_id_desc *                  cred_desc;

    static char *                       _function_name_ =
        "gss_export_cred";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    cred_desc = (gss_cred_id_desc *) cred_handle;
    
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if (export_buffer == NULL ||
        export_buffer == GSS_C_NO_BUFFER)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("NULL or emtpy export_buffer parameter passed to function: %s",
             _function_name_));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    export_buffer->length = 0;
    export_buffer->value = NULL;

    if (cred_handle == NULL)
    { 
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("NULL or emtpy export_buffer parameter passed to function: %s",
             _function_name_));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if(desired_mech != NULL &&
       g_OID_equal(desired_mech, (gss_OID) gss_mech_globus_gssapi_openssl))
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH,
            ("The desired mechanism for exporting this credential is not
        GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_BAD_MECH);
        major_status = GSS_S_BAD_MECH;
        goto err;
    }

    if(option_req == 0)
    {
        bp = BIO_new(BIO_s_mem());
	
        if((result = globus_gsi_cred_write(cred_desc->cred_handle,
                                 bp)) != GLOBUS_SUCCESS)
        {
#error add error
        }            
		
        export_buffer->length = BIO_pending(bp);
		
        if (export_buffer->length > 0)
        {
            export_buffer->value = (char *) malloc(export_buffer->length);
            if (export_buffer->value == NULL)
            {
                export_buffer->length = 0;
#error do error here
                GSSerr(GSSERR_F_EXPORT_CRED, GSSERR_R_OUT_OF_MEMORY);
                goto err;
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
        if((result = 
            GLOBUS_GSI_CRED_GET_UNIQUE_PROXY_FILENAME(& proxy_filename))
           != GLOBUS_SUCCESS)
        {
#error error
        }

        if((result = globus_gsi_cred_write_proxy(cred_desc->cred_handle,
                                                 proxy_filename)) 
           != GLOBUS_SUCCESS)
        {
#error error
        }                                       

        export_buffer->length = strlen(X509_USER_PROXY) +
            strlen(filename) + 2;
        if((export_buffer->value = malloc(export_buffer->length)) == NULL)
        {
#error use errno here
        }

        snprintf(export_buffer->value, export_buffer->length, "%s=%s",
                 X509_USER_PROXY, proxy_filename);
    }
    else
    {
#error do error
        GSSerr(GSSERR_F_EXPORT_CRED,GSSERR_R_BAD_ARGUMENT);
        major_status = GSS_S_FAILURE;
        goto err;
    }

err:
    if (bp) 
    {
        BIO_free(bp);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
#endif /*  _HAVE_GSI_EXTENDED_GSSAPI */
