#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file export_name.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi.h"
#include "globus_i_gsi_gss_utils.h"
#include "gssapi_openssl.h"
#include <string.h>

/**
 * @name Export Name
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * Produces a single line version of the internal x509 name
 */
OM_uint32 
GSS_CALLCONV gss_export_name(
    OM_uint32 *                         minor_status,
    const gss_name_t                    input_name_P,
    gss_buffer_t                        exported_name)
{
    const gss_name_desc *               input_name = 
		                        (gss_name_desc *) input_name_P;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    static char *                       _function_name_ = 
        "gss_export_name";
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;
    if (!(input_name) || !(input_name->x509n) || !(exported_name)) {
        
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("The input name passed to: %s is not valid", _function_name_));
        goto exit;
    }

    /* ToDo: Memory returned by X509_NAME_oneline() must be freed using
             OPENSSL_free() not free() and caller won't know that. So
             an new string should be malloc'd and that one returned
             instead so the SSL one can be freed here.              */
    exported_name->value = X509_NAME_oneline(input_name->x509n, NULL, 0);
    if(exported_name->value == NULL)
    {
        GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
            ("Couldn't get the subject name of the gss_name_t"));
        major_status = GSS_S_FAILURE;
        goto exit;
    }
        
    exported_name->length = strlen(exported_name->value);
    
 exit:

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* gss_export_name */
/* @} */
