
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

/**
 * Import a credential that was exported by gss_export_cred().
 *
 * This function will import credentials exported by
 * gss_export_cred(). It is intended to allow a multiple use
 * application to checkpoint delegated credentials.  
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param output_cred_handle
 *        Upon success, this paramter will contain the imported
 *        credential. When no longer needed this credential should be
 *        freed using gss_release_cred().
 * @param desired_mech
 *        This paramter may be used to specify the desired security
 *        mechanism. May be GSS_C_NO_OID.
 * @param option_req
 *        This paramater indicates which option_req value was used to
 *        produce the import_buffer.
 * @param import_buffer
 *        A buffer produced by gss_export_credential().
 * @param time_req
 *        The requested period of validity (seconds) for the imported
 *        credential. May be NULL.
 * @param time_rec
 *        This parameter will contain the received period of validity
 *        of the imported credential upon success. May be NULL.
 * @return
 *        GSS_S_COMPLETE         upon successful completion
 *        GSS_S_BAD_MECH         if the requested security mechanism
 *                               is unavailable
 *        GSS_S_DEFECTIVE_TOKEN  if the import_buffer is defective
 *        GSS_S_FAILURE          upon general failure
 */

OM_uint32 
GSS_CALLCONV gss_import_cred(
    OM_uint32 *                         minor_status,
    gss_cred_id_t *                     output_cred_handle,
    const gss_OID                       desired_mech,
    OM_uint32                           option_req,
    const gss_buffer_t                  import_buffer,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec)
{
    OM_uint32                           major_status = 0;
    BIO *                               bp = NULL;
    char *                              filename;
    FILE *                              fp;
    
#ifdef DEBUG
    fprintf(stderr,"import_cred:\n");
#endif /* DEBUG */

    /* module activation if not already done by calling
     * globus_module_activate
     */
    
    globus_thread_once(
        &once_control,
        (void (*)(void))globus_i_gsi_gssapi_module.activation_func);

    *minor_status = 0;

    if (import_buffer == NULL ||
        import_buffer ==  GSS_C_NO_BUFFER ||
        import_buffer->length < 1) 
    {
        GSSerr(GSSERR_F_IMPORT_CRED,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if (output_cred_handle == NULL )
    { 
        GSSerr(GSSERR_F_IMPORT_CRED,GSSERR_R_BAD_ARGUMENT);
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
    
    if (import_buffer->length > 0)
    {
        if(option_req == 0)
        {
            bp = BIO_new(BIO_s_mem());
            
            BIO_write(bp,
                      import_buffer->value,
                      import_buffer->length);
        }
        else if(option_req == 1) 
        {
            filename = strchr((char *) import_buffer->value, '=');
            filename++;
            
            if ((fp = fopen(filename,"r")) == NULL)
            {
                /* right error? */
                major_status = GSS_S_DEFECTIVE_TOKEN;
                goto err;
            }
            
            bp = BIO_new(BIO_s_file());
            
            BIO_set_fp(bp,fp,BIO_NOCLOSE);
        }
        else
        {
            GSSerr(GSSERR_F_IMPORT_CRED,GSSERR_R_BAD_ARGUMENT);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_FAILURE;
            goto err;
        }
    }
    else
    {
        major_status = GSS_S_DEFECTIVE_TOKEN;
        goto err;
    }
    
    major_status = gss_create_and_fill_cred(output_cred_handle,
                                            GSS_C_BOTH,
                                            NULL,
                                            NULL,
                                            NULL,
                                            bp);

    if(major_status != GSS_S_COMPLETE)
    {
        goto err;
    }
    
    /* If I understand this right, time_rec should contain the time
     * until the cert expires */
    
    if (time_rec != NULL)
    {
        time_t                time_after;
        time_t                time_now;
        ASN1_UTCTIME *        asn1_time = NULL;

        asn1_time = ASN1_UTCTIME_new();
        X509_gmtime_adj(asn1_time,0);
        time_now = ASN1_UTCTIME_mktime(asn1_time);
        time_after = ASN1_UTCTIME_mktime(
            X509_get_notAfter(
                ((gss_cred_id_desc *) *output_cred_handle)->pcd->ucert));
        *time_rec = (OM_uint32) time_after - time_now;
        ASN1_UTCTIME_free(asn1_time);
    }
        
err:
    if (bp) 
    {
        BIO_free(bp);
    }
    return major_status;
}


