
/**********************************************************************

inquire_cred.c:

Description:
        GSSAPI routine to inquire about the local credential
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

#include "gssapi.h"
#include "gssapi_ssleay.h"
#include "gssutils.h"

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
Function:   gss_inquire_cred()

Description:
        Get information about the current credential

        We will also allow the return of the proxy file name,
        if the minor_status is set to a value of 57056 0xdee0
        This is done since there is no way to pass back the delegated
        credential file name. 

        When 57056 is seen, this will cause a new copy of this
        credential to be written, and it is the user's responsibility
        to free the file when done. 
        The name will be a pointer to a char * of the file name
        which must be freeed. The minor_status will be set to 
        57057 0xdee1 to indicate this. 
        
        DEE - this is a kludge, till the GSSAPI get a better way 
        to return the name. 

        If the minor status is not changed from 57056 to 57057
        assume it is not this gssapi, and a gss name was returned. 

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_inquire_cred(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle_P,
    gss_name_t *                        name,
    OM_uint32 *                         lifetime,
    gss_cred_usage_t *                  cred_usage,
    gss_OID_set *                       mechanisms) 
{
    OM_uint32                           major_status = 0;
    gss_cred_id_desc *                  cred_handle =
        (gss_cred_id_desc *)cred_handle_P;
    char *                              filename = NULL;
    int                                 rc;

#ifdef DEBUG
    fprintf(stderr,"inquire_cred:\n");
#endif /* DEBUG */

    if (cred_handle == GSS_C_NO_CREDENTIAL)
    {
        major_status = GSS_S_NO_CRED;
    }
    else
    {
        if (mechanisms != NULL)
        {
            *mechanisms = GSS_C_NO_OID_SET;
        }

        if (cred_usage != NULL)
        {
            *cred_usage = cred_handle->cred_usage;
        }


        if (lifetime != NULL)
        {
            time_t                time_after;
            time_t                time_now;
            ASN1_UTCTIME *        asn1_time = NULL;
            
            asn1_time = ASN1_UTCTIME_new();
            X509_gmtime_adj(asn1_time,0);
            time_now = ASN1_UTCTIME_mktime(asn1_time);
            time_after = ASN1_UTCTIME_mktime(
                X509_get_notAfter(cred_handle->pcd->ucert));
            *lifetime = (OM_uint32) time_after - time_now;
            ASN1_UTCTIME_free(asn1_time);
        }

        if (name != NULL)
        {
            if (*minor_status == 0xdee0)
            {
                *minor_status = 0;
                rc = proxy_marshal_tmp(cred_handle->pcd->ucert,
                                       cred_handle->pcd->upkey,
                                       NULL,
                                       cred_handle->pcd->cert_chain,
                                       &filename);
                if (rc)
                {
                    major_status = GSS_S_FAILURE;
                    *minor_status = gsi_generate_minor_status();
                    if (filename)
                    {
                        free(filename);
                    }
                }
                else
                {
                    *name = filename;
                    *minor_status = 0xdee1;
                    /* DEE passback the char string */
                    /* non standard, but then there is no standard */
                }
            }
            else
            {
                major_status =
                    gss_copy_name_to_name((gss_name_desc **)name,
                                          cred_handle->globusid);

                if (GSS_ERROR(major_status))
                {
                    *minor_status = gsi_generate_minor_status();
                }
            }
        }
    }
    
err:
    return major_status;
}
