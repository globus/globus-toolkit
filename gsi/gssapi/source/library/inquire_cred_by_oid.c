/**********************************************************************

inquire_cred_by_oid.c:

Description:
    GSSAPI routine to extract information from a credential.

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/


static char *rcsid = "$Header$";

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <string.h>

OM_uint32
GSS_CALLCONV gss_inquire_cred_by_oid(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_object,
    gss_buffer_set_t *                  data_set)
{
    OM_uint32                           major_status;
    OM_uint32                           tmp_minor_status;
    gss_cred_id_desc *                  cred;
    int                                 i;
    int                                 cert_count;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex;
    X509 *                              cert;
    ASN1_OBJECT *                       asn1_obj;
    ASN1_OCTET_STRING *                 asn1_oct_string;
    gss_buffer_desc                     data_set_buffer;
    
    *minor_status = 0;
    major_status = GSS_S_COMPLETE;
    cred = (gss_cred_id_desc *) cred_handle;

    /* parameter checking goes here */

    if(minor_status == NULL)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,GSSERR_R_BAD_ARGUMENT);
        /* *minor_status = GSSERR_R_BAD_ARGUMENT; */
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    if(cred_handle == GSS_C_NO_CREDENTIAL)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(desired_object == GSS_C_NO_OID)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(data_set == NULL)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    cert_count = 1;

    if(cred->callback_data->cert_chain)
    {
        cert_count += sk_X509_num(cred->pcd->cert_chain);
    }

    major_status = gss_create_empty_buffer_set(minor_status, data_set);

    if(major_status != GSS_S_COMPLETE)
    {
        goto err;
    }

    cert = cred->pcd->ucert;
    cert_count--;
    
    do
    {
        extensions = cert->cert_info->extensions;
        data_set_buffer.value = NULL;
        data_set_buffer.length = 0;
        
        for (i=0;i<sk_X509_EXTENSION_num(extensions);i++)
        {
            ex = (X509_EXTENSION *) sk_X509_EXTENSION_value(extensions,i);
            asn1_obj = X509_EXTENSION_get_object(ex);

            /* if statement is kind of ugly, but I couldn't find a
             * better way
             */
            
            if((asn1_obj->length == desired_object->length) &&
               !memcmp(asn1_obj->data, desired_object->elements, asn1_obj->length))
            {
                /* found a match */
                
                asn1_oct_string = X509_EXTENSION_get_data(ex);
                
                data_set_buffer.value = asn1_oct_string->data;
                
                data_set_buffer.length = asn1_oct_string->length;

                /* assume one extension per cert ? */
                
                break;
            }
        }
        
        major_status = gss_add_buffer_set_member(minor_status,
                                                 &data_set_buffer,
                                                 data_set);
        
        if(major_status != GSS_S_COMPLETE)
        {
            gss_release_buffer_set(&tmp_minor_status, data_set);
            goto err;
        }
    } while(cert_count-- &&
            (cert = sk_X509_value(cred->pcd->cert_chain,cert_count)));

err:
    return major_status;

    
}



