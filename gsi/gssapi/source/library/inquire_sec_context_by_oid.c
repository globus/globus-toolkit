/**********************************************************************

inquire_sec_context_by_oid.c:

Description:
    GSSAPI routine to extract extensions from a credential.

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
GSS_CALLCONV gss_inquire_sec_context_by_oid(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID                       desired_object,
    gss_buffer_set_t                    data_set)
{
    OM_uint32                           major_status;
    gss_ctx_id_desc *                   context;
    int                                 i;
    int                                 j;
    int                                 cert_count;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex;
    X509 *                              cert;
    ASN1_OBJECT *                       asn1_obj;
    ASN1_OCTET_STRING *                 asn1_oct_string;

    
    *minor_status = 0;
    major_status = GSS_S_COMPLETE;
    context = (gss_ctx_id_desc *) context_handle;

    /* parameter checking goes here */

    if(minor_status == NULL)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    if(context_handle == GSS_C_NO_CONTEXT)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }


    if(desired_object == GSS_C_NO_OID)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(data_set == GSS_C_NO_BUFFER_SET)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    cert_count = 0;
    
    data_set->count = sk_X509_num(context->pvd.cert_chain);

    data_set->elements = (gss_buffer_desc *) malloc(
        sizeof(gss_buffer_desc) *
        data_set->count);

    if(data_set->elements == NULL)
    {
        GSSerr(GSSERR_F_INQUIRE_BY_OID,ERR_R_MALLOC_FAILURE);
        /* what is the the correct minor status ?*/
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    memset(data_set->elements,0,sizeof(gss_buffer_desc) * data_set->count);

    while(cert_count < data_set->count &&
          (cert = sk_X509_value(context->pvd.cert_chain,cert_count)))
    {
        extensions = cert->cert_info->extensions;

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
                
                data_set->elements[cert_count].value =
                    malloc(asn1_oct_string->length);

                if(data_set->elements[cert_count].value == NULL)
                {
                    for(j=0;j<cert_count;j++)
                    {
                        gss_release_buffer(minor_status,
                                           &data_set->elements[j]);
                    }
                    
                    free(data_set->elements);
                    GSSerr(GSSERR_F_INQUIRE_BY_OID,ERR_R_MALLOC_FAILURE);
                    /* what is the the correct minor status ?*/
                    major_status = GSS_S_FAILURE;
                    goto err;
                }
                
                data_set->elements[cert_count].length =
                    asn1_oct_string->length;
                
                memcpy(data_set->elements[cert_count].value,
                       asn1_oct_string->data,
                       asn1_oct_string->length);
                
                /* assume one extension per cert ? */
                
                break;
            }
        }

        cert_count++;
        
    } 

err:
    return major_status;

    
}



