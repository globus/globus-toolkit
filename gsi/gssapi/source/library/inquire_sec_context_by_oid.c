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

OM_uint32
GSS_CALLCONV gss_inquire_sec_context_by_oid(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID                       desired_object,
    gss_buffer_set_t                    data_set)
{
    OM_uint32                           major_status;
    gss_ctx_id_desc *                   context;
    gss_oid_desc *                      oid;
    int                                 i;
    int                                 j;
    int                                 cert_count;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex;
    X509 *                              cert;
    ASN1_OBJECT *                       asn1_obj;
    gss_buffer_set_desc *               extension_data;
    ASN1_OCTET_STRING *                 asn1_oct_string;

    
    *minor_status = 0;

    major_status = GSS_S_COMPLETE;
    
    output_token->length = 0;
    context = (gss_ctx_id_desc *) context_handle;
    oid = (gss_oid_desc *) desired_object;

    extension_data = (gss_buffer_set_desc *) extension_data;

    cert_count = 1 + sk_X509_num(context->pcd->cert_chain);
    
    extension_data->count = cert_count;

    extension_data->elements = (gss_buffer_desc *) malloc(sizeof(gss_buffer_desc) *
                                                          extension_data->count);

    cert = context->pcd->ucert;
    
    do
    {
        for (i=0;i<sk_X509_EXTENSION_num(extensions);i++)
        {
            extensions = cert->cert_info->extensions;
            ex = (X509_EXTENSION *) sk_X509_EXTENSION_value(extensions,i);
            asn1_obj = X509_EXTENSION_get_object(ex);

            /* if statement is kind of ugly, but I couldn't find a
             * better way
             */
            
            if((asn1_obj->length == oid->length) &&
               !memcmp(asn1_obj->data, oid->elements,asn1_obj->length))
            {
                /* found a match */
                
                asn1_oct_string = X509_EXTENSION_get_data(ex);
                
                extension_data->elements[cert_count].value =
                    malloc(asn1_oct_string->length);
                
                extension_data->elements[cert_count].length =
                    asn1_oct_string->length;
                
                memcpy(extension_data->elements[1].value,
                       asn1_oct_string->data,
                       asn1_oct_string->length);
                
                /* assume one extension per cert ? */
                
                break;
            }
        }

        cert_count--;
        
    } while(cert_count &&
            cert = (X509 *) sk_value(cred->pvd.cert_chain,cert_count - 1));

    return major_status;
}



