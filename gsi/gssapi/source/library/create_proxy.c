
#include "gssapi.h"
#include "gssapi_ssleay.h"
#include "gssutils.h"

#define CAS_PROXY_BASE_FN "/tmp/x509up_c"

static X509_EXTENSION *
proxy_create_cas_extension(
    const gss_buffer_t                  extension_data);


OM_uint32
gss_create_cas_proxy(
    OM_uint32 *                         minor_status,
    gss_cred_id_t                       credential,
    gss_buffer_t                        policy,
    char *                              proxy_tag)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    int                                 result;
    gss_cred_id_desc *                  cred_handle;
    int                                 hours = 12;
    globus_proxy_type_t                 proxy_type = GLOBUS_RESTRICTED_PROXY;
    int                                 bits = 512;
    int                                 length;
    char *                              outfile = NULL;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex = NULL;

    cred_handle = (gss_cred_id_desc *) credential;

    extensions = sk_X509_EXTENSION_new_null();

    ex = proxy_create_cas_extension(policy);

    sk_X509_EXTENSION_push(extensions, ex);

    length = strlen(CAS_PROXY_BASE_FN) + strlen(proxy_tag) + 1;
    
    outfile = malloc(length);

    snprintf(outfile,length,CAS_PROXY_BASE_FN "%s",proxy_tag);
        
    result = proxy_create_local(cred_handle->pcd,
                                outfile,
                                hours,
                                bits,
                                proxy_type,
                                NULL,
                                extensions);

    if(result)
    {
        major_status = GSS_S_FAILURE;
        *minor_status = gsi_generate_minor_status();
        goto done;
    }
    
 done:

    if (extensions)
    {
        sk_X509_EXTENSION_pop_free(extensions, 
                                   X509_EXTENSION_free);
    }

    if(outfile)
    {
        free(outfile);
    }

    

    return major_status;
}

static X509_EXTENSION *
proxy_create_cas_extension(
    const gss_buffer_t                  extension_data)

{
    X509_EXTENSION *                    ex = NULL;
    ASN1_OBJECT *                       asn1_obj = NULL;
    ASN1_OCTET_STRING *                 asn1_oct_string = NULL;
    int                                 crit = 0;

    asn1_obj = OBJ_txt2obj("CASRIGHTS",0);   
    
    if(!(asn1_oct_string = ASN1_OCTET_STRING_new()))
    {
        /* set some sort of error */
        goto err;
    }

    asn1_oct_string->data = extension_data->value;
    asn1_oct_string->length = extension_data->length;

    if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, asn1_obj, 
                                            crit, asn1_oct_string)))
    {
        /* set some sort of error */
        goto err;
    }
    
err:
    if (asn1_oct_string)
    {
        ASN1_OCTET_STRING_free(asn1_oct_string);
    }
    
    if (asn1_obj)
    {
        ASN1_OBJECT_free(asn1_obj);
    }
    
    return ex;
}
