
#include "gssapi.h"
#include "gssapi_ssleay.h"
#include "gssutils.h"

OM_uint32
gss_policy_sign(
    OM_uint32 *                         minor_status,
    gss_cred_id_t                       credential,
    gss_buffer_t                        input_token,
    gss_buffer_t                        output_token)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    BIO *                               bio = NULL;
    BIO *                               b64 = NULL;
    int                                 result;
    ASN1_BIT_STRING *                   signature = NULL;
    ASN1_OCTET_STRING *                 asn1_data = NULL;
    gss_cred_id_desc *                  cred_handle;
    int                                 i;
    int                                 cert_chain_length;
    X509 *                              cert;

    cred_handle = (gss_cred_id_desc *) credential;
    
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bio);

    asn1_data = ASN1_OCTET_STRING_new();

    ASN1_OCTET_STRING_set(asn1_data,
                          (unsigned char *) input_token->value,
                          input_token->length);

    ASN1_i2d_bio(i2d_ASN1_OCTET_STRING,b64,(unsigned char *) asn1_data);
    
    result = globus_ssl_utils_sign(asn1_data,
                                   &signature,
                                   cred_handle->pcd->upkey);
    if(result <= 0)
    {
        major_status = GSS_S_FAILURE;
        *minor_status = gsi_generate_minor_status();
        goto done;
    }

    ASN1_i2d_bio(i2d_ASN1_BIT_STRING,b64,(unsigned char *) signature);
    
    if(cred_handle->pcd->cert_chain != NULL)
    {
        cert_chain_length = sk_X509_num(cred_handle->pcd->cert_chain);
    }
    
    for(i=cert_chain_length-1;i>=0;i--)
    {
        cert = sk_X509_value(cred_handle->pcd->cert_chain,i);
        
        i2d_X509_bio(b64,cert);
    }

    i2d_X509_bio(b64,cred_handle->pcd->ucert);

    BIO_flush(b64);

    gs_get_token(NULL,bio,output_token);

 done:
    if(b64)
    {
        BIO_free_all(b64);
    }
    
    if(asn1_data)
    { 
        ASN1_OCTET_STRING_free(asn1_data);
    }

    if(signature)
    {
        ASN1_BIT_STRING_free(signature);
    }

    return major_status;
    
}
