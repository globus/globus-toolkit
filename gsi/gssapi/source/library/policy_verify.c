
#include "gssapi.h"
#include "gssapi_ssleay.h"
#include "gssutils.h"

OM_uint32
gss_policy_verify(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t                        context,
    gss_buffer_t                        input_token,
    gss_buffer_t                        output_token,
    gss_name_t *                        signing_identity)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    BIO *                               bio = NULL;
    BIO *                               b64 = NULL;
    int                                 result;
    ASN1_BIT_STRING *                   signature = NULL;
    ASN1_OCTET_STRING *                 policy = NULL;
    gss_ctx_id_desc *                   context_handle;
    STACK_OF(X509) *                    cert_chain = NULL;
    X509 *                              sig_cert = NULL;
    X509 *                              chain_cert = NULL; 
    gss_name_desc *                     sig_identity = NULL;

    context_handle = (gss_ctx_id_desc *) context;
    
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bio);

    major_status = gs_put_token(NULL,bio,input_token);

    if (major_status != GSS_S_COMPLETE)
    {
        *minor_status = gsi_generate_minor_status();
        goto done;
    }
    
    ASN1_d2i_bio((char *(*)()) ASN1_OCTET_STRING_new,
                 (char *(*)()) d2i_ASN1_OCTET_STRING,
                 b64,
                 (unsigned char **) &policy);

    if(policy == NULL)
    {
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto done;
    }

    ASN1_d2i_bio((char *(*)()) ASN1_BIT_STRING_new,
                 (char *(*)()) d2i_ASN1_BIT_STRING,
                 b64,
                 (unsigned char **) &signature);
    if(signature == NULL)
    {
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto done;
    }
    d2i_X509_bio(b64,&sig_cert);
    if(sig_cert == NULL)
    {
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto done;
    }
    cert_chain = sk_X509_new_null();
    
    while(BIO_pending(b64))
    {
        chain_cert = d2i_X509_bio(b64, NULL);

        if(chain_cert == NULL)
        {
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_FAILURE;
            goto done;
        }

        sk_X509_push(cert_chain,chain_cert);
    }
    result = globus_ssl_utils_verify_signature(policy,
                                               signature,
                                               sig_cert);
    if(result <= 0)
    {
        major_status = GSS_S_FAILURE;
        *minor_status = gsi_generate_minor_status();
        goto done;
    }

    result = globus_ssl_utils_verify_cert(sig_cert,
                                          cert_chain,
                                          context_handle->pvxd.certdir);
    if(result)
    {
        major_status = GSS_S_FAILURE;
        *minor_status = gsi_generate_minor_status();
        goto done;
    }
    
    output_token->length = ASN1_STRING_length(policy);
    output_token->value = malloc(output_token->length);
    memcpy(output_token->value,
           ASN1_STRING_data(policy),
           output_token->length);

    sig_identity = malloc(sizeof(gss_name_desc));

    memset(sig_identity,0,sizeof(gss_name_desc));

    sig_identity->x509n = X509_NAME_dup(X509_get_subject_name(sig_cert));

    proxy_get_base_name(sig_identity->x509n);

    *signing_identity = sig_identity;
    
 done:
    if(bio)
    {
        BIO_free(bio);
    }
    
    if(policy)
    { 
        ASN1_OCTET_STRING_free(policy);
    }

    if(signature)
    {
        ASN1_BIT_STRING_free(signature);
    }

    if(sig_cert)
    {
        X509_free(sig_cert);
    }

    if(cert_chain)
    {
        sk_X509_pop_free(cert_chain, X509_free);
    }
    return major_status;
    
}
