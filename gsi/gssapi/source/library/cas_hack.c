#ifdef GLOBUS_AUTHORIZATION

#include "gssapi_openssl.h"
#include "globus_gsi_system_config.h"
#include "globus_i_gsi_gss_utils.h"
#include "sslutils.h"

static const gss_OID_desc gss_cas_policy_extension_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x06"}; 
const gss_OID_desc * const gss_cas_policy_extension = 
                &gss_cas_policy_extension_oid;


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
    globus_result_t			g_result;
    ASN1_BIT_STRING *                   signature = NULL;
    ASN1_OCTET_STRING *                 policy = NULL;
    gss_ctx_id_desc *                   context_handle;
    STACK_OF(X509) *                    cert_chain = NULL;
    X509 *                              sig_cert = NULL;
    X509 *                              chain_cert = NULL; 
    gss_name_desc *                     sig_identity = NULL;
    char *				certdir = 0;
    OM_uint32				local_minor_status = 0;
    static char *                       _function_name_ =
        "gss_policy_verify";

    context_handle = (gss_ctx_id_desc *) context;
    
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bio);

    major_status = globus_i_gsi_gss_put_token(&local_minor_status,
					      NULL,bio,input_token);
    if (GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL);
        goto done;
    }
    
    ASN1_d2i_bio((char *(*)()) ASN1_OCTET_STRING_new,
                 (char *(*)()) d2i_ASN1_OCTET_STRING,
                 b64,
                 (unsigned char **) &policy);

    if(policy == NULL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL,
            ("null policy"));
        major_status = GSS_S_FAILURE;
        goto done;
    }

    ASN1_d2i_bio((char *(*)()) ASN1_BIT_STRING_new,
                 (char *(*)()) d2i_ASN1_BIT_STRING,
                 b64,
                 (unsigned char **) &signature);
    if(signature == NULL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL,
            ("null policy signature"));
        major_status = GSS_S_FAILURE;
        goto done;
    }
    d2i_X509_bio(b64,&sig_cert);
    if(sig_cert == NULL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL,
            ("null policy-signing cert"));
        major_status = GSS_S_FAILURE;
        goto done;
    }
    cert_chain = sk_X509_new_null();
    
    while(BIO_pending(b64))
    {
        chain_cert = d2i_X509_bio(b64, NULL);

        if(chain_cert == NULL)
        {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL,
            ("problem with policy-signing cert chain"));
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
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL,
            ("problem verifying policy signature"));
        goto done;
    }

    g_result = GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&certdir);

    result = globus_ssl_utils_verify_cert(sig_cert,
                                          cert_chain,
                                          certdir);
    if(result)
    {
        major_status = GSS_S_FAILURE;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL,
            ("problem verifying policy-signing cert chain"));
        goto done;
    }
    
    output_token->length = ASN1_STRING_length(policy);
    output_token->value = malloc(output_token->length);
    memcpy(output_token->value,
           strdup(ASN1_STRING_data(policy)),
           output_token->length);

    sig_identity = malloc(sizeof(gss_name_desc));

    memset(sig_identity,0,sizeof(gss_name_desc));

    sig_identity->x509n = X509_NAME_dup(X509_get_subject_name(sig_cert));

    globus_gsi_cert_utils_get_base_name(sig_identity->x509n);

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

#endif /* GLOBUS_AUTHORIZATION */
