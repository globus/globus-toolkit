#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_proxy.c
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#define PROXYCERTINFO_OID               "1.3.6.1.4.1.3536.1.222"
#define PROXYCERTINFO_SN                "Proxy Cert Info"
#define PROXYCERTINFO_LN                "Proxy Certificate Info Extension"

#define PROXY_NAME                      "proxy"
#define LIMITED_PROXY_NAME              "limited proxy"
#define RESTRICTED_PROXY_NAME           "restricted proxy"

#include "globus_i_gsi_proxy.h"
#include "globus_gsi_proxy_constants.h"
#include "version.h"
#include "globus_error_openssl.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

static int globus_l_gsi_proxy_activate(void);
static int globus_l_gsi_proxy_deactivate(void);

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t		globus_i_gsi_proxy_module =
{
    "globus_gsi_proxy",
    globus_l_gsi_proxy_activate,
    globus_l_gsi_proxy_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_gsi_proxy_activate(void)
{
    return globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
}

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_proxy_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
}
/* globus_l_gsi_proxy_deactivate() */
#endif

/**
 * @name Create Request
 */
/*@{*/
/**
 * Create a proxy credential request
 * @ingroup globus_gsi_proxy_operations
 *
 * This function creates a proxy credential request, ie. a unsigned 
 * certificate and the corresponding private key, based on the handle
 * that is passed in.
 * The public part of the request is written to the BIO supplied in
 * the output_bio parameter.
 * The proxy handle is updated with the private key.
 *
 * @param handle
 *        A GSI Proxy handle to use for the request operation.
 * @param output_bio
 *        A BIO to write the resulting request structure to.
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_create_req(
    globus_gsi_proxy_handle_t           handle,
    BIO *                               output_bio)
{
    char *                              pci_DER = NULL;            
    X509_EXTENSION *                    pci_ext = NULL;
    STACK_OF(X509_EXTENSION) *          extensions = NULL;
    ASN1_OCTET_STRING *                 pci_DER_string = NULL;
    int                                 pci_NID;
    int                                 pci_critical;
    int                                 pci_DER_length;

    int                                 key_bits;
    int                                 init_prime;
    RSA *                               rsa_key = NULL;
    BIO *                               stdout_bio = NULL;
    globus_result_t                     result;

    char *                              _FUNCTION_NAME_ =
        "globus_gsi_proxy_create_req";

    /* create a stdout bio for sending key generation 
     * progress information */
    if((stdout_bio = BIO_new(BIO_s_file())) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_BIO);
        goto done;
    }

    BIO_set_fp(stdout_bio, stdout, BIO_NOCLOSE);

    if((result = globus_gsi_proxy_handle_attrs_get_keybits(
        handle->attrs, & key_bits)) != GLOBUS_SUCCESS)
    {
        goto free_bio;
    }

    if((result = globus_gsi_proxy_handle_attrs_get_init_prime(
        handle->attrs, &init_prime)) != GLOBUS_SUCCESS)
    {
        goto free_bio;
    }

    /* First, generate and setup private/public key pair */
    if((rsa_key = RSA_generate_key(key_bits, init_prime, 
                                   (void (*)()) 
                                   globus_i_gsi_proxy_create_private_key_cb, 
                                   (char *) stdout_bio)) == NULL)
    {
        /* ERROR: RSA_generate_key errored */
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto free_bio;
    }

    if(EVP_PKEY_assign_RSA(handle->proxy_key, rsa_key))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto free_rsa;
    }

    if(X509_REQ_set_version(handle->req, 0L))
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto free_rsa;
    }

    X509_REQ_set_pubkey(handle->req, handle->proxy_key);

    /* create the X509 extension from the PROXYCERTINFO */
    if((pci_NID = OBJ_create(PROXYCERTINFO_OID, 
                             PROXYCERTINFO_SN, 
                             PROXYCERTINFO_LN)) == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO);
        goto free_rsa;
    }

    /* openssl doesn't appear to have any error checking
     * for these i2d functions - so we just have to cross our fingers
     */
    if((pci_DER_length = i2d_PROXYCERTINFO(handle->proxy_cert_info, 
                                           (unsigned char **) &pci_DER)) < 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_BETWEEN_INT_DER_FORM);
        goto free_rsa;
    }

    if((pci_DER_string = ASN1_OCTET_STRING_new()) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO);
        goto free_rsa;
    }
    
    pci_DER_string->data = pci_DER;
    pci_DER_string->length = pci_DER_length;

    /* set the extensions's critical value */
    pci_critical = 
        PROXYCERTINFO_get_restriction(handle->proxy_cert_info) ? 1 : 0;

    if((pci_ext = X509_EXTENSION_create_by_NID(& pci_ext, 
                                               pci_NID, 
                                               pci_critical, 
                                               pci_DER_string)) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS);
        goto free_pci_string;
    }

    /* get the list of extensions from the X509_REQ,
     * and add the PROXYCERTINFO extension to the list
     */

    if((extensions = X509_REQ_get_extensions(handle->req)) == NULL)
    {

        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto free_pci_ext;
    }

    if(sk_X509_EXTENSION_push(extensions, pci_ext) == 0)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS);
        goto free_extensions;
    }

    if(X509_REQ_add_extensions(handle->req, extensions) == 0)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto free_extensions;
    }
    /* write the request to the BIO */
    if(i2d_X509_REQ_bio(output_bio, handle->req) == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_BETWEEN_INT_DER_FORM);
        goto free_extensions;
    }

    result = GLOBUS_SUCCESS;

 free_extensions:
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
 free_pci_ext:
    X509_EXTENSION_free(pci_ext);
 free_pci_string:
    ASN1_OCTET_STRING_free(pci_DER_string);
 free_rsa:
    RSA_free(rsa_key);
 free_bio: 
    BIO_free(stdout_bio);
 done:
    return result;
}
/* globus_gsi_proxy_create_req */
/*@}*/

/**
 * @name Inquire Request
 */
/*@{*/
/**
 * Inquire a proxy credential request
 * @ingroup globus_gsi_proxy_operations
 *
 * This function reads the public part of a proxy credential request
 * from input_bio and if the request contains a ProxyCertInfo
 * extension, updates the handle with the information contained in the
 * extension.
 *
 * @param handle
 *        A GSI Proxy handle to use for the inquire operation.
 * @param input_bio
 *        A BIO to read a request structure from.
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_inquire_req(
    globus_gsi_proxy_handle_t           handle,
    BIO *                               input_bio)
{
    X509_REQ *                          request = NULL;
    STACK_OF(X509_EXTENSION) *          extensions = NULL;
    X509_EXTENSION *                    tmp_ext = NULL;
    int                                 ext_index;
    int                                 pci_NID;
    PROXYCERTINFO *                     pci = NULL;
    ASN1_OCTET_STRING *                 ext_data = NULL;
    globus_result_t                     result;

    char *                              _FUNCTION_NAME_ =
        "globus_gsi_proxy_inquire_req";

    if(d2i_X509_REQ_bio(input_bio, & request) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_BETWEEN_INT_DER_FORM);
        goto done;
    }

    if((extensions = X509_REQ_get_extensions(request)) == NULL)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto free_request;
    }
    
    if((pci_NID = OBJ_create(PROXYCERTINFO_OID, 
                             PROXYCERTINFO_SN, 
                             PROXYCERTINFO_LN)) == 0)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO);
        goto free_extensions;
    }
        
    /* we assume there's only one proxycertinfo extension */
    if((ext_index = X509v3_get_ext_by_NID(extensions, pci_NID, -1)) != -1)
    {
        if((tmp_ext = X509v3_get_ext(extensions, ext_index)) == NULL)
        {
            result = GLOBUS_GSI_PROXY_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS);
            goto free_extensions;
        }
        if((ext_data = X509_EXTENSION_get_data(tmp_ext)) == NULL)
        {
            result = GLOBUS_GSI_PROXY_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS);
            goto free_tmp_ext;
        }

        if(d2i_PROXYCERTINFO(
            & pci, 
            & ext_data->data, 
            ext_data->length) == NULL)
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_CONVERTING_BETWEEN_INT_DER_FORM);
            goto free_ext_data;
        }

        if((handle->proxy_cert_info = PROXYCERTINFO_dup(pci)) == NULL)
        {
            
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO);
            goto free_pci;
        }
    }

    result = GLOBUS_SUCCESS;

 free_pci:
    PROXYCERTINFO_free(pci);
 free_ext_data:
    ASN1_OCTET_STRING_free(ext_data); 
 free_tmp_ext:
    X509_EXTENSION_free(tmp_ext);
 free_extensions:
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
 free_request:
    X509_REQ_free(request);
 done:
    return result;
}
/* globus_gsi_proxy_inquire_req */
/*@}*/

/**
 * @name Sign Request
 */
/*@{*/
/**
 * Sign a proxy certificate request
 * @ingroup globus_gsi_proxy_operations
 *
 * This function signs the public part of a proxy credential request,
 * i.e. the unsigned certificate, previously read by inquire req using
 * the supplied issuer_credential. This operation will add a
 * ProxyCertInfo extension to the proxy certificate if values
 * contained in the extension are specified in the handle.
 * The resulting signed certificate is written to the output_bio.
 *
 * @param handle
 *        A GSI Proxy handle to use for the signing operation.
 * @param issuer_credential
 *        The credential structure to be used for signing the proxy
 *        certificate. 
 * @param output_bio
 *        A BIO to write the resulting certificate and cert chain to.
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_sign_req(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cred_handle_t            issuer_credential,
    BIO *                               output_bio)
{
    char *                              common_name;
    X509 *                              new_pc = NULL;
    X509 *                              issuer_cert = NULL;
    STACK_OF(X509_EXTENSION) *          pc_req_extensions =  NULL;
    X509_EXTENSION *                    tmp_ext = NULL;
    EVP_PKEY *                          issuer_pkey = NULL;
    globus_result_t                     result;
    int                                 ext_num;
    int                                 ext_index;
    int                                 res;
    
    char *                              _FUNCTION_NAME_ =
        "globus_gsi_proxy_sign_req";
    
    if(handle == NULL || issuer_credential == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
        goto done;
    }
    
    if((res = 
        X509_REQ_verify(handle->req, X509_REQ_get_pubkey(handle->req))) == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto done;
    }
    
    if(PROXYCERTINFO_get_restriction(handle->proxy_cert_info) != NULL)
    {
        common_name = RESTRICTED_PROXY_NAME;
    }
    else
    {
        common_name = PROXY_NAME;
    }

    if((new_pc = X509_new()) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto done;
    }

    if((result = 
        globus_gsi_cred_get_cert(issuer_credential, &issuer_cert))
       != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CREDENTIAL,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error getting certificate from credential");
        goto free_new_pc;
    }

    /* create proxy subject name */
    if((result = 
        globus_i_gsi_proxy_set_subject(new_pc, issuer_cert, 
                                       common_name)) != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error setting subject of new proxy cert");
        goto free_new_pc;
    }

    if(X509_set_version(new_pc, 3) == 0 ||
       X509_set_serialNumber(
           new_pc, 
           X509_get_serialNumber(issuer_cert)) == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto free_new_pc;
    }

    if((result = 
        globus_i_gsi_proxy_set_pc_times(
            new_pc, 
            issuer_cert, 
            handle->clock_skew, 
            handle->time_valid)) != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error setting valid times of new proxy cert");
        goto free_new_pc;
    }
       
    if(X509_set_pubkey(new_pc, X509_REQ_get_pubkey(handle->req)) == 0 ||
       X509_set_serialNumber(
           new_pc, 
           X509_get_serialNumber(issuer_cert)) == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto free_new_pc;
    }


    /* add the extensions from the proxy cert request 
     * to the new proxy cert */    
    if((pc_req_extensions = X509_REQ_get_extensions(handle->req)) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_BETWEEN_INT_DER_FORM);
        goto free_new_pc;
    }

    ext_num = sk_X509_EXTENSION_num(pc_req_extensions);
    for(ext_index = 0; ext_index < ext_num; ++ext_index)
    {
        tmp_ext = sk_X509_EXTENSION_value(pc_req_extensions, ext_index);
        if(X509_add_ext(new_pc, tmp_ext, ext_index) == 0)
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS);
            goto free_req_extensions;
        }
        X509_EXTENSION_free(tmp_ext);
        tmp_ext = NULL;
    }
    sk_X509_EXTENSION_pop_free(pc_req_extensions, X509_EXTENSION_free);
    pc_req_extensions = NULL;

    /* sign the new certificate */
    if((result = globus_gsi_cred_get_key(issuer_credential, &issuer_pkey))
       != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CREDENTIAL,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error getting private key of credential");
        goto free_req_extensions;
    }
    
    /* right now if MD5 isn't requested as the signing algorithm,
     * we throw an error
     */
    if(EVP_MD_type(handle->signing_algorithm) != NID_md5)
    {
        result = globus_i_gsi_proxy_openssl_error_result(
            GLOBUS_GSI_PROXY_ERROR_WITH_CREDENTIAL,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "The signing algorithm: %s is not currently allowed."
            "\nUse MD5 to sign certificate requests",
            OBJ_nid2sn(EVP_MD_type(handle->signing_algorithm)));
        goto free_req_extensions;
    }
    
    if(!X509_sign(new_pc, issuer_pkey, handle->signing_algorithm))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto free_req_extensions;
    }

    /* write out the X509 certificate in DER encoded format to the BIO */
    if(!i2d_X509_bio(output_bio, new_pc))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_BETWEEN_INT_DER_FORM);
        goto free_req_extensions;
    }
    
    result = GLOBUS_SUCCESS;
    
 free_req_extensions:
    sk_X509_EXTENSION_pop_free(pc_req_extensions, X509_EXTENSION_free);
 free_new_pc:
    X509_free(new_pc); 
 done:  
    return result;
}
/* globus_gsi_proxy_sign_req */
/*@}*/

/* read cert and cert chain from bio and combine them with the private
 * key into a credential structure.
 */

/**
 * @name Assemble credential
 */
/*@{*/
/**
 * Assemble a proxy credential
 * @ingroup globus_gsi_proxy_operations
 *
 * This function assembles a proxy credential. It reads a signed proxy
 * certificate and a associated certificate chain from the input_bio
 * and combines them with a private key previously generated by a call
 * to globus_gsi_proxy_create_req. The resulting credential is then
 * returned through the proxy_credential parameter.
 *
 * @param handle
 *        A GSI Proxy handle to use for the assemble operation.
 * @param proxy_credential
 *        This parameter will contain the assembled credential upon
 *        successful return.
 * @param input_bio
 *        A BIO to read a signed certificate and corresponding
 *        certificate chain from.
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_gsi_proxy_assemble_cred(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cred_handle_t *          proxy_credential,
    BIO *                               input_bio)
{
    X509 *                              signed_cert = NULL;
    X509 *                              tmp_cert = NULL;
    STACK_OF(X509) *                    issuer_certs = NULL;

    globus_gsi_cred_handle_attrs_t      cred_handle_attrs = NULL;
    globus_result_t                     result;

    char *                              _FUNCTION_NAME_ =
        "globus_gsi_proxy_assemble_cred";

    /* check to make sure params are ok */
    if(handle == NULL)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_HANDLE);
        goto done;
    }

    if(input_bio == NULL)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_BIO);
        goto done;
    }

    /* create the stack of issuer certs */
    if((issuer_certs = sk_X509_new_null()) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto done;
    }

    /* get the signed proxy cert from the BIO */
    if(!d2i_X509_bio(input_bio, &signed_cert))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_BETWEEN_INT_DER_FORM);
        goto free_issuer_certs;
    }

    /* get all the signing certificates in the chain from the BIO */
    while(!BIO_eof(input_bio))
    {
        if(!d2i_X509_bio(input_bio, &tmp_cert))
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_CONVERTING_BETWEEN_INT_DER_FORM);
            goto free_tmp_cert;
        }
        
        sk_X509_push(issuer_certs, tmp_cert);
        X509_free(tmp_cert);
    }
    
    /* SLANG: what should the cred handle attrs be set to ? */
    
    if((result = globus_gsi_cred_handle_attrs_init(
        & cred_handle_attrs)) != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE_ATTRS,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error creating credential handle attributes for proxy");
        
        goto free_signed_cert;
    }

    if((result = globus_gsi_cred_handle_init(proxy_credential, 
                                             cred_handle_attrs))
       != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error creating credential handle for proxy");
        goto free_signed_cert;
    }

    if((result = globus_gsi_cred_set_cert(*proxy_credential, signed_cert))
       != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error setting cert in credential");
        goto free_signed_cert;
    }

    if((result = globus_gsi_cred_set_key(*proxy_credential, handle->proxy_key))
       != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error setting key in credential");
        goto free_signed_cert;
    }

    if((result = globus_gsi_cred_set_cert_chain(*proxy_credential, 
                                                issuer_certs))
       != GLOBUS_SUCCESS)
    {
        result = globus_i_gsi_proxy_error_chain_result(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE,
            __FILE__, _FUNCTION_NAME_, __LINE__,
            "Error setting cert chain in credential");
        goto free_signed_cert;
    }
    
    result = GLOBUS_SUCCESS;
    
 free_tmp_cert:
    X509_free(tmp_cert);
 free_signed_cert:
    X509_free(signed_cert);
 free_issuer_certs:
    sk_X509_pop_free(issuer_certs, X509_free);
 done:
    return result;
}
/* globus_gsi_proxy_assemble_cred */
/*@}*/
    
/**
 * Get Base Name
 * @ingroup globus_gsi_proxy_operations
 */
/* @{ */
/**
 * Ge the base name of a proxy certificate.  Given an X509 name, strip
 * off the /CN=proxy component (can be "limited proxy" or "restricted proxy")
 * to get the base name of the certificate's subject
 *
 * @param subject
 *        Pointer to an X509_NAME object which gets stripped
 *
 * @return
 *        GLOBUS_SUCCESS
 */
globus_result_t
globus_l_gsi_proxy_get_base_name(
    X509_NAME *                     subject)
{
    X509_NAME_ENTRY *                  ne;
    ASN1_STRING *                      data;
    
    /* 
     * drop all the /CN=proxy entries 
     */
    for(;;)
    {
        ne = X509_NAME_get_entry(subject,
                                 X509_NAME_entry_count(subject)-1);
        if (!OBJ_cmp(ne->object,OBJ_nid2obj(NID_commonName)))
        {
            data = X509_NAME_ENTRY_get_data(ne);
            if ((data->length == 5 && 
                 !memcmp(data->data,"proxy",5)) ||
                (data->length == 13 && 
                 !memcmp(data->data,"limited proxy",13)) ||
		(data->length == 16 &&
		 !memcmp(data->data,"restricted proxy",16)))
            {
                ne = X509_NAME_delete_entry(subject,
                                            X509_NAME_entry_count(subject)-1);
                X509_NAME_ENTRY_free(ne);
                ne = NULL;
            }
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }

    return GLOBUS_SUCCESS;
}
/* @} */


#ifndef BUILD_FOR_K5CERT_ONLY

/**
 * Check Proxy Name
 * @ingroup globus_gsi_proxy_operations
 */
/* @{ */
/**
 * Check if the subject name is a proxy, and the issuer name
 * is the same as the subject name, but without the proxy
 * entry.
 * i.e. inforce the proxy signing requirement of 
 * only a user or a user's proxy can sign a proxy. 
 *
 * @param cert
 *        The proxy cert as an X509 struct
 * @param type
 *       -1  error related to mismatch of proxy name with cert
 *        0  if not a proxy
 *        1  if a proxy
 *        2  if a limited proxy
 *        3  if a restricted proxy
 *
 * @return 
 *        GLOBUS_SUCCESS or a error object id
 */
globus_result_t
globus_l_gsi_proxy_check_proxy_name(
    X509 *                              cert,
    int *                               type)
{
    X509_NAME *                         subject;
    X509_NAME *                         name = NULL;
    X509_NAME_ENTRY *                   ne = NULL;
    ASN1_STRING *                       data;
    char *                              _FUNCTION_NAME_ =
        "globus_l_gsi_proxy_check_proxy_name";

    *type = 0;
    subject = X509_get_subject_name(cert);
    if((ne = X509_NAME_get_entry(subject, X509_NAME_entry_count(subject)-1))
       == NULL)
    {
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
    }
    if (!OBJ_cmp(ne->object, OBJ_nid2obj(NID_commonName)))
    {
        data = X509_NAME_ENTRY_get_data(ne);
        if (data->length == 5 && !memcmp(data->data,"proxy",5))
        {
            *type = GLOBUS_FULL_PROXY;
        }
        else if (data->length == 13 && !memcmp(data->data,"limited proxy",13))
        {
            *type = GLOBUS_LIMITED_PROXY;
        }
        else if (data->length == 16 && 
                 !memcmp(data->data,"restricted proxy",16))
        {
	    *type = GLOBUS_RESTRICTED_PROXY;
        } 

        if(*type != 0)
        {

#ifdef DEBUG
            fprintf(stderr,"Subject is a %s\n", data->data);
#endif
        
            /*
             * Lets dup the issuer, and add the CN=proxy. This should
             * match the subject. i.e. proxy can only be signed by
             * the owner.  We do it this way, to double check
             * all the ANS1 bits as well.
             */
            
            if((name = X509_NAME_dup(X509_get_issuer_name(cert))) == NULL)
            {
                return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                    GLOBUS_GSI_PROXY_ERROR_WITH_X509);
            }
            
            if((ne = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName,
                                                   V_ASN1_APP_CHOOSE,
                                                   data->data, -1)) == NULL)
            {
                return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                    GLOBUS_GSI_PROXY_ERROR_WITH_X509);
            }
            
            if(!X509_NAME_add_entry(name, ne, X509_NAME_entry_count(name),0))
            {
                X509_NAME_ENTRY_free(ne);
                ne = NULL;
                return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                    GLOBUS_GSI_PROXY_ERROR_WITH_X509);
            }
            
            X509_NAME_ENTRY_free(ne);
            ne = NULL;

#warning SLANG -- should this be changed back to X509_NAME_cmp from X509_NAME_cmp_no_set -- Look in sslutils.c for more info ??

            if (X509_NAME_cmp(name,subject))
            {
                /*
                 * Reject this certificate, only the user
                 * may sign the proxy
                 */
                *type = -1;
            }
            X509_NAME_free(name);
        }
    }
    return GLOBUS_SUCCESS;
}
#endif // BUILD_FOR_K5CERT_ONLY


/*  globus_result_t */
/*  globus_gsi_proxy_verify_cert_chain( */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * Prints the status of a private key generating algorithm.
 * this could be modified to return more status information
 * if required.
 */
void 
globus_i_gsi_proxy_create_private_key_cb(
    BIO *                               output)
{
    BIO_printf(output, ".");
}


/**
 * Takes the new proxy cert and sets the valid start
 * and end times of the cert
 */
globus_result_t 
globus_i_gsi_proxy_set_pc_times(
    X509 *                              new_pc,
    X509 *                              issuer_cert,
    int                                 skew_allowable,
    int                                 time_valid)
{
    ASN1_UTCTIME *                      pc_notAfter = NULL;
    time_t                              tmp_time;

    char *                              _FUNCTION_NAME_ =
        "globus_i_gsi_proxy_set_pc_times";

    /* adjust for the allowable skew */
    if(X509_gmtime_adj(X509_get_notBefore(new_pc), (- skew_allowable)) == NULL)
    {
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
    }
    
    tmp_time = time(NULL) + ((long) 60 * time_valid);

    /* check that issuer cert won't expire before new proxy cert */
    if(X509_cmp_time(X509_get_notAfter(issuer_cert), & tmp_time) < 0)
    {
        if((pc_notAfter = 
            M_ASN1_UTCTIME_dup(X509_get_notAfter(issuer_cert))) == NULL)
        {
            return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        }
    }
    else
    {
        if(X509_gmtime_adj(pc_notAfter, tmp_time) == NULL)
        {
            ASN1_UTCTIME_free(pc_notAfter);
            return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        }
    }
    
    if(!X509_set_notAfter(new_pc, pc_notAfter))
    {
        ASN1_UTCTIME_free(pc_notAfter);
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
    }

    ASN1_UTCTIME_free(pc_notAfter);
    return GLOBUS_SUCCESS;
}


/**
 * Takes the new proxy cert and sets the subject
 * based on the subject of the issuer cert
 */
globus_result_t 
globus_i_gsi_proxy_set_subject(
    X509 *                              new_pc,
    X509 *                              issuer_cert,
    char *                              common_name)

{
    X509_NAME *                         pc_name = NULL;
    X509_NAME_ENTRY *                   pc_name_entry = NULL;
    globus_result_t                     result;

    char *                              _FUNCTION_NAME_ = 
        "globus_i_gsi_proxy_set_subject";

    if((pc_name = X509_NAME_dup(X509_get_subject_name(issuer_cert))) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto done;
    }
       
    if((pc_name_entry = 
       X509_NAME_ENTRY_create_by_NID(& pc_name_entry, NID_commonName,
                                     V_ASN1_APP_CHOOSE,
                                     (unsigned char *) common_name,
                                     -1)) == NULL)
    {
        
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto free_pc_name;
    }

    if(!X509_NAME_add_entry(pc_name,
                            pc_name_entry,
                            X509_NAME_entry_count(pc_name),
                            0) ||
       !X509_set_subject_name(new_pc, pc_name))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto free_pc_name_entry;
    }
    
    result = GLOBUS_SUCCESS;

 free_pc_name_entry:
    X509_NAME_ENTRY_free(pc_name_entry);
 free_pc_name:
    X509_NAME_free(pc_name);
 done:
    return result;
}


globus_result_t
globus_i_gsi_proxy_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_result_t                     result;

    va_start(ap, format);

    result = globus_error_put(
        globus_i_gsi_proxy_openssl_error_construct(
            error_type,
            filename,
            function_name,
            line_number,
            format,
            ap));

    va_end(ap);

    return result;
}

globus_object_t *
globus_i_gsi_proxy_openssl_error_construct(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap)
{
    static FILE *                       proxy_openssl_error_file = NULL;
    char *                              desc_string = NULL;
    char *                              reason_string = NULL;
    int                                 len;
    globus_object_t *                   error_object;

    globus_libc_lock();
    
    proxy_openssl_error_file = fopen("/dev/null", "w");
    len = vfprintf(proxy_openssl_error_file, format ? format : "", ap) + 1;
    reason_string = (char *) globus_malloc(len);
    vsprintf(reason_string, format ? format : "", ap);

    len = fprintf(proxy_openssl_error_file, "OpenSSL Error: %s:%s:%d: %s",
                  filename, function_name, line_number,
                  globus_l_gsi_proxy_error_strings[error_type]);
    desc_string = (char *) globus_malloc(len);
    sprintf(desc_string, "OpenSSL Error: %s:%s:%d: %s",
            filename, function_name, line_number,
            globus_l_gsi_proxy_error_strings[error_type]);

    fclose(proxy_openssl_error_file);

    globus_libc_unlock();

    error_object = globus_error_wrap_openssl_error(
            GLOBUS_GSI_PROXY_MODULE,
            desc_string,
            error_type,
            reason_string);
    
    globus_free(desc_string);
    globus_free(reason_string);

    return error_object;
}            
        
globus_result_t
globus_i_gsi_proxy_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_result_t                     result;

    va_start(ap, format);

    result = globus_error_put(
        globus_i_gsi_proxy_error_construct(
            error_type,
            filename,
            function_name,
            line_number,
            format,
            ap));
        
    va_end(ap);

    return result;
}
            
globus_object_t *
globus_i_gsi_proxy_error_construct(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap)
{
    static FILE *                       proxy_error_file = NULL;
    char *                              desc_string = NULL;
    char *                              reason_string = NULL;
    int                                 len;
    globus_object_t *                   error_object;

    globus_libc_lock();

    proxy_error_file = fopen("/dev/null", "w");
    len = vfprintf(proxy_error_file, format ? format : "", ap) + 1;
    reason_string = globus_malloc(len);
    vsprintf(reason_string, format ? format : "", ap);

    len = fprintf(proxy_error_file, "%s:%s:%d: %s", 
                  filename, function_name, line_number, 
                  globus_l_gsi_proxy_error_strings[error_type]);
    desc_string = globus_malloc(len);
    sprintf(desc_string, "%s:%s:%d: %s", 
            filename, function_name, line_number,
            globus_l_gsi_proxy_error_strings[error_type]);

    fclose(proxy_error_file);
    
    globus_libc_unlock();

    error_object = globus_error_construct_error(
        GLOBUS_GSI_PROXY_MODULE,
        NULL,
        error_type,
        desc_string,
        reason_string);

    globus_free(desc_string);
    globus_free(reason_string);

    return error_object;
}
        
globus_result_t
globus_i_gsi_proxy_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    ...)
{
    va_list                             ap;
    globus_result_t                     result;

    va_start(ap, format);

    result = globus_error_put(
        globus_i_gsi_proxy_error_chain_construct(
            chain_result,
            error_type,
            filename,
            function_name,
            line_number,
            format,
            ap));
        
    va_end(ap);

    return result;
}
            
globus_object_t *
globus_i_gsi_proxy_error_chain_construct(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        format,
    va_list                             ap)
{
    static FILE *                       proxy_error_file = NULL;
    char *                              desc_string = NULL;
    char *                              reason_string = NULL;
    int                                 len;
    globus_object_t *                   error_object;

    globus_libc_lock();

    proxy_error_file = fopen("/dev/null", "w");
    len = vfprintf(proxy_error_file, format ? format : "", ap) + 1;
    reason_string = globus_malloc(len);
    vsprintf(reason_string, format ? format : "", ap);

    len = fprintf(proxy_error_file, "%s:%s:%d: %s", 
                  filename, function_name, line_number, 
                  globus_l_gsi_proxy_error_strings[error_type]);
    desc_string = globus_malloc(len);
    sprintf(desc_string, "%s:%s:%d: %s", 
            filename, function_name, line_number,
            globus_l_gsi_proxy_error_strings[error_type]);

    fclose(proxy_error_file);
    
    globus_libc_unlock();

    error_object = globus_error_construct_error(
        GLOBUS_GSI_PROXY_MODULE,
        globus_error_get(chain_result),
        error_type,
        desc_string,
        reason_string);

    globus_free(desc_string);
    globus_free(reason_string);

    return error_object;
}

#endif
