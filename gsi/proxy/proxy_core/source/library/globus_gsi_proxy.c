#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_proxy.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#define PROXYCERTINFO_OID               "1.3.6.1.4.1.3536.1.222"
#define PROXYCERTINFO_SN                "Proxy Cert Info"
#define PROXYCERTINFO_LN                "Proxy Certificate Info Extension"
#define PRIME_START                     0x10001

#define RESTRICTED_PROXY_NAME  "restricted proxy"
#define PROXY_NAME             "proxy"

#include "globus_i_gsi_proxy.h"

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
    GLOBUS_NULL
};

/**
 * Module activation
 */
static
int
globus_l_gsi_proxy_activate(void)
{
    globus_module_activate(GLOBUS_GSI_CREDENTIAL_MODULE);
    return GLOBUS_SUCCESS;
}

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_proxy_deactivate(void)
{
    globus_module_deactivate(GLOBUS_GSI_CREDENTIAL_MODULE);
    return GLOBUS_SUCCESS;
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
    char *                              pci_DER;            
    X509_EXTENSION *                    pci_ext;
    STACK_OF(X509_EXTENSION) *          extensions;
    int                                 pci_NID;
    int                                 pci_critical;

    int                                 key_bits = 1024;
    RSA *                               rsa_key;
    BIO *                               stdout_bio;


    /* create a stdout bio for sending key generation 
     * progress information */
    stdout_bio = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);

    /* First, generate and setup private/public key pair */
    rsa_key = RSA_generate_key(key_bits, PRIME_START, 
                               globus_i_private_key_processing_callback, stdout_bio);

    if(rsa_key == NULL)
    {
        /* ERROR: RSA_generate_key errored - probably ran out of memory */
    }

    EVP_PKEY_assign_RSA(handle->proxy_key, rsa_key);

    if(X509_REQ_set_version(handle->req, 0L))
    {
        /* ERROR */
    }

    X509_REQ_set_pubkey(handle->req, handle->proxy_key);

    i2d_X509_REQ_bio(output_bio, handle->req);

    /* create the X509 extension from the PROXYCERTINFO */
    pci_NID = OBJ_create(PROXYCERTINFO_OID, 
                         PROXYCERTINFO_SN, 
                         PROXYCERTINFO_LN);
    i2d_PROXYCERTINFO(handle->proxy_cert_info, &pci_DER);

    /* set the extensions's critical value */
    pci_critical = 
        PROXYCERTINFO_get_restriction(handle->proxy_cert_info) ? 1 : 0;
    pci_ext = 
        X509_EXTENSION_create_by_NID(pci_ext, 
                                     pci_NID, 
                                     pci_critical, 
                                     pci_DER);

    /* get the list of extensions from the X509_REQ,
     * and add the PROXYCERTINFO extension to the list
     */
    extensions = X509_REQ_get_extensions(handle->req);
    sk_X509_EXTENSION_push(extensions, pci_ext);
    X509_REQ_add_extensions(handle->req, extensions);

    sk_X509_EXTENSION_free(extensions);
    X509_EXTENSION_free(pci_ext);

    return GLOBUS_SUCCESS;
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

    d2i_X509_REQ_bio(input_bio, request);
    if(
    
    return GLOBUS_SUCCESS;
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
    int                                 hours = 24;
    int                                 clock_skew_minutes = 5;
    EVP_MD *                            signing_algorithm,
    char *                              common_name;
    char *                              proxy_subject;
    X509 *                              new_pc;
    STACK_OF(X509_EXTENSION) *          pc_req_extensions;
    STACK_OF(X509_EXTENSION) *          pc_extensions;
    ASN1_UTCTIME *                      pc_notAfter;
    X509_EXTENSION *                    tmp_ext;
    long                                tmp_time;
    int                                 ext_num;
    int                                 res;
    
    res = X509_REQ_verify(handle->req, X509_REQ_get_pubkey(handle->req));

    if(res >= 0)
    {
        /* ERROR */
    }

    if(PROXYCERTINFO_get_restriction(handle->proxy_cert_info) != NULL)
    {
        common_name = RESTRICTED_PROXY_NAME;
    }
    else
    {
        common_name = PROXY_NAME;
    }

    new_pc = X509_new();

    if(new_proxycert == NULL)
    {
        /* ERROR */
    }

    X509_set_version(new_pc, 3);
    X509_set_serialNumber(new_pc, 
                          X509_get_serialNumber(issuer_credential->cert));



    X509_set_pubkey(new_pc, X509_REQ_get_pubkey(handle->req));

    X509_set_issuer_name(new_pc, 
                         X509_get_subject_name(issuer_credential->cert));

    /* create proxy subject name */
    
    
    
    /* add the extensions from the proxy cert request 
     * to the new proxy cert */    
    pc_req_extensions = X509_REQ_get_extensions(handle->req);
    ext_num = sk_X509_EXTENSION_num(req_extensions);
    for(ext_index = 0; ext_index < ext_num; ++ext_index)
    {
        tmp_ext = sk_X509_EXTENSION_value(pc_req_extensions, ext_index);
        X509_add_ext(new_pc, tmp_ext);
        X509_EXTENSION_free(tmp_ext);
    }
    sk_X509_EXTENSION_free(pc_req_extensions);

    return GLOBUS_SUCCESS;
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
    return GLOBUS_SUCCESS;
}
/* globus_gsi_proxy_assemble_cred */
/*@}*/


/* prints the status of a private key generating algorithm.
 * this could be modified to return more status information
 * if required.
 */
void globus_i_gsi_proxy_create_private_key_cb(BIO * output)
{
    BIO_printf(output, "+");
}

void globus_i_gsi_proxy_set_pc_times(
    X509 *                              new_pc,
    X509 *                              issuer_cred)
{
    ASN1_UTCTIME *                      pc_notAfter;
    int                                 skew_mins = 5;
    long                                hours = 24;
    time_t                              tmp_time;

    X509_gmtime_adj(X509_get_notBefore(new_pc), (- skew_mins * 60));
    
    tmp_time = time(NULL) + ((long) 60 * 60 * hours);

    /* check that issuer cert won't expire before new proxy cert */
    if(X509_cmp_time(X509_get_notAfter(issuer_cred->cert), tmp_time) < 0)
    {
        pc_notAfter = 
            ASN1_UTCTIME_dup(X509_get_notAfter(issuer_cred->cert));
    }
    else
    {
        X509_gmtime_adj(pc_notAfter, tmp_time);
    }
    
    X509_set_notAfter(new_pc, pc_notAfter);

    ASN1_UTCTIME_free(pc_notAfter);
}
    
