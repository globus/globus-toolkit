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
    ASN1_OCTET_STRING *                 pci_DER_string;
    int                                 pci_NID;
    int                                 pci_critical;
    int                                 pci_DER_length;

    int                                 key_bits = 1024;
    RSA *                               rsa_key;
    BIO *                               stdout_bio;


    /* create a stdout bio for sending key generation 
     * progress information */
    stdout_bio = BIO_new(BIO_s_file());
    BIO_set_fp(stdout_bio, stdout, BIO_NOCLOSE);

    /* First, generate and setup private/public key pair */
    rsa_key = RSA_generate_key(key_bits, PRIME_START, 
                               (void (*)()) 
                               globus_i_gsi_proxy_create_private_key_cb, 
                               (char *) stdout_bio);

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

    /* create the X509 extension from the PROXYCERTINFO */
    pci_NID = OBJ_create(PROXYCERTINFO_OID, 
                         PROXYCERTINFO_SN, 
                         PROXYCERTINFO_LN);
    pci_DER_length = i2d_PROXYCERTINFO(handle->proxy_cert_info, 
                          (unsigned char **) &pci_DER);

    pci_DER_string = ASN1_OCTET_STRING_new();
    pci_DER_string->data = pci_DER;
    pci_DER_string->length = pci_DER_length;

    /* set the extensions's critical value */
    pci_critical = 
        PROXYCERTINFO_get_restriction(handle->proxy_cert_info) ? 1 : 0;
    pci_ext = 
        X509_EXTENSION_create_by_NID(& pci_ext, 
                                     pci_NID, 
                                     pci_critical, 
                                     pci_DER_string);

    /* get the list of extensions from the X509_REQ,
     * and add the PROXYCERTINFO extension to the list
     */
    extensions = X509_REQ_get_extensions(handle->req);
    sk_X509_EXTENSION_push(extensions, pci_ext);
    X509_REQ_add_extensions(handle->req, extensions);

    /* write the request to the BIO */
    i2d_X509_REQ_bio(output_bio, handle->req);

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

    d2i_X509_REQ_bio(input_bio, & request);
/*      if( */
    
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
    EVP_MD *                            signing_algorithm;
    char *                              common_name;
    char *                              proxy_subject;
    X509 *                              new_pc;
    STACK_OF(X509_EXTENSION) *          pc_req_extensions;
    STACK_OF(X509_EXTENSION) *          pc_extensions;
    ASN1_UTCTIME *                      pc_notAfter;
    X509_EXTENSION *                    tmp_ext;
    EVP_PKEY *                          issuer_pkey;
    long                                tmp_time;
    int                                 ext_num;
    int                                 ext_index;
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

    if(new_pc == NULL)
    {
        /* ERROR */
    }

    /* create proxy subject name */
    globus_i_gsi_proxy_set_subject(new_pc, issuer_credential->cert, common_name);

    X509_set_version(new_pc, 3);
    X509_set_serialNumber(new_pc, 
                          X509_get_serialNumber(issuer_credential->cert));

    globus_i_gsi_proxy_set_pc_times(new_pc, issuer_credential->cert);

    X509_set_pubkey(new_pc, X509_REQ_get_pubkey(handle->req));

    X509_set_issuer_name(new_pc, 
                         X509_get_subject_name(issuer_credential->cert));

    /* add the extensions from the proxy cert request 
     * to the new proxy cert */    
    pc_req_extensions = X509_REQ_get_extensions(handle->req);
    ext_num = sk_X509_EXTENSION_num(pc_req_extensions);
    for(ext_index = 0; ext_index < ext_num; ++ext_index)
    {
        tmp_ext = sk_X509_EXTENSION_value(pc_req_extensions, ext_index);
        X509_add_ext(new_pc, tmp_ext, ext_index);
        X509_EXTENSION_free(tmp_ext);
    }
    sk_X509_EXTENSION_free(pc_req_extensions);

    /* sign the new certificate */
    globus_gsi_cred_get_key(issuer_credential, &issuer_pkey);
    if(!X509_sign(new_pc, issuer_pkey, EVP_md5()))
    {
        /* ERROR */
    }

    /* write out the X509 certificate in DER encoded format to the BIO */
    i2d_X509_bio(output_bio, new_pc);

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
void 
globus_i_gsi_proxy_create_private_key_cb(
    BIO *                               output)
{
    BIO_printf(output, "+");
}

globus_result_t 
globus_i_gsi_proxy_set_pc_times(
    X509 *                              new_pc,
    X509 *                              issuer_cert)
{
    ASN1_UTCTIME *                      pc_notAfter;
    int                                 skew_mins = 5;
    long                                hours = 24;
    time_t                              tmp_time;

    X509_gmtime_adj(X509_get_notBefore(new_pc), (- skew_mins * 60));
    
    tmp_time = time(NULL) + ((long) 60 * 60 * hours);

    /* check that issuer cert won't expire before new proxy cert */
    if(X509_cmp_time(X509_get_notAfter(issuer_cert), & tmp_time) < 0)
    {
        pc_notAfter = 
            M_ASN1_UTCTIME_dup(X509_get_notAfter(issuer_cert));
    }
    else
    {
        X509_gmtime_adj(pc_notAfter, tmp_time);
    }
    
    X509_set_notAfter(new_pc, pc_notAfter);

    ASN1_UTCTIME_free(pc_notAfter);

    return GLOBUS_SUCCESS;
}
    
globus_result_t 
globus_i_gsi_proxy_set_subject(
    X509 *                              new_pc,
    X509 *                              issuer_cert,
    char *                              common_name)

{

    X509_NAME *                         pc_name;
    X509_NAME_ENTRY *                   pc_name_entry;

    if((pc_name = X509_NAME_dup(X509_get_subject_name(issuer_cert))) == NULL)
    {
        /* ERROR */
    }
       
    if((pc_name_entry = 
       X509_NAME_ENTRY_create_by_NID(& pc_name_entry, NID_commonName,
                                     V_ASN1_APP_CHOOSE,
                                     (unsigned char *) common_name,
                                     -1)) == NULL)
    {
        /* ERROR */
    }

    if(!X509_NAME_add_entry(pc_name,
                            pc_name_entry,
                            X509_NAME_entry_count(pc_name),
                            0))
    {
        /* ERROR */
    }
    
    X509_set_subject_name(new_pc, pc_name);

    X509_NAME_free(pc_name);
    X509_NAME_ENTRY_free(pc_name_entry);
    
    return GLOBUS_SUCCESS;
}
