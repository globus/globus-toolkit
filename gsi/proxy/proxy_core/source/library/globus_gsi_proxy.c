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

#define GLOBUS_GSI_PROXY_CREATE_REQ_FREE \
    BIO_free(stdout_bio); \
    RSA_free(rsa_key); \
    X509_EXTENSION_free(pci_ext); \
    sk_X509_EXTENSION_free(extensions); \
    ASN1_OCTET_STRING_free(pci_DER_string);

    /* create a stdout bio for sending key generation 
     * progress information */
    if((stdout_bio = BIO_new(BIO_s_file())) == NULL)
    {
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CREATING_STDOUT_BIO);
    }

    BIO_set_fp(stdout_bio, stdout, BIO_NOCLOSE);

    globus_gsi_proxy_handle_attrs_get_keybits(handle->attrs, &key_bits);
    globus_gsi_proxy_handle_attrs_get_init_prime(handle->attrs, &init_prime);

    /* First, generate and setup private/public key pair */
    ;

    if((rsa_key = RSA_generate_key(key_bits, init_prime, 
                                   (void (*)()) 
                                   globus_i_gsi_proxy_create_private_key_cb, 
                                   (char *) stdout_bio)) == NULL)
    {
        /* ERROR: RSA_generate_key errored - probably ran out of memory */
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_GENERATING_RSA_KEYS);
    }

    if(EVP_PKEY_assign_RSA(handle->proxy_key, rsa_key))
    {
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_ASSIGNING_RSA_KEY);
    }

    if(X509_REQ_set_version(handle->req, 0L))
    {
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_NULL_X509_REQ);
    }

    X509_REQ_set_pubkey(handle->req, handle->proxy_key);

    /* create the X509 extension from the PROXYCERTINFO */
    if((pci_NID = OBJ_create(PROXYCERTINFO_OID, 
                             PROXYCERTINFO_SN, 
                             PROXYCERTINFO_LN)) == 0)
    {
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CREATING_OID);
    }

    /* openssl doesn't appear to have any error checking
     * for these i2d functions - so we just have to cross our fingers
     */
    pci_DER_length = i2d_PROXYCERTINFO(handle->proxy_cert_info, 
                          (unsigned char **) &pci_DER);

    if((pci_DER_string = ASN1_OCTET_STRING_new()) == NULL)
    {
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CREATING_OCTET_STRING);
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
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CREATING_X509_EXTENSION);
    }

    /* get the list of extensions from the X509_REQ,
     * and add the PROXYCERTINFO extension to the list
     */

    if((extensions = X509_REQ_get_extensions(handle->req)) == NULL)
    {

        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_GETTING_EXTENSIONS_FROM_REQ);
    }

    if(sk_X509_EXTENSION_push(extensions, pci_ext) == 0)
    {
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_X509_EXTENSION_STACK_PUSH);
    }

    if(X509_REQ_add_extensions(handle->req, extensions) == 0)
    {
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_ADDING_EXTENSIONS_TO_REQ);
    }
    /* write the request to the BIO */
    if(i2d_X509_REQ_bio(output_bio, handle->req) == 0)
    {
        GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_TO_DER_FORM);
    }

    GLOBUS_GSI_PROXY_CREATE_REQ_FREE;
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
    STACK_OF(X509_EXTENSION) *          extensions = NULL;
    X509_EXTENSION *                    tmp_ext = NULL;
    int                                 ext_index;
    int                                 pci_NID;
    PROXYCERTINFO *                     pci = NULL;
    ASN1_OCTET_STRING *                 ext_data = NULL;

#define GLOBUS_GSI_PROXY_INQUIRE_REQ_FREE \
    X509_REQ_free(request); \
    sk_X509_EXTENSION_free(extensions); \
    X509_EXTENSION_free(tmp_ext); \
    PROXYCERTINFO_free(pci); \
    ASN1_OCTET_STRING_free(ext_data);


    if(d2i_X509_REQ_bio(input_bio, & request) == NULL)
    {
        GLOBUS_GSI_PROXY_INQUIRE_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_TO_INTERNAL_FORM);
    }

    if((extensions = X509_REQ_get_extensions(request)) == NULL)
    {
        GLOBUS_GSI_PROXY_INQUIRE_REQ_FREE;
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_GETTING_EXTENSIONS_FROM_REQ);
    }
    
    if((pci_NID = OBJ_create(PROXYCERTINFO_OID, 
                             PROXYCERTINFO_SN, 
                             PROXYCERTINFO_LN)) == 0)
    {
        GLOBUS_GSI_PROXY_INQUIRE_REQ_FREE;
        return GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_COULD_NOT_CREATE_PCI_OBJECT);
    }
        
    /* we assume there's only one proxycertinfo extension */
    if((ext_index = X509v3_get_ext_by_NID(extensions, pci_NID, -1)) != -1)
    {

        if((tmp_ext = X509v3_get_ext(extensions, ext_index)) == NULL ||
           (ext_data = X509_EXTENSION_get_data(tmp_ext)) == NULL)
        {
            GLOBUS_GSI_PROXY_INQUIRE_REQ_FREE;
            return GLOBUS_GSI_PROXY_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_BAD_EXTENSION);
        }

        d2i_PROXYCERTINFO(& pci, & ext_data->data, ext_data->length);
        if((handle->proxy_cert_info = PROXYCERTINFO_dup(pci)) == NULL)
        {
            GLOBUS_GSI_PROXY_INQUIRE_REQ_FREE;
            return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_DUPLICATING_OBJECT);
        }
    }

    GLOBUS_GSI_PROXY_INQUIRE_REQ_FREE;
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
    EVP_MD *                            signing_algorithm = NULL;
    char *                              common_name;
    char *                              proxy_subject;
    X509 *                              new_pc = NULL;
    STACK_OF(X509_EXTENSION) *          pc_req_extensions =  NULL;
    STACK_OF(X509_EXTENSION) *          pc_extensions = NULL;
    ASN1_UTCTIME *                      pc_notAfter = NULL;
    X509_EXTENSION *                    tmp_ext = NULL;
    EVP_PKEY *                          issuer_pkey = NULL;
    globus_result_t *                   return_error = NULL
    long                                tmp_time;
    int                                 ext_num;
    int                                 ext_index;
    int                                 res;
    
#define GLOBUS_GSI_PROXY_SIGN_REQ_FREE \
    EVP_MD_free(signing_algorithm); \
    X509_free(new_pc); \
    sk_X509_EXTENSION_free(pc_req_extensions); \
    sk_X509_EXTENSION_free(pc_extensions); \
    ASN1_UTCTIME_free(pc_notAfter); \
    X509_EXTENSION_free(tmp_ext); \
    EVP_PKEY_free(issuer_pkey);
    
    if((res = 
        X509_REQ_verify(handle->req, X509_REQ_get_pubkey(handle->req)) == 0)
    {
        GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_X509_REQUEST);
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
        GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CREATING_ASN1_OBJECT);
    }

    /* create proxy subject name */
    if((return_error = 
       globus_i_gsi_proxy_set_subject(new_pc, issuer_credential->cert, 
                                      common_name)) != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
        return return_error;
    }

    if(X509_set_version(new_pc, 3) == 0 ||
       X509_set_serialNumber(
           new_pc, 
           X509_get_serialNumber(issuer_credential->cert)) == 0)
    {
        GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_X509);
    }

    if((return_error = 
        globus_i_gsi_proxy_set_pc_times(
            new_pc, 
            issuer_credential->cert, 
            handle->clock_skew, 
            handle->time_valid)) != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
        return return_error;
    }
       
    if(X509_set_pubkey(new_pc, X509_REQ_get_pubkey(handle->req)) == 0 ||
       X509_set_serialNumber(
           new_pc, 
           X509_get_serialNumber(issuer_credential->cert)) == 0)
    {
        GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_X509);
    }


    /* add the extensions from the proxy cert request 
     * to the new proxy cert */    
    pc_req_extensions = X509_REQ_get_extensions(handle->req);
    ext_num = sk_X509_EXTENSION_num(pc_req_extensions);
    for(ext_index = 0; ext_index < ext_num; ++ext_index)
    {
        tmp_ext = sk_X509_EXTENSION_value(pc_req_extensions, ext_index);
        if(X509_add_ext(new_pc, tmp_ext, ext_index) == 0)
        {
            GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
            return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_BAD_X509_EXTENSIONS);
        }
        X509_EXTENSION_free(tmp_ext);
        tmp_ext = NULL;
    }
    sk_X509_EXTENSION_free(pc_req_extensions);
    pc_req_extensions = NULL;

    /* sign the new certificate */
    globus_gsi_cred_get_key(issuer_credential, &issuer_pkey);
    if(!X509_sign(new_pc, issuer_pkey, handle->signing_algorithm))
    {
        GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CANT_SIGN_X509);
    }

    /* write out the X509 certificate in DER encoded format to the BIO */
    if(!i2d_X509_bio(output_bio, new_pc))
    {
        GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CONVERTING_TO_DER_FORM);
    }
    
    GLOBUS_GSI_PROXY_SIGN_REQ_FREE;
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
    BIO_printf(output, "+");
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

    /* adjust for the allowable skew */
    if(X509_gmtime_adj(X509_get_notBefore(new_pc), (- skew_allowable)) == NULL)
    {
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_X509);
    }
    
    tmp_time = time(NULL) + ((long) 60 * time_valid);

    /* check that issuer cert won't expire before new proxy cert */
    if(X509_cmp_time(X509_get_notAfter(issuer_cert), & tmp_time) < 0)
    {
        if((pc_notAfter = 
            M_ASN1_UTCTIME_dup(X509_get_notAfter(issuer_cert))) == NULL)
        {
            return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_DUPLICATING_OBJECT);
        }
    }
    else
    {
        if(X509_gmtime_adj(pc_notAfter, tmp_time) == NULL)
        {
            ASN1_UTCTIME_free(pc_notAfter);
            return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_BAD_X509);
        }
    }
    

    if(X509_set_notAfter(new_pc, pc_notAfter) == NULL)
    {
        ASN1_UTCTIME_free(pc_notAfter);
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_X509);
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

#define GLOBUS_I_GSI_PROXY_SET_SUBJECT_FREE \
    X509_NAME_free(pc_name); \
    X509_NAME_ENTRY_free(pc_name);

    if((pc_name = X509_NAME_dup(X509_get_subject_name(issuer_cert))) == NULL)
    {
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_DUPLICATING_OBJECT);
    }
       
    if((pc_name_entry = 
       X509_NAME_ENTRY_create_by_NID(& pc_name_entry, NID_commonName,
                                     V_ASN1_APP_CHOOSE,
                                     (unsigned char *) common_name,
                                     -1)) == NULL)
    {
        GLOBUS_I_GSI_PROXY_SET_SUBJECT_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_CREATING_ASN1_OBJECT);
    }

    if(!X509_NAME_add_entry(pc_name,
                            pc_name_entry,
                            X509_NAME_entry_count(pc_name),
                            0) ||
       !X509_set_subject_name(new_pc, pc_name))
    {
        GLOBUS_I_GSI_PROXY_SET_SUBJECT_FREE;
        return GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_BAD_X509);
    }
    
    GLOBUS_I_GSI_PROXY_SET_SUBJECT_FREE;
    return GLOBUS_SUCCESS;
}

#endif
