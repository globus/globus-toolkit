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

int pci_NID;

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

int                                     globus_i_gsi_proxy_debug_level;
FILE *                                  globus_i_gsi_proxy_debug_fstream;

/**
 * Module activation
 */
static
int
globus_l_gsi_proxy_activate(void)
{
    char *                              tmpstring;
    int                                 result;
    static char *                       _function_name_ =
        "globus_l_gsi_proxy_activate";

    /* create the proxycertinfo object identifier and add it to the
     * database of oids
     */
    pci_NID = OBJ_create(PROXYCERTINFO_OID, 
                         PROXYCERTINFO_SN, 
                         PROXYCERTINFO_LN);

    /* set the debug level */
    tmpstring = globus_module_getenv("GLOBUS_GSI_PROXY_DEBUG_LEVEL");
    
    if(tmpstring != GLOBUS_NULL)
    {
        globus_i_gsi_proxy_debug_level = atoi(tmpstring);

        if(globus_i_gsi_proxy_debug_level < 0)
        {
            globus_i_gsi_proxy_debug_level = 0;
        }
    }

    /* set the location for the debugging for the 
     * debugging output (file or stderr)
     */
    tmpstring = globus_module_getenv("GLOBUS_GSI_PROXY_DEBUG_FILE");
    if(tmpstring != GLOBUS_NULL)
    {
        globus_i_gsi_proxy_debug_fstream = fopen(tmpstring, "w");
        if(globus_i_gsi_proxy_debug_fstream == NULL)
        {
            result = GLOBUS_NULL;
            goto exit;
        }
    }
    else
    {
        /* if the env. var isn't set we use stderr */
        globus_i_gsi_proxy_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    result = globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_proxy_deactivate(void)
{
    int                                 result;
    static char *                       _function_name_ = 
        "globus_i_gsi_proxy_deactivate";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    OBJ_cleanup();

    result = globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;

    fclose(globus_i_gsi_proxy_debug_fstream);
    
    return result;
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
    int                                 pci_critical;
    int                                 pci_DER_length;

    int                                 key_bits;
    int                                 init_prime;
    RSA *                               rsa_key = NULL;
    BIO *                               stdout_bio = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_proxy_create_req";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
        
    /* create a stdout bio for sending key generation 
     * progress information */
    if((stdout_bio = BIO_new(BIO_s_file())) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_BIO,
            ("Couldn't initialize new BIO for writing to stdout"));
        goto done;
    }

    BIO_set_fp(stdout_bio, stdout, BIO_NOCLOSE);

    result = globus_gsi_proxy_handle_attrs_get_keybits(
        handle->attrs, & key_bits);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto free_bio;
    }

    result = globus_gsi_proxy_handle_attrs_get_init_prime(
        handle->attrs, &init_prime);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ);
        goto free_bio;
    }

    /* First, generate and setup private/public key pair */
    rsa_key = RSA_generate_key(key_bits, init_prime, 
                               (void (*)()) 
                               globus_i_gsi_proxy_create_private_key_cb, 
                               (char *) stdout_bio);
    if(rsa_key == NULL)
    {
        /* ERROR: RSA_generate_key errored */
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY, 
            ("Couldn't generate RSA key pair for proxy handle"));
        goto free_bio;
    }

    if(!EVP_PKEY_assign_RSA(handle->proxy_key, rsa_key))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PRIVATE_KEY,
            ("Could not set private key in proxy handle"));
        goto free_rsa;
    }

    if(!X509_REQ_set_version(handle->req, 0L))
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Could not set version of X509 request in proxy handle"));
        goto free_rsa;
    }

    if(!X509_REQ_set_pubkey(handle->req, handle->proxy_key))
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Couldn't set public key of X509 request in proxy handle"));
        goto free_rsa;
    }
       
    /* create the X509 extension from the PROXYCERTINFO */
    if(pci_NID == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            ("No valid PROXYCERTINFO numeric identifier found"));
        goto free_rsa;
    }

    /* openssl doesn't appear to have any error checking
     * for these i2d functions - so we just have to cross our fingers
     */
    pci_DER_length = i2d_PROXYCERTINFO(handle->proxy_cert_info, 
                                       (unsigned char **) &pci_DER);
    if(pci_DER_length < 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            ("Couldn't convert PROXYCERTINFO struct from internal"
             " to DER encoded form"));
        goto free_rsa;
    }

    pci_DER_string = ASN1_OCTET_STRING_new();
    if(pci_DER_string == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            ("Couldn't create new ASN.1 octet string for the DER encoding"
             " of a PROXYCERTINFO struct"));
        goto free_rsa;
    }
    
    pci_DER_string->data = pci_DER;
    pci_DER_string->length = pci_DER_length;

    /* set the extensions's critical value */
    pci_critical = 
        PROXYCERTINFO_get_restriction(handle->proxy_cert_info) ? 1 : 0;

    pci_ext = X509_EXTENSION_create_by_NID(& pci_ext, pci_NID, 
                                           pci_critical, pci_DER_string);
    if(pci_ext == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS,
            ("Couldn't create X509 extension list "
             "to hold PROXYCERTINFO extension"));
        goto free_pci_string;
    }

    /* get the list of extensions from the X509_REQ,
     * and add the PROXYCERTINFO extension to the list
     */

    extensions = X509_REQ_get_extensions(handle->req);
    if(extensions == NULL)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Couldn't get X509 request extensions"));
        goto free_pci_ext;
    }

    if(sk_X509_EXTENSION_push(extensions, pci_ext) == 0)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS,
            ("Couldn't add PROXYCERTINFO struct to stack of X509 extensions"));
        goto free_extensions;
    }

    if(X509_REQ_add_extensions(handle->req, extensions) == 0)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Couldn't add extensions to the X509 "
             "request in the proxy handle"));
        goto free_extensions;
    }
    /* write the request to the BIO */
    if(i2d_X509_REQ_bio(output_bio, handle->req) == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Couldn't convert X509 request from internal to"
             " DER encoded form"));
        goto free_extensions;
    }

    GLOBUS_I_GSI_PROXY_DEBUG_PRINT(3, "****** START X509_REQ ******\n");
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT_OBJECT(3, X509_REQ, handle->req);
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT(3, "******  END X509_REQ  ******\n");

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

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
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
    PROXYCERTINFO *                     pci = NULL;
    ASN1_OCTET_STRING *                 ext_data = NULL;
    globus_result_t                     result;

    static char *                       _function_name_ =
        "globus_gsi_proxy_inquire_req";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if(pci_NID == 0)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
            ("proxycertinfo oid is not initialized"));
        goto done;
    }
        
    if(d2i_X509_REQ_bio(input_bio, & request) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Couldn't convert X509_REQ struct from DER encoded "
             "to internal form"));
        goto done;
    }

    if((extensions = X509_REQ_get_extensions(request)) == NULL)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS,
            ("Couldn't get extensions from X509_REQ"));
        goto free_request;
    }
    
    /* we assume there's only one proxycertinfo extension */
    if((ext_index = X509v3_get_ext_by_NID(extensions, pci_NID, -1)) != -1)
    {
        if((tmp_ext = X509v3_get_ext(extensions, ext_index)) == NULL)
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS,
                ("Couldn't get proxycerinfo extension from extension stack"));
            goto free_extensions;
        }
        if((ext_data = X509_EXTENSION_get_data(tmp_ext)) == NULL)
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS, (NULL));
            goto free_tmp_ext;
        }

        if(d2i_PROXYCERTINFO(
            & pci, 
            & ext_data->data, 
            ext_data->length) == NULL)
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
                ("Couldn't convert PROXYCERTINFO struct from  "
                    "DER encoded to internal form"));
            goto free_ext_data;
        }

        if((handle->proxy_cert_info = PROXYCERTINFO_dup(pci)) == NULL)
        {
            
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
                ("Couldn't duplicate PROXYCERTINFO"));
            goto free_pci;
        }
    }

    GLOBUS_I_GSI_PROXY_DEBUG_PRINT(3, "****** START X509_REQ ******\n");
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT_OBJECT(3, X509_REQ, handle->req);
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT(3, "******  END X509_REQ  ******\n");
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT(3, "****** START PCI ******\n");
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT_OBJECT(3, PROXYCERTINFO, 
                                          handle->proxy_cert_info);
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT(3, "******  END PCI  ******\n");

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
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
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
 * The resulting signed certificate is written to the output_bio, along
 * with the new cert chain for that certificate.  The order of data written
 * to the bio is: N, N-1, ..., 0.  N being the newly signed certificate.
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
    STACK_OF(X509_EXTENSION) *          issuer_cert_chain = NULL;
    X509_EXTENSION *                    tmp_ext = NULL;
    EVP_PKEY *                          issuer_pkey = NULL;
    globus_result_t                     result;
    int                                 ext_num;
    int                                 ext_index;
    int                                 index;
    int                                 res;
    
    static char *                       _function_name_ =
        "globus_gsi_proxy_sign_req";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
    
    if(handle == NULL || issuer_credential == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle passed to function: %s", _function_name_));
        goto done;
    }
    
    res = X509_REQ_verify(handle->req, X509_REQ_get_pubkey(handle->req));
    if(res == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_REQ,
            ("Error verifying X509_REQ struct"));
        goto done;
    }
    
    if(PROXYCERTINFO_get_restriction(handle->proxy_cert_info) != NULL)
    {
        if(handle->is_limited == GLOBUS_TRUE)
        {
            result = GLOBUS_GSI_PROXY_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_PROXYCERTINFO,
                ("The proxy request has a restriction in the"
                 " proxycertinfo extension and the limited proxy bit is set"));
            goto done;
        }

        common_name = RESTRICTED_PROXY_NAME;
    }
    else if(handle->is_limited == GLOBUS_TRUE)
    {
        common_name = LIMITED_PROXY_NAME;
    }
    else
    {
        common_name = PROXY_NAME;
    }

    if((new_pc = X509_new()) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Couldn't initialize new X509"));
        goto done;
    }

    if((result = 
        globus_gsi_cred_get_cert(issuer_credential, &issuer_cert))
       != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CREDENTIAL);
        goto free_new_pc;
    }

    /* create proxy subject name */
    if((result = 
        globus_i_gsi_proxy_set_subject(new_pc, issuer_cert, 
                                       common_name)) != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto free_new_pc;
    }

    if(X509_set_version(new_pc, 3) == 0 ||
       X509_set_serialNumber(
           new_pc, 
           X509_get_serialNumber(issuer_cert)) == 0)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error setting serial number of X509"));
        goto free_new_pc;
    }

    result = globus_i_gsi_proxy_set_pc_times(new_pc, issuer_cert, 
                                             handle->attrs->clock_skew, 
                                             handle->attrs->time_valid);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_X509);
        goto free_new_pc;
    }
       
    if(!X509_set_pubkey(new_pc, X509_REQ_get_pubkey(handle->req)) ||
       !X509_set_serialNumber(new_pc, X509_get_serialNumber(issuer_cert)))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Couldn't set pubkey or serial number of X509 cert"));
        goto free_new_pc;
    }


    /* add the extensions from the proxy cert request 
     * to the new proxy cert */    
    if((pc_req_extensions = X509_REQ_get_extensions(handle->req)) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS,
            ("Couldn't get proxy cert req's X509 extensions"));
        goto free_new_pc;
    }

    ext_num = sk_X509_EXTENSION_num(pc_req_extensions);
    for(ext_index = 0; ext_index < ext_num; ++ext_index)
    {
        tmp_ext = sk_X509_EXTENSION_value(pc_req_extensions, ext_index);
        if(X509_add_ext(new_pc, tmp_ext, ext_index) == 0)
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509_EXTENSIONS,
                ("Couldn't add extension to proxy X509 cert"));
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
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CREDENTIAL);
        goto free_req_extensions;
    }
    
    /* right now if MD5 isn't requested as the signing algorithm,
     * we throw an error
     */
    if(EVP_MD_type(handle->attrs->signing_algorithm) != NID_md5)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("The signing algorithm: %s is not currently allowed."
             "\nUse MD5 to sign certificate requests",
             OBJ_nid2sn(EVP_MD_type(handle->attrs->signing_algorithm))));
        goto free_req_extensions;
    }
    
    if(!X509_sign(new_pc, issuer_pkey, handle->attrs->signing_algorithm))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error signing proxy cert"));
        goto free_req_extensions;
    }

    /* write out the X509 certificate in DER encoded format to the BIO */
    if(!i2d_X509_bio(output_bio, new_pc))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error converting X509 proxy cert from internal "
             "to DER encoded form"));
        goto free_req_extensions;
    }

    result = globus_gsi_cred_get_cert(issuer_credential, &issuer_cert);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CREDENTIAL);
        goto free_req_extensions;
    }

    if(!i2d_X509_bio(output_bio, issuer_cert))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error converting X509 proxy cert from internal "
             "to DER encoded form"));
    }

    result = globus_gsi_cred_get_cert_chain(issuer_credential, 
                                            &issuer_cert_chain);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CREDENTIAL);
        goto free_req_extensions;
    }

    for(index = 0; index < sk_X509_num(issuer_cert_chain); ++index)
    {
        if(!i2d_X509_bio(output_bio, sk_X509_value(issuer_cert_chain, index)))
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509,
                ("Error converting X509 cert in cert chain from "
                 "internal to DER encoded form"));
        }
    }
        
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT(3, "****** START SIGNED CERT ******\n");
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT_OBJECT(3, X509, new_pc);
    GLOBUS_I_GSI_PROXY_DEBUG_PRINT(3, "******  END SIGNED CERT  ******\n");

    result = GLOBUS_SUCCESS;
    
 free_req_extensions:
    sk_X509_EXTENSION_pop_free(pc_req_extensions, X509_EXTENSION_free);
 free_new_pc:
    X509_free(new_pc); 
 done:  
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
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

    static char *                       _function_name_ =
        "globus_gsi_proxy_assemble_cred";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    /* check to make sure params are ok */
    if(handle == NULL)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_HANDLE,
            ("NULL handle parameter passed to function: %s", _function_name_));
        goto done;
    }

    if(input_bio == NULL)
    {
        result = GLOBUS_GSI_PROXY_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_BIO,
            ("NULL bio passed to function: %s", _function_name_));
        goto done;
    }

    /* create the stack of issuer certs */
    if((issuer_certs = sk_X509_new_null()) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Couldn't create new X509 cert chain"));
        goto done;
    }

    /* get the signed proxy cert from the BIO */
    if(!d2i_X509_bio(input_bio, &signed_cert))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Couldn't convert X509 proxy cert from "
             "DER encoded to internal form"));
        goto free_issuer_certs;
    }

    /* get all the signing certificates in the chain from the BIO */
    while(!BIO_eof(input_bio))
    {
        if(!d2i_X509_bio(input_bio, &tmp_cert))
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509,
                ("Couldn't convert X509 cert from "
                 "DER encoded to internal form"));
            goto free_tmp_cert;
        }
        
        sk_X509_push(issuer_certs, tmp_cert);
        X509_free(tmp_cert);
    }
    
    result = globus_gsi_cred_handle_attrs_init(&cred_handle_attrs);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE_ATTRS);        
        goto free_signed_cert;
    }

    result = globus_gsi_cred_handle_init(proxy_credential, 
                                         cred_handle_attrs);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE);
        goto free_signed_cert;
    }

    result = globus_gsi_cred_set_cert(*proxy_credential, signed_cert);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE);
        goto free_signed_cert;
    }

    result = globus_gsi_cred_set_key(*proxy_credential, handle->proxy_key);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE);
        goto free_signed_cert;
    }

    result = globus_gsi_cred_set_cert_chain(*proxy_credential, issuer_certs);
    if(result != GLOBUS_SUCCESS)
    {
        result = GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_PROXY_ERROR_WITH_CRED_HANDLE);
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
    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
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

    static char *                       _function_name_ =
        "globus_l_gsi_proxy_get_base_name";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;
    
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

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* @} */


/* INTERNAL FUNCTIONS */

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
    static char *                       _function_name_ =
        "globus_i_gsi_proxy_create_private_key_cb";
    
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    BIO_printf(output, ".");

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
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
    globus_result_t                     result;
    ASN1_UTCTIME *                      pc_notAfter = NULL;
    time_t                              tmp_time;

    static char *                       _function_name_ =
        "globus_i_gsi_proxy_set_pc_times";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    /* adjust for the allowable skew */
    if(X509_gmtime_adj(X509_get_notBefore(new_pc), (- skew_allowable)) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error adjusting the allowable time skew for proxy"));
        goto exit;
    }
    
    tmp_time = time(NULL) + ((long) 60 * time_valid);

    /* check that issuer cert won't expire before new proxy cert */
    if(X509_cmp_time(X509_get_notAfter(issuer_cert), & tmp_time) < 0)
    {
        if((pc_notAfter = 
            M_ASN1_UTCTIME_dup(X509_get_notAfter(issuer_cert))) == NULL)
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509,
                ("Error copying issuer certificate of proxy"));
            goto exit;
        }
    }
    else
    {
        if(X509_gmtime_adj(pc_notAfter, tmp_time) == NULL)
        {
            result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
                GLOBUS_GSI_PROXY_ERROR_WITH_X509,
                ("Error adjusting X509 proxy cert's expiration time"));
            goto free_pc_notafter;
        }
    }
    
    if(!X509_set_notAfter(new_pc, pc_notAfter))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error setting X509 proxy cert's expiration"));
        goto free_pc_notafter;
    }

    result = GLOBUS_SUCCESS;

 free_pc_notafter:
    
    if(pc_notAfter != NULL)
    {
        ASN1_UTCTIME_free(pc_notAfter);
    }

 exit:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
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

    static char *                       _function_name_ = 
        "globus_i_gsi_proxy_set_subject";

    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    if((pc_name = X509_NAME_dup(X509_get_subject_name(issuer_cert))) == NULL)
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error copying subject name of proxy cert"));
        goto done;
    }
       
    if((pc_name_entry = 
       X509_NAME_ENTRY_create_by_NID(& pc_name_entry, NID_commonName,
                                     V_ASN1_APP_CHOOSE,
                                     (unsigned char *) common_name,
                                     -1)) == NULL)
    {
        
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error creating NAME ENTRY of type common name"));
        goto free_pc_name;
    }

    if(!X509_NAME_add_entry(pc_name, pc_name_entry,
                            X509_NAME_entry_count(pc_name), 0) ||
       !X509_set_subject_name(new_pc, pc_name))
    {
        result = GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(
            GLOBUS_GSI_PROXY_ERROR_WITH_X509,
            ("Error setting common name of subject in proxy cert"));
        goto free_pc_name_entry;
    }
    
    result = GLOBUS_SUCCESS;

 free_pc_name_entry:
    X509_NAME_ENTRY_free(pc_name_entry);
 free_pc_name:
    X509_NAME_free(pc_name);
 done:

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return result;
}

char *
globus_i_gsi_proxy_create_string(
    const char *                        format,
    ...)
{
    va_list                             ap;
    int                                 len = 128;
    int                                 length;
    char *                              error_string;
    static char *                       _function_name_ =
        "globus_i_gsi_proxy_create_error_string";
    
    GLOBUS_I_GSI_PROXY_DEBUG_ENTER;

    globus_libc_lock();
    
    va_start(ap, format);

    if((error_string = globus_malloc(len)) == NULL)
    {
        return NULL;
    }

    while(1)
    {
        length = vsnprintf(error_string, len, format, ap);
        if(length > -1 && length < len)
        {
            break;
        }

        if(length > -1)
        {
            len = length + 1;
        }
        else
        {
            len *= 2;
        }

        if((error_string = realloc(error_string, len)) == NULL)
        {
            return NULL;
        }
    }

    va_end(ap);

    globus_libc_unlock();

    GLOBUS_I_GSI_PROXY_DEBUG_EXIT;
    return error_string;
}

#endif
