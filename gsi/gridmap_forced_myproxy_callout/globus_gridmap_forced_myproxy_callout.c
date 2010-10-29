/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "gssapi.h"
#include "globus_gss_assist.h"
#include "globus_gridmap_callout_error.h"

#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <openssl/ssl.h>

extern int xmlLoadExtDtdDefaultValue;

#define SAML_NS_URN "urn:oasis:names:tc:SAML:2.0:assertion"

/* 1.2.3.4.4.3.2.1.7.8 */
static const gss_OID_desc               forced_myproxy_token_extension_oid =
    {9, "\x2a\x03\x04\x04\x03\x02\x01\x07\x08"}; 
static const gss_OID_desc               forced_myproxy_cert_chain_oid =
    {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x08"}; 



static
globus_result_t
ggfm_base64_decode(
    char *                              in,
    unsigned char **                    out,
    int *                               out_len)
{
    globus_result_t                     result;
    BIO *                               b64;
    BIO *                               bm;
    int                                 len;
    unsigned char *                     buf;
    
    if(!in)
    {
        goto err;
    }
        
    len = strlen(in);
    buf = malloc(len);
    
    b64 = BIO_new(BIO_f_base64());
    if(!b64)
    {
        goto err;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bm = BIO_new_mem_buf(in, len);
    if(!bm)
    {
        goto err;
    }
    
    bm = BIO_push(b64, bm);
    
    len = BIO_read(bm, buf, len);
    
    if(len <= 0)
    {
        goto err;
    }
    
    *out = buf;
    *out_len = len;

    BIO_free_all(bm);
    return GLOBUS_SUCCESS;

err:
    GLOBUS_GRIDMAP_CALLOUT_ERROR(
        result,
        GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
        ("error decoding token."));
    
    return result;
}

static
globus_result_t
ggfm_parse_assertion(
    char *                              assertion,
    char **                             out_token)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    char *                              token = NULL;
    xmlDocPtr                           doc;
    xmlNodePtr                          cur;
    
    
    xmlInitParser();
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
    
    doc = xmlParseMemory(assertion, strlen(assertion));
    if(doc == NULL)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("invalid assertion format"));
        goto err;
    }
        
    cur = xmlDocGetRootElement(doc);
        
    if(cur == NULL ||
        xmlSearchNsByHref(doc, cur, (const xmlChar *) SAML_NS_URN) == NULL ||
        xmlStrcmp(cur->name, (const xmlChar *) "Assertion"))
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("invalid assertion format"));
        goto err;
    }
    
    cur = cur->children;
    
    while(cur && !token)
    {
        if(!xmlStrcmp(cur->name, (const xmlChar *) "AttributeStatement"))
        {
            cur = cur->children;
            continue;
        }
        else if(!xmlStrcmp(cur->name, (const xmlChar *) "Attribute") &&
            !xmlStrcmp(cur->properties->name, (const xmlChar *) "Name") &&
            !xmlStrcmp(cur->properties->children->content, (const xmlChar *) "Assertion"))
        {
            cur = cur->children;
            continue;
        }
        else if(!xmlStrcmp(cur->name, (const xmlChar *) "AttributeValue") &&
            cur->children->content != NULL)
        {
            token = globus_libc_strdup((char *) cur->children->content);
        }
        else
        {
            cur = cur->next;
        }
    }
    
    if(!token)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("no valid myproxy token assertion found"));

        goto err;
    }
    
    *out_token = token;
    
err:
    if(doc)
    {
        xmlFreeDoc(doc);
    }
    xmlCleanupParser();

    return result;
}


static
globus_result_t
ggfm_extract_cert_from_chain(
    gss_ctx_id_t                        context,
    int                                 cert_index,
    X509 **                             out_cert)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_set_t                    cert_chain_buffers = 0;
    X509 *                              cert;
    const unsigned char *               ptr;
    
    major_status = gss_inquire_sec_context_by_oid(
        &minor_status,
        context,
        (gss_OID) &forced_myproxy_cert_chain_oid,
        &cert_chain_buffers);

    if(GSS_ERROR(major_status))
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("can't extract cert chain"));
        goto err;
    }
    
    if(cert_chain_buffers->count <= cert_index)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("too few certs in chain"));
        goto err;
    }

    ptr = cert_chain_buffers->elements[cert_index].value;
    cert = d2i_X509(
        NULL, 
        &ptr, 
        cert_chain_buffers->elements[cert_index].length);
    if(cert == NULL)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("can't extract cert from chain"));
        goto err;
    }
    
    *out_cert = cert;

err:
    if(cert_chain_buffers)
    {
        gss_release_buffer_set(&minor_status, &cert_chain_buffers);
    }
    
    return result;
}

static
globus_result_t
ggfm_extract_assertion(
    gss_ctx_id_t                        context,
    char **                             out_assertion)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_set_t                    extension_buffer = 0;
    const unsigned char *               encoded_assertion = NULL;
    unsigned char *                     assertion = NULL;
    char *                              decoded_assertion = NULL;
    int                                 assertion_len;
    ASN1_UTF8STRING *                   asn1_str;

    major_status = gss_inquire_sec_context_by_oid(
        &minor_status,
        context, 
        (gss_OID) &forced_myproxy_token_extension_oid, 
        &extension_buffer);
    if(major_status != GSS_S_COMPLETE)
    {        
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("error checking for authz extension."));    
        goto err;
    }
    
    if(extension_buffer->count == 0)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("no assertion extension found."));
        goto err;
    }

    if(extension_buffer->elements[0].length && extension_buffer->elements[0].value)
    {
        assertion = malloc(extension_buffer->elements[0].length + 1);
        memcpy(assertion,
                extension_buffer->elements[0].value,
                extension_buffer->elements[0].length);
        assertion_len = extension_buffer->elements[0].length;
        assertion[assertion_len] = '\0';
    }
    
    if(!assertion)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("authz extension found, but no assertion."));
        goto err;
    }
    
    encoded_assertion = assertion;
    asn1_str = d2i_ASN1_UTF8STRING(NULL, &encoded_assertion, assertion_len);
    if(!asn1_str)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("improperly encoded assertion found."));
        goto err;        
    }

    decoded_assertion = malloc(asn1_str->length + 1);
    memcpy(decoded_assertion, asn1_str->data, asn1_str->length);
    decoded_assertion[asn1_str->length] = 0;
    ASN1_UTF8STRING_free(asn1_str);
    globus_free(assertion);
    
    *out_assertion = decoded_assertion;
    
err:
    if(extension_buffer)
    {
        gss_release_buffer_set(&minor_status, &extension_buffer);
    }

    return result;   
}


static
globus_result_t
ggfm_load_cert_from_file(
    char *                              certfile,
    X509 **                             out_cert)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    FILE *                              certfp = NULL;
    X509 *                              cert;
   
    certfp = fopen(certfile, "r");
    if(!certfp)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("error opening file."));
        goto err;
    }
    
    cert = PEM_read_X509(certfp, 0, 0, 0);
    if(!*out_cert)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("file does not contain a valid PEM certificate."));
        goto err;
    }
    
    *out_cert = cert;
    
err:
    if(certfp)
    {
        fclose(certfp);
    }
    
    return result;
}


static
globus_result_t
ggfm_verify_signature(
    X509 *                              issuer_cert,
    X509 *                              verifier_cert,
    unsigned char *                     signature,
    int                                 signature_len)
{
    globus_result_t                     result = GLOBUS_FAILURE;
    EVP_MD_CTX                          mdctx;
    int                                 verified = 0;
    char *                              modulus = NULL;                     
    EVP_PKEY *                          issuer_pkey = NULL;
    EVP_PKEY *                          verifier_pkey = NULL;

    verifier_pkey = X509_get_pubkey(verifier_cert);
    if(!verifier_pkey)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("can't get verifier public key."));
        goto err;
    }

    issuer_pkey = X509_get_pubkey(issuer_cert);
    if(issuer_pkey == NULL)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("can't get issuer public key."));
        goto err;
    }

    /*  will this need to be configurable?
     
     OpenSSL_add_all_digests();
     md = EVP_get_digestbyname("sha256");
    */
            
    EVP_MD_CTX_init(&mdctx);

    EVP_VerifyInit_ex(&mdctx, EVP_sha256(), NULL);

    modulus = BN_bn2hex(issuer_pkey->pkey.rsa->n);

    EVP_VerifyUpdate(&mdctx, modulus, strlen(modulus));

    verified = EVP_VerifyFinal(
        &mdctx, signature, signature_len, verifier_pkey);
    
    EVP_MD_CTX_cleanup(&mdctx);

    if(!verified)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("verification of signature failed"));
        goto err;
    }
    result = GLOBUS_SUCCESS;
    
err:
    if(issuer_pkey)
    {
        EVP_PKEY_free(issuer_pkey);
    }
    if(verifier_pkey)
    {
        EVP_PKEY_free(verifier_pkey);
    }
    
    return result;
}


globus_result_t
globus_gridmap_forced_myproxy_callout(
    va_list                             ap)
{
    gss_ctx_id_t                        context;
    char *                              service;
    char *                              desired_identity;
    char *                              identity_buffer;
    char *                              local_identity;
    char *                              subject = NULL;
    unsigned int                        buffer_length;
    globus_result_t                     result = GLOBUS_SUCCESS;
    gss_name_t                          peer;
    gss_buffer_desc                     peer_name_buffer;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 rc;
    int                                 initiator;
    char *                              assertion = NULL;
    char *                              token = NULL;
    unsigned char *                     sigbuf = NULL;
    int                                 siglen;
    X509 *                              issuer_cert;
    X509 *                              verify_cert;
    char *                              verify_cert_file;

    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    rc = globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    rc = globus_module_activate(GLOBUS_GRIDMAP_CALLOUT_ERROR_MODULE);
    
    context = va_arg(ap, gss_ctx_id_t);
    service = va_arg(ap, char *);
    desired_identity = va_arg(ap, char *);
    identity_buffer = va_arg(ap, char *);
    buffer_length = va_arg(ap, unsigned int);

    verify_cert_file = globus_libc_getenv("GLOBUS_GRIDMAP_FORCED_MYPROXY_CERT");
    if(!verify_cert_file)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("server configuration error.  "
             "GLOBUS_GRIDMAP_FORCED_MYPROXY_CERT must be set."));
        goto error;
    }


    /* extract assertion */    
    result = ggfm_extract_assertion(context, &assertion);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("Unable to extract a myproxy assertion extenstion from the user credentials."));
        goto error;
    }    

    /* parse assertion, pull out signature */
    result = ggfm_parse_assertion(assertion, &token);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("Unable to parse the assertion extension."));
        goto error;
    }    

    /* base64 decode signature */
    result = ggfm_base64_decode(token, &sigbuf, &siglen);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("Could not base64 decode the assertion token."));
        goto error;
    }    

    /* extract issuer cert */
    result = ggfm_extract_cert_from_chain(context, 1, &issuer_cert);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("Could not extract issuer cert from user credentials."));
        goto error;
    }    

    /* load ca cert for verify */   
    result = ggfm_load_cert_from_file(verify_cert_file, &verify_cert);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("Server configuration problem.  Unable to load myproxy verification cert."));
        goto error;
    }    

    /* verify signature */
    result = ggfm_verify_signature(issuer_cert, verify_cert, sigbuf, siglen);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("Unable to verify a myproxy token."));
        goto error;
    }    


    /* proceed with gridmap lookup */
    if(subject == NULL)
    {
        major_status = gss_inquire_context(&minor_status,
                                           context,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           &initiator,
                                           GLOBUS_NULL);
    
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
            goto error;
        }
    
        major_status = gss_inquire_context(&minor_status,
                                           context,
                                           initiator ? GLOBUS_NULL : &peer,
                                           initiator ? &peer : GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL);
    
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
            goto error;
        }
        
        major_status = gss_display_name(&minor_status,
                                        peer,
                                        &peer_name_buffer,
                                        GLOBUS_NULL);
        
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
            gss_release_name(&minor_status, &peer);
            goto error;
        }
        

        subject = globus_libc_strdup(peer_name_buffer.value);
        gss_release_buffer(&minor_status, &peer_name_buffer);
        gss_release_name(&minor_status, &peer);

    }
    
    if(desired_identity == NULL)
    {
        rc = globus_gss_assist_gridmap(subject, &local_identity);
        if(rc != 0)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
                ("Could not map %s\n", subject));
            goto error;
        }

        if(strlen(local_identity) + 1 > buffer_length)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_BUFFER_TOO_SMALL,
                ("Local identity length: %d Buffer length: %d\n",
                 strlen(local_identity), buffer_length));
        }
        else
        {
            strcpy(identity_buffer, local_identity);
        }
        free(local_identity);           
    }
    else
    {
        rc = globus_gss_assist_userok(subject, desired_identity);
        if(rc != 0)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
                ("Could not map %s to %s\n",
                 subject, desired_identity));
        }
    }

    
error:
    if(assertion)
    {
        globus_free(assertion);
    }
    if(token)
    {
        globus_free(token);
    }
    if(sigbuf)
    {
        globus_free(sigbuf);
    }

    if(subject)
    {
        globus_free(subject);
    }
    
    globus_module_deactivate(GLOBUS_GRIDMAP_CALLOUT_ERROR_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    
    return result;
}


