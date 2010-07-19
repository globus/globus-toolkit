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

#ifndef TESTING_ONLY
#include "gaa.h"
#include "globus_fifo.h"
#include "globus_gsi_system_config.h"
#endif /* TESTING_ONLY */
#include <libxml/parser.h>
#define XMLSEC_NO_XSLT
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/templates.h>
#define XMLSEC_CRYPTO_OPENSSL
#include <xmlsec/crypto.h>

static int
load_ca_certs(xmlSecKeysMngrPtr mngr, char *errbuf, int errbuflen);

#ifndef TESTING_ONLY
gaa_status
gaa_simple_i_verify_xml_sig(xmlDocPtr doc)
{
    char errbuf[2048];
    char *id = 0;

    if (! gaa_simple_i_xml_sig_ok(doc, errbuf, sizeof(errbuf))) {
	gaa_set_callback_err(errbuf);
	return(GAA_S_POLICY_PARSING_FAILURE);
    }
    return(GAA_S_SUCCESS);
}
#endif /* TESTING_ONLY */

gaa_simple_i_xml_sig_ok(xmlDocPtr doc, char *errbuf, int errbuflen)
{
    xmlSecDSigCtxPtr dsigCtx = NULL;
    xmlNodePtr node = 0;
    xmlSecKeysMngrPtr mngr = 0;
    int retval = 0;

    if (doc == 0) {
	snprintf(errbuf, errbuflen, "Null xml document");
	return(0);
    }

    /* Boilerplate xmlsec startup code */
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */

/* Init xmlsec library */
    if(xmlSecInit() < 0) {
	snprintf(errbuf, errbuflen, "Error: xmlsec initialization failed.\n");
	return(0);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
	snprintf(errbuf, errbuflen, "Error: loaded xmlsec library version is not compatible.\n");
	goto end;
    }    

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl") < 0) {
	snprintf(errbuf, errbuflen, "Error: unable to load default xmlsec-crypto library. Make sure\n"
			"that you have it installed and check shared libraries path\n"
			"(LD_LIBRARY_PATH) envornment variable.\n");
	goto end;
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
	snprintf(errbuf, errbuflen, "Error: xmlsec-crypto-app initialization failed.\n");
	goto end;
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
	snprintf(errbuf, errbuflen, "Error: xmlsec-crypto initialization failed.\n");
	goto end;
    }

    /* End of boilerplate xmlsec startup code */

  /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc),
			  xmlSecNodeSignature,
			  xmlSecDSigNs);
    if(node == NULL) {
	snprintf(errbuf, errbuflen, "Error: xml signature node not found");
	goto end;
    }

    /* Create a key manager */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
	snprintf(errbuf, errbuflen, "Error: failed to create keys manager.\n");
	goto end;
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
	snprintf(errbuf, errbuflen, "Error: failed to initialize keys manager.\n");
	xmlSecKeysMngrDestroy(mngr);
	goto end;
    }

    if (load_ca_certs(mngr, errbuf, errbuflen) < 1) {
	goto end;
    }

    /* create signature context */
    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if(dsigCtx == NULL) {
        snprintf(errbuf, errbuflen, "Error: failed to create signature context");
	goto end;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        snprintf(errbuf, errbuflen, "Error: signature verify failed\n");
	goto end;
    }
        
    /* check verification result */
    if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
	retval = 1;
    } else {
        snprintf(errbuf, errbuflen, "Error: invalid signature\n");
	goto end;
    }


 end:

    if(dsigCtx) {
	xmlSecDSigCtxDestroy(dsigCtx);
    }

    if (mngr) {
	xmlSecKeysMngrDestroy(mngr);
    }
    /* Boilerplate xmlsec shutdown code */
    
    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();
    
    /* Shutdown crypto library */
    /*
     * XXX -- xmlSecCryptoAppShutdown shuts down openssl, which breaks
     * much of GSI.  Find a better way to deal with this.
     */
    /* xmlSecCryptoAppShutdown(); */
    
    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();	

    /* End of boilerplate xmlsec shutdown code */

    return(retval);
}

gaa_status
gaa_simple_i_find_signer(xmlDocPtr doc, char **signer, char *errbuf, int errbuflen)
{
    xmlNodePtr 		signode = 0;
    xmlNodePtr 		x509node = 0;
    xmlNodePtr 		x509textnode = 0;
    xmlNodePtr 		kinode = 0;
    xmlChar *		x509text;
    X509 *     		x509cert;
    BIO *       	bp;
    char *		certbuf = 0;
    gaa_status		status = GAA_S_SUCCESS;

    if (doc == 0 || signer == 0) {
	snprintf(errbuf, errbuflen, "Null xml document or signer pointer");
	return(GAA_S_INTERNAL_ERR);
    }

    /* Boilerplate xmlsec startup code */
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */

/* Init xmlsec library */
    if(xmlSecInit() < 0) {
	snprintf(errbuf, errbuflen, "Error: xmlsec initialization failed.\n");
	return(GAA_S_INTERNAL_ERR);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
	snprintf(errbuf, errbuflen, "Error: loaded xmlsec library version is not compatible.\n");
	status = GAA_S_INTERNAL_ERR;
	goto end;
    }    

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl") < 0) {
	snprintf(errbuf, errbuflen, "Error: unable to load default xmlsec-crypto library. Make sure\n"
			"that you have it installed and check shared libraries path\n"
			"(LD_LIBRARY_PATH) envornment variable.\n");
	status = GAA_S_INTERNAL_ERR;
	goto end;
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
	snprintf(errbuf, errbuflen, "Error: xmlsec-crypto-app initialization failed.\n");
	status = GAA_S_INTERNAL_ERR;
	goto end;
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
	snprintf(errbuf, errbuflen, "Error: xmlsec-crypto initialization failed.\n");
	status = GAA_S_INTERNAL_ERR;
	goto end;
    }

    /* End of boilerplate xmlsec startup code */


  /* find signature node */
    signode = xmlSecFindNode(xmlDocGetRootElement(doc),
			     xmlSecNodeSignature,
			     xmlSecDSigNs);
    if(signode == NULL) {
	snprintf(errbuf, errbuflen, "Error: xml signature node not found");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    kinode = xmlSecFindNode(signode,
			    xmlSecNodeKeyInfo,
			    xmlSecDSigNs);
    if(kinode == NULL) {
	snprintf(errbuf, errbuflen, "Error: xml keyinfo node not found");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    x509node = xmlSecFindNode(kinode,
			      xmlSecNodeX509Certificate,
			      xmlSecDSigNs);
    if(x509node == NULL) {
	snprintf(errbuf, errbuflen, "Error: x509 cert node not found");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    for (x509textnode = x509node->children; x509textnode; x509textnode = x509textnode->next)
    {
	if (x509textnode->type == XML_TEXT_NODE)
	    break;
    }

    if(x509textnode == NULL) {
	snprintf(errbuf, errbuflen, "Error: no text in x509 cert node");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    x509text = x509textnode->content;

    if ((certbuf = globus_libc_malloc(strlen(x509text) + 80)) == 0)
    {	
	snprintf(errbuf, errbuflen, "Malloc failed");
	status = GAA_S_SYSTEM_ERR;
	goto end;
    }
    sprintf(certbuf,
	    "-----BEGIN CERTIFICATE-----%s-----END CERTIFICATE-----\n",
	    x509text);

    bp = BIO_new(BIO_s_mem());
    BIO_puts(bp, certbuf);
    x509cert = PEM_read_bio_X509(bp, NULL, 0, NULL);
    *signer = strdup(x509cert->name);

 end:    
    /* Boilerplate xmlsec shutdown code */
    
    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();
    
    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();
    
    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();	

    /* End of boilerplate xmlsec shutdown code */

    return(status);
}

#ifdef TESTING_ONLY
#define CA_CERT_FILENAME "/etc/grid-security/certificates/b38b4d8c.0"
static int
load_ca_certs(xmlSecKeysMngrPtr mngr, char *errbuf, int errbuflen)
{

    if(xmlSecCryptoAppKeysMngrCertLoad(mngr,
				       CA_CERT_FILENAME,
				       xmlSecKeyDataFormatPem,
				       xmlSecKeyDataTypeTrusted) == 0) {
	return(1);
    } else {
	snprintf(errbuf, errbuflen,
		 "Error: failed to load CA certificate from \"%s\"\n",
		 CA_CERT_FILENAME);
	return(0);
    }
}
#else /* TESTING_ONLY */

/** load_ca_certs()
 *
 * Loads trusted CA certificates into the key manager.
 *
 * @param mngr
 *        input/output -- key manager into which certs should be loaded.
 * @param errbuf
 *	  output -- buffer to hold error string.
 * @param errbuflen
 *        input -- max length to write to errbuf
 *
 * @retval  number of CA certificates successfully loaded.
 */
static int
load_ca_certs(xmlSecKeysMngrPtr mngr, char *errbuf, int errbuflen)
{
    globus_fifo_t ca_cert_list;
    char *ca_cert_dir = 0;
    char *ca_cert_filename = 0;
    int keysloaded = 0;
    
    /* Add CA certs to the key manager */

    globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE);
    if (GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&ca_cert_dir))
    {
	snprintf(errbuf, errbuflen, "Error: failed to get CA cert directory");
	goto end;
    }
    
    globus_fifo_init(&ca_cert_list);
    
    if (GLOBUS_GSI_SYSCONFIG_GET_CA_CERT_FILES(ca_cert_dir, &ca_cert_list))
    {
	snprintf(errbuf, errbuflen, "Error: failed to get list of CA cert files");
	goto end;
    }
    
    while (! globus_fifo_empty(&ca_cert_list)) {
	ca_cert_filename = (char *)globus_fifo_dequeue(&ca_cert_list);
	if (ca_cert_filename) {
	    if(xmlSecCryptoAppKeysMngrCertLoad(mngr,
					       ca_cert_filename,
					       xmlSecKeyDataFormatPem,
					       xmlSecKeyDataTypeTrusted) == 0) {
		keysloaded++;
	    } else {
		/*
		 * xxx -- maybe we should fail if any cert load fails?
		 */
		snprintf(errbuf, errbuflen,
			 "Error: failed to load CA certificate from \"%s\"\n",
			 ca_cert_filename);
	    }
	}
    }

    globus_fifo_destroy(&ca_cert_list);

 end:
    return(keysloaded);
}
#endif /* TESTING_ONLY */
