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
    xmlSecCryptoAppShutdown();
    
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
