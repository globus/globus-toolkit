#include "gaa.h"
#include "globus_fifo.h"
#include "globus_gsi_system_config.h"
#include <libxml/parser.h>
#define XMLSEC_NO_XSLT
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/templates.h>
#define XMLSEC_CRYPTO_OPENSSL
#include <xmlsec/crypto.h>

gaa_status
gaa_simple_i_verify_xml_sig(xmlDocPtr doc)
{
    gaa_status status = GAA_S_SUCCESS;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    char *ca_cert_dir = 0;
    globus_fifo_t ca_cert_list;
    char *ca_cert_filename = 0;
    char *eptr = 0;
    xmlNodePtr node;
    xmlSecKeysMngrPtr mngr;

    if (doc == 0) {
	gaa_set_callback_err("Null xml document");
	return(GAA_S_POLICY_PARSING_FAILURE);
    }

    /* Boilerplate xmlsec startup code */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */

/* Init xmlsec library */
    if(xmlSecInit() < 0) {
	fprintf(stderr, "Error: xmlsec initialization failed.\n");
	return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
	gaa_set_callback_err("Error: loaded xmlsec library version is not compatible.\n");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }    

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl") < 0) {
	gaa_set_callback_err("Error: unable to load default xmlsec-crypto library. Make sure\n"
			"that you have it installed and check shared libraries path\n"
			"(LD_LIBRARY_PATH) envornment variable.\n");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
	gaa_set_callback_err("Error: xmlsec-crypto-app initialization failed.\n");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
	gaa_set_callback_err("Error: xmlsec-crypto initialization failed.\n");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    /* End of boilerplate xmlsec startup code */

  /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc),
			  xmlSecNodeSignature,
			  xmlSecDSigNs);
    if(node == NULL) {
	gaa_set_callback_err("Error: xml signature node not found");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    /* Create a key manager */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
	gaa_set_callback_err("Error: failed to create keys manager.\n");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
	gaa_set_callback_err("Error: failed to initialize keys manager.\n");
	xmlSecKeysMngrDestroy(mngr);
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    /* Add CA certs to the key manager */

    if (GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&ca_cert_dir))
    {
	gaa_set_callback_err("Error: failed to get CA cert directory");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    globus_fifo_init(&ca_cert_list);

    if (GLOBUS_GSI_SYSCONFIG_GET_CA_CERT_FILES(ca_cert_dir, &ca_cert_list))
    {
	gaa_set_callback_err("Error: failed to get list of CA cert files");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    while (! globus_fifo_empty(&ca_cert_list)) {
	ca_cert_filename = (char *)globus_fifo_dequeue(&ca_cert_list);
	if (ca_cert_filename) {
	    if(xmlSecCryptoAppKeysMngrCertLoad(mngr,
					       ca_cert_filename,
					       xmlSecKeyDataFormatPem,
					       xmlSecKeyDataTypeTrusted) < 0) {
		/*
		 * xxx -- maybe we shouldn't fail here.  there might be some
		 * good and some bad CA certs; maybe we should just ignore
		 * the bad ones.
		 */
		if (eptr = malloc(80 + strlen(ca_cert_filename))) {
		    sprintf(eptr,
			    "Error: failed to load CA certificate from \"%s\"\n",
			    ca_cert_filename);
		    gaa_set_callback_err(eptr);
		} else {
		    gaa_set_callback_err("Error: failed to load CA certificate from \"%s\"\n");
		}
		xmlSecKeysMngrDestroy(mngr);
		status = GAA_S_POLICY_PARSING_FAILURE;
		goto end;
	    }
	}
    }

    globus_fifo_destroy(&ca_cert_list);

    /* create signature context */
    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if(dsigCtx == NULL) {
        gaa_set_callback_err("Error: failed to create signature context");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        gaa_set_callback_err("Error: signature verify failed\n");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }
        
    /* check verification result */
    if(dsigCtx->status != xmlSecDSigStatusSucceeded) {
        gaa_set_callback_err("Error: invalid signature\n");
	status = GAA_S_POLICY_PARSING_FAILURE;
	goto end;
    }

 end:

    if(dsigCtx) {
	xmlSecDSigCtxDestroy(dsigCtx);
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


    return(status);
}
