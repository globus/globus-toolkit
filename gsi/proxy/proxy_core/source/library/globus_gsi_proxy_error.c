
#include "globus_gsi_proxy.h"
#include "globus_gsi_proxy_constants.h"

static char * 
globus_l_gsi_proxy_error_strings[GLOBUS_GSI_PROXY_ERROR_LAST] =
{

/* 0 */   "Success",
/* 1 */   "NULL Handle"
/* 2 */   "Handle is not NULL - Don't want to overwrite it",
/* 3 */   "NULL Handle Attributes",
/* 4 */   "Handle Attributes is not NULL - Don't want to overwrite it",
/* 5 */   "error with the proxy handle",
/* 6 */   "error with the proxy handle attributes",
/* 7 */   "error within openssl",
/* 8 */   "error with ASN1 proxycertinfo structure",
/* 9 */   "error with ASN1 proxyrestriction structure",
/* 10 */  "error with ASN1 proxygroup structure",
/* 11 */  "error with pathlength of proxyrestriction",
/* 12 */  "error with X509 request structure",
/* 13 */  "error with X509 structure",
/* 14 */  "error with X509 extensions",
/* 15 */  "error with private key",
/* 16 */  "error with openssl's BIO handle",
/* 17 */  "error converting between internal and DER encoded form",
/* 18 */  "error with credential",
/* 19 */  "error with credential handle",
/* 20 */  "error with credential handle attributes"

};
