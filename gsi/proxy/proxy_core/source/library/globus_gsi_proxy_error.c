
#include "globus_gsi_proxy.h"
#include "globus_gsi_proxy_constants.h"

static char * 
globus_l_gsi_proxy_error_strings[GLOBUS_GSI_PROXY_ERROR_LAST] =
{

/* 0 */   "Success",
/* 1 */   "NULL Handle"
/* 2 */   "Handle is not NULL - Don't want to overwrite it",
/* 3 */   "GSI PROXY wrapper for OpenSSL Error",
/* 4 */   "The proxyrestriction of the proxycertinfo object is invalid",
/* 5 */   "The proxygroup of the proxycertinfo object is invalid",
/* 6 */   "The pathlength of the proxycertinfo object is invalid",
/* 7 */   "NULL Handle Attrs object",
/* 8 */   "Handle Attrs object is not NULL - Don't want to overwrite it",
/* 9 */   "Bad X509 Request object",
/* 10 */  "The X509 Extension object could not be added to the stack of extensions",
/* 11 */  "Could not get the stack of X509 Extensions from the X509 Request",
/* 12 */  "Bad X509 Extensions",
/* 13 */  "Could not create the PROXYCERTINFO object identifier",
/* 14 */  "Invalid X509 Extension",
/* 15 */  "Could not create the BIO for stdout",
/* 16 */  "Could not generate RSA keys",
/* 17 */  "Could not create OID",
/* 18 */  "Could not create ASN1 object",
/* 20 */  "Could not convert ASN1 object from internal to DER form for BIO",
/* 21 */  "Could not convert ASN1 object from DER to internal form for BIO",
/* 22 */  "Could not Duplicate Object",

};
