
#include "globus_gsi_proxy.h"
#include "globus_gsi_proxy_constants.h"

static char * 
globus_l_gsi_cred_error_strings[GLOBUS_GSI_CRED_ERROR_LAST] =
{

/* 0 */   "Success",
/* 1 */   "NULL Handle"
/* 2 */   "Handle is not NULL - Don't want to overwrite it",
/* 3 */   "GSI PROXY wrapper for OpenSSL Error",
/* 4 */   "NULLe Handle Attributes",
/* 5 */   "Handle Attributes is not NULL - Don't want to overwrite it",
/* 6 */   "Error with credential",
/* 7 */   "Error with credential handle",
/* 8 */   "Error with credential handle attributes",
/* 9 */   "Error with X509 certificate structure",
/* 10 */  "Error with X509 extensions structure",
/* 11 */  "Error with private key",
/* 12 */  "Error with X509 cert chain",
/* 13 */  "Error verifying cert",
/* 14 */  "Error finding file locations",
/* 15 */  "Error reading pem file",
/* 16 */  "Null parameter to function"
/* 17 */  "Error writing pem file",
/* 18 */  "Error opening file",
/* 19 */  "Error system config"

};
