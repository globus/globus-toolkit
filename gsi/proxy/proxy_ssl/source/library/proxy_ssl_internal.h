
#ifndef HEADER_PROXY_SSL_INTERNAL_H
#define HEADER_PROXY_SSL_INTERNAL_H

#include <openssl/x509.h>

#define M_PROXY_ASN1_D2I_get_EXP_opt(r,func,free_func) \
    M_ASN1_D2I_get_EXP_opt(r, func, 0) \
    else \
    { \
	if(r != NULL) \
	{ \
	    free_func(r); \
	} \
    } \


/* Used by external API headers */
#define _PROXY_SSL_INTERNAL_

struct PROXYGROUP_st
{
    ASN1_OCTET_STRING *                 group_name;
    ASN1_BOOLEAN *                      attached_group;
};

typedef struct PROXYGROUP_st PROXYGROUP;

struct PROXYRESTRICTION_st
{
    ASN1_OBJECT *                       policy_language;
    ASN1_OCTET_STRING *                 policy;
};

typedef struct PROXYRESTRICTION_st PROXYRESTRICTION;

struct PROXYCERTINFO_st
{
    ASN1_BOOLEAN *                      pC;                       
    ASN1_INTEGER *                      path_length;
    PROXYRESTRICTION *                  restriction;
    PROXYGROUP *                        group;
    X509_SIG *                          issuer_signature;
};

typedef struct PROXYCERTINFO_st PROXYCERTINFO;

#endif /* HEADER_PROXY_SSL_INTERNAL_H */
