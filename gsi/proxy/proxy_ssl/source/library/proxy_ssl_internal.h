
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

#endif /* HEADER_PROXY_SSL_INTERNAL_H */
