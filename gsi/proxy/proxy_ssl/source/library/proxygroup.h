
#ifndef HEADER_PROXYGROUP_H
#define HEADER_PROXYGROUP_H

/**
 * @defgroup proxygroup ProxyGroup
 *
 * @author Sam Meder
 * @author Sam Lang
 *
 * The proxygroup set of data structures and functions provide
 * an interface to generating a PROXYGROUP structure which
 * is maintained as a field in the PROXYCERTINFO structure,
 * and ultimately gets written out to a DER encoded string.
 *
 * @see Further information about proxy groups is available
 * in the Internet Draft Document:
 *
 * draft-ietf-pkix-proxy-01.txt
 */


#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN


#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

/**
 * @defgroup proxycertinfo ProxyCertInfo
 * 
 * @author Sam Meder
 * @author Sam Lang
 * 
 * The proxycertinfo.h file defines a method of
 * maintaining information about proxy certificates.
 */

#define PROXYGROUP_OID               "1.3.6.1.4.1.3536.1.225"
#define PROXYGROUP_SN                "PROXYGROUP"
#define PROXYGROUP_LN                "Proxy Group"

/* Used for error handling */
#define ASN1_F_PROXYGROUP_NEW                            440
#define ASN1_F_D2I_PROXYGROUP                            441

/* data structures */

/**
 * @ingroup proxygroup
 *
 * @note NOTE: The API provides functions to manipulate
 * the fields of a PROXYGROUP.  Accessing the fields
 * directly will not work.
 *
 * This typedef maintains information about the group
 * a proxy certificate is a member of
 *
 * @param group_name the name of the group the proxy
 * certificate is a member of
 * @param attached_group a boolean value, determining
 * whether the proxy certificate is actually in the 
 * group or not
 */
struct PROXYGROUP_st
{
    ASN1_OCTET_STRING *                 group_name;
    ASN1_BOOLEAN *                      attached_group;
};

typedef struct PROXYGROUP_st PROXYGROUP;

DECLARE_STACK_OF(PROXYGROUP)
DECLARE_ASN1_SET_OF(PROXYGROUP)

/* functions */

ASN1_METHOD * PROXYGROUP_asn1_meth();

PROXYGROUP * PROXYGROUP_new();

void PROXYGROUP_free(
    PROXYGROUP *                        group);

PROXYGROUP * PROXYGROUP_dup(
    PROXYGROUP *                        group);

int PROXYGROUP_cmp(
    const PROXYGROUP *                  a,
    const PROXYGROUP *                  b);

int PROXYGROUP_print(
    BIO *                               bp,
    PROXYGROUP *                        group);

int PROXYGROUP_print_fp(
    FILE *                              fp,
    PROXYGROUP *                        group);

int PROXYGROUP_set_name(
    PROXYGROUP *                        group,
    char *                              group_name,
    long                                length);

char * PROXYGROUP_get_name(
    PROXYGROUP *                        group,
    long *                              length);

int PROXYGROUP_set_attached(
    PROXYGROUP *                        group,
    ASN1_BOOLEAN                        attached);

ASN1_BOOLEAN * PROXYGROUP_get_attached(
    PROXYGROUP *                        group);

int i2d_PROXYGROUP(
    PROXYGROUP *                        group,
    unsigned char **                    a);

PROXYGROUP * d2i_PROXYGROUP(
    PROXYGROUP **                       group,
    unsigned char **                    a,
    long                                length);

X509V3_EXT_METHOD * PROXYGROUP_x509v3_ext_meth();

STACK_OF(CONF_VALUE) * i2v_PROXYGROUP(
    struct v3_ext_method *              method,
    PROXYGROUP *                        ext,
    STACK_OF(CONF_VALUE) *              extlist);

EXTERN_C_END

#endif /* HEADER_PROXYGROUP_H */

