/**********************************************************************
gssapi_ssleay.h:

Description:
        This header file used internally by the gssapi_ssleay
        routines

CVS Information:

        $Source$
        $Date$
        $Revision$
        $Author$

**********************************************************************/

#ifndef _GSSAPI_SSLEAY_H
#define _GSSAPI_SSLEAY_H

/**********************************************************************
                             Include header files
**********************************************************************/

#if defined(WIN32)
#   include "windows.h"
#endif

#include "gssapi.h"
#include "sslutils.h"
#include <stdio.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
#include "openssl/x509v3.h"
#endif

#include "openssl/stack.h"

/**********************************************************************
                               Define constants
**********************************************************************/

#define GSS_I_CTX_INITIALIZED                       1
#define GSS_I_DISALLOW_ENCRYPTION                   2
#define GSS_I_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION 4
#define GSS_I_APPLICATION_WILL_HANDLE_EXTENSIONS    8


#define GSS_C_QOP_GLOBUS_GSSAPI_SSLEAY_BIG 1
/* 
 * Use the SSLeay error facility with the ERR_LIB_USER
 */

/* Offset from ERR_LIB_USER where GSSERR library will be stored */
#define ERR_USER_LIB_GSSERR_NUMBER                  ((ERR_LIB_USER) + 2) 

#define GSSerr(f,r) ERR_PUT_error(ERR_USER_LIB_GSSERR_NUMBER,(f),(r),ERR_file_name,__LINE__)

/* 
 * defines for function codes our minor error codes
 * These match strings defined in gsserr.c
 */

#define GSSERR_F_BASE                   100

#define GSSERR_F_ACCEPT_SEC                GSSERR_F_BASE + 0
#define GSSERR_F_ACQUIRE_CRED              GSSERR_F_BASE + 1
#define GSSERR_F_COMPARE_NAME              GSSERR_F_BASE + 2
#define GSSERR_F_DELETE_SEC                GSSERR_F_BASE + 3
#define GSSERR_F_EXPORT_NAME               GSSERR_F_BASE + 4
#define GSSERR_F_GLOBUSFILE                GSSERR_F_BASE + 5
#define GSSERR_F_IMPORT_NAME               GSSERR_F_BASE + 6
#define GSSERR_F_INIT_SEC                  GSSERR_F_BASE + 7
#define GSSERR_F_RELEASE_BUFFER            GSSERR_F_BASE + 8
#define GSSERR_F_RELEASE_CRED              GSSERR_F_BASE + 9
#define GSSERR_F_RELEASE_NAME              GSSERR_F_BASE + 10
/* In gssutil.c: */
#define GSSERR_F_NAME_TO_NAME              GSSERR_F_BASE + 11
#define GSSERR_F_CREATE_FILL               GSSERR_F_BASE + 12
#define GSSERR_F_GS_HANDSHAKE              GSSERR_F_BASE + 13
#define GSSERR_F_GS_RETRIEVE_PEER          GSSERR_F_BASE + 14

#define GSSERR_F_WRAP                      GSSERR_F_BASE + 15
#define GSSERR_F_UNWRAP                    GSSERR_F_BASE + 16
#define GSSERR_F_GET_MIC                   GSSERR_F_BASE + 17
#define GSSERR_F_VERIFY_MIC                GSSERR_F_BASE + 18

#define GSSERR_F_IMPORT_SEC                GSSERR_F_BASE + 19
#define GSSERR_F_EXPORT_SEC                GSSERR_F_BASE + 20

#define GSSERR_F_IMPORT_CRED               GSSERR_F_BASE + 21
#define GSSERR_F_EXPORT_CRED               GSSERR_F_BASE + 22
#define GSSERR_F_READ                      GSSERR_F_BASE + 23
#define GSSERR_F_WRITE                     GSSERR_F_BASE + 24
#define GSSERR_F_INIT_DELEGATION           GSSERR_F_BASE + 25
#define GSSERR_F_ACCEPT_DELEGATION         GSSERR_F_BASE + 26
#define GSSERR_F_INQUIRE_BY_OID            GSSERR_F_BASE + 27
#define GSSERR_F_INQUIRE_CONTEXT           GSSERR_F_BASE + 28
#define GSSERR_F_ADD_OID_SET_MEMBER        GSSERR_F_BASE + 29
#define GSSERR_F_CREATE_EMPTY_OID_SET      GSSERR_F_BASE + 30
#define GSSERR_F_TEST_OID_SET_MEMBER       GSSERR_F_BASE + 31
#define GSSERR_F_SET_SEC_CONTEXT_OPT       GSSERR_F_BASE + 32
#define GSSERR_F_CREATE_EMPTY_BUFFER_SET   GSSERR_F_BASE + 33
#define GSSERR_F_ADD_BUFFER_SET_MEMBER     GSSERR_F_BASE + 34
#define GSSERR_F_RELEASE_BUFFER_SET        GSSERR_F_BASE + 35
#define GSSERR_F_SET_GROUP                 GSSERR_F_BASE + 36
#define GSSERR_F_GET_GROUP                 GSSERR_F_BASE + 37

/*
 * GSI minor error code
 *
 * There are three types of GSI minor error codes. There are the codes
 * defined in the gssapi library (as defined below starting at code 100).
 * There are the codes defined in the ssl_utils library (as defined in
 * sslutils.h starting at code 1000) and then there are codes that come up
 * from openssl. These codes are indicated by having the high bit set. See
 * below for more details.
 *
 * Defines for reasons in gssapi library.
 * The match strings defined in gsserr.c
 * These are also used for the minor_status codes.
 * Need to make sure these don't overlap with errors in sslutils.h
 */

#define GSSERR_R_BASE                           100

#define GSSERR_R_HANDSHAKE                      GSSERR_R_BASE + 0
#define GSSERR_R_NO_GLOBUSID                    GSSERR_R_BASE + 1
#define GSSERR_R_PROCESS_CERT                   GSSERR_R_BASE + 2
#define GSSERR_R_MUTUAL_AUTH                    GSSERR_R_BASE + 3
#define GSSERR_R_WRAP_BIO                       GSSERR_R_BASE + 4
#define GSSERR_R_PROXY_VIOLATION                GSSERR_R_BASE + 5
#define GSSERR_R_PROXY_NOT_RECEIVED             GSSERR_R_BASE + 6
#define GSSERR_R_BAD_ARGUMENT                   GSSERR_R_BASE + 7
#define GSSERR_R_IMPEXP_BIO_SSL                 GSSERR_R_BASE + 8
#define GSSERR_R_IMPEXP_NO_CIPHER               GSSERR_R_BASE + 9
#define GSSERR_R_IMPEXP_BAD_LEN                 GSSERR_R_BASE + 10
#define GSSERR_R_EXPORT_FAIL                    GSSERR_R_BASE + 12
#define GSSERR_R_IMPORT_FAIL                    GSSERR_R_BASE + 13
#define GSSERR_R_READ_BIO                       GSSERR_R_BASE + 14
#define GSSERR_R_WRITE_BIO                      GSSERR_R_BASE + 15
#define GSSERR_R_UNEXPECTED_FORMAT              GSSERR_R_BASE + 17
#define GSSERR_R_BAD_DATE                       GSSERR_R_BASE + 20
#define GSSERR_R_BAD_MECH                       GSSERR_R_BASE + 21
#define GSSERR_R_ADD_EXT                        GSSERR_R_BASE + 22
#define GSSERR_R_REMOTE_CERT_VERIFY_FAILED      GSSERR_R_BASE + 23
#define GSSERR_R_OUT_OF_MEMORY                  GSSERR_R_BASE + 24
#define GSSERR_R_BAD_NAME                       GSSERR_R_BASE + 25
#define GSSERR_R_UNORDERED_CHAIN                GSSERR_R_BASE + 26
/* NOTE: Don't go over 1000 here or will conflict with errors in sslutils.h */

/* Old error codes in case anyone is using them */
#define GSSERR_R_IMPEXP_BAD_PARMS       GSSERR_R_BAD_ARGUMENT
#define GSSERR_R_PASSED_NULL_PARAMETER  GSSERR_R_BAD_ARGUMENT

/*
 * Flag used on minor_status to indicate an error from the openssl
 * libraries that we have caught and converted to an error code as
 * defined above, in sslutils.h or in scutils.h
 *
 * If this flag is set then the rest of the 32-bit minor status is
 * the error code as returned from the openssl library.
 */
#define GSI_SSL_ERROR_FLAG                      0x8000

#define GSI_IS_SSL_ERROR(minor)         (minor & GSI_SSL_ERROR_FLAG)

/*
 * we need to distinguish between a token
 * created by us using get_mic vs one using
 * the SSL application data
 * We use this in wrap and unwrap
 * Future versions of SSL may use this
 *
 * Our wraped buffer (integrity only) has
 *
 *  byte  type[1]          = SSL3_RT_GSSAPI_SSLEAY
 *  byte  version_major[1] = 0x03
 *  byte  version_minor[1] = 0
 *  byte  mic_length[2]    = 2 byte length of following mic 
 * 
 *  byte  mic_seq[8]           = 8 byte sequence number
 *  byte  mic_data_length[4]   = 4 byte length of data 
 *  byte  hash[*]          = the hash of variable length
 *
 *  byte  data[*]          = the data being wrapped. 
 */

#define SSL3_RT_GSSAPI_SSLEAY                   26



/* These conversions macros are taken from SSL */

#define l2n(l,c)   (*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                    *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                    *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                    *((c)++)=(unsigned char)(((l)    )&0xff))

#define n2l(c,l)   (l =((unsigned long)(*((c)++)))<<24, \
                    l|=((unsigned long)(*((c)++)))<<16, \
                    l|=((unsigned long)(*((c)++)))<< 8, \
                    l|=((unsigned long)(*((c)++))))

#define n2s(c,s)    (s =((unsigned int)(*((c)++)))<< 8, \
                                 s|=((unsigned int)(*((c)++))))

#define s2n(s,c)    (*((c)++)=(unsigned char)(((s)>> 8)&0xff), \
                     *((c)++)=(unsigned char)(((s)    )&0xff))

/* ssl_locl.h is not installed, so we define a few needed items */

#ifndef SSL_eNULL
#define SSL_eNULL       0x00010000L
#endif

#ifndef SSL_STRONG_MASK
#if  SSLEAY_VERSION_NUMBER >= 0x0090581fL
#define  SSL_STRONG_MASK     0x0000007cL
#else
#define SSL_STRONG_MASK     0x07000000L
#endif
#endif

#ifndef SSL_LOW
#if  SSLEAY_VERSION_NUMBER >= 0x0090581fL
#define SSL_LOW         0x00000010L
#else
#define SSL_LOW         0x01000000L
#endif
#endif


/* Compare OIDs */

#define g_OID_equal(o1,o2) \
        (((o1) == (o2)) || \
         ((o1) && (o2) && \
         ((o1)->length == (o2)->length) && \
         (memcmp((o1)->elements,(o2)->elements,(int) (o1)->length) == 0)))

/**********************************************************************
                               Type definitions
**********************************************************************/

/* 
 * The SSL ssl_locl.h is a private headerfile which does
 * not get installed. The ssl3_enc_method is needed for 
 * the import/export so we include it here, in orged to avoid
 * changes to the SSLeay code. 
 *DEE This needs to be looked at. 
 */ 

#ifndef HEADER_SSL_LOCL_H
typedef struct ssl3_enc_method
{
    int                                 (*enc)();
    int                                 (*mac)();
    int                                 (*setup_key_block)();
    int                                 (*generate_master_secret)();
    int                                 (*change_cipher_state)();
    int                                 (*final_finish_mac)();
    int                                 finish_mac_length;
    int                                 (*cert_verify_mac)();
    unsigned char                       client_finished[20];
    int                                 client_finished_len;
    unsigned char                       server_finished[20];
    int                                 server_finished_len;
    int                                 (*alert_value)();
} SSL3_ENC_METHOD;
#endif

typedef enum {
    GS_CON_ST_HANDSHAKE = 0,
    GS_CON_ST_FLAGS,
    GS_CON_ST_REQ,
    GS_CON_ST_CERT,
    GS_CON_ST_DONE
} gs_con_st_t;

typedef enum
{
    GS_DELEGATION_START,
    GS_DELEGATION_DONE,
    GS_DELEGATION_COMPLETE_CRED,
    GS_DELEGATION_SIGN_CERT
} gs_delegation_state_t;

typedef struct gss_name_desc_struct {
    /* gss_buffer_desc  name_buffer ; */
    gss_OID                             name_oid;
    X509_NAME *                         x509n;
    STACK *                             group;
    ASN1_BIT_STRING *                   group_types;
} gss_name_desc ;

typedef struct gss_cred_id_desc_struct {
    proxy_cred_desc *                   pcd;
    gss_name_desc *                     globusid;
    gss_cred_usage_t                    cred_usage;
    BIO *                               gs_bio_err;
} gss_cred_id_desc ;

typedef struct gss_ctx_id_desc_struct{
    proxy_verify_desc                   pvd; /* used for verify_callback */
    proxy_verify_ctx_desc               pvxd;
    gss_name_desc *                     source_name;                 
    gss_name_desc *                     target_name;                 
    gss_cred_id_desc *                  cred_handle;
    OM_uint32                           ret_flags;
    OM_uint32                           req_flags;
    OM_uint32                           ctx_flags;
    int                                 cred_obtained;
    SSL *                               gs_ssl; 
    BIO *                               gs_rbio;
    BIO *                               gs_wbio;
    BIO *                               gs_sslbio;
    gs_con_st_t                         gs_state;
    int                                 locally_initiated;
    time_t                              goodtill;
    /* following used during delegation */

    /* new key for delegated proxy - do we need this now that we have
     * init/accept-delegation
     */
    EVP_PKEY *                          dpkey;
    /* delegated cert */
    X509 *                              dcert;
    /* delegation state */
    gs_delegation_state_t               delegation_state;
} gss_ctx_id_desc ;

/**********************************************************************
                               Global variables
**********************************************************************/

extern
const gss_OID_desc * const gss_mech_globus_gssapi_ssleay;

extern
const gss_OID_desc * const gss_restrictions_extension;

extern
const gss_OID_desc * const gss_trusted_group;

extern
const gss_OID_desc * const gss_untrusted_group;

/**********************************************************************
                               Function prototypes
**********************************************************************/

int
ERR_load_gsserr_strings(int);

OM_uint32
gsi_generate_minor_status();

#endif /* _GSSAPI_SSLEAY_H */
