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

#ifndef _GSSAPI_OPENSSL_H
#define _GSSAPI_OPENSSL_H

#if defined(WIN32)
#   include "windows.h"
#endif

#include "gssapi.h"
#include "globus_gsi_gssapi_constants.h"
#include "globus_gsi_proxy.h"
#include "globus_gsi_credential.h"

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/stack.h>

#define GSS_I_CTX_INITIALIZED                       1
#define GSS_I_DISALLOW_ENCRYPTION                   2
#define GSS_I_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION 4
#define GSS_I_APPLICATION_WILL_HANDLE_EXTENSIONS    8

#define GSS_C_QOP_GLOBUS_GSSAPI_SSLEAY_BIG 1

/*
 * we need to distinguish between a token
 * created by us using get_mic vs one using
 * the SSL application data
 * We use this in wrap and unwrap
 * Future versions of SSL may use this
 *
 * Our wrapped buffer (integrity only) has
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
#define  SSL_STRONG_MASK     0x0000007cL
#endif

#ifndef SSL_LOW
#define SSL_LOW         0x00000010L
#endif

/* ERROR MACROS */

#define GLOBUS_GSI_GSSAPI_ERROR_RESULT(_MIN_RESULT_, _MAJ_, _MIN_,      \
                                       _ERRSTR_)                        \
    {                                                                   \
         char *                         tmpstr =                        \
             globus_i_gsi_gssapi_create_string _ERRSTR_;                \
         *_MIN_RESULT_ = (OM_uint32) globus_i_gsi_gssapi_error_result(  \
             _MAJ_, _MIN_,                                              \
             __FILE__, _function_name_, __LINE__, tmpstr);              \
         globus_libc_free(tmpstr);                                      \
    }

#define GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(_MIN_RESULT_,            \
                                               _ERRORTYPE_, _ERRORSTR_) \
    {                                                                   \
         char *                         tmpstr =                        \
             globus_i_gsi_gssapi_create_string _ERRORSTR_;              \
         *_MIN_RESULT_ =                                                \
             (OM_uint32) globus_i_gsi_gssapi_openssl_error_result(      \
             _ERRORTYPE_, __FILE__, _function_name_, __LINE__, tmpstr); \
         globus_libc_free(tmpstr);                                      \
    }

#define GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(_MIN_RESULT_, _TOP_RESULT_  \
                                             _ERRORTYPE_)                \
    *_MIN_RESULT_ = (OM_uint32) globus_i_gsi_gssapi_error_chain_result(  \
                                 (globus_result_t)_TOP_RESULT_,          \
                                 _ERRORTYPE_, __FILE__,                  \
                                 _function_name_, __LINE__, NULL)


/* DEBUG MACROS */

#ifdef BUILD_DEBUG
#define GLOBUS_I_GSI_GSSAPI_DEBUG(level) \
    (globus_i_gssapi_debug_level >= (level))

#define GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(level, message) \
{                                                         \
    if (GLOBUS_I_GSI_GSSAPI_DEBUG(level))                 \
    {                                                     \
	globus_libc_fprintf message;                      \
    }                                                     \
} 

#define GLOBUS_I_GSI_GSSAPI_DEBUG_FNPRINTF(level, message) \
{                                                          \
    if (GLOBUS_I_GSI_GSSAPI_DEBUG(level))                  \ 
    {                                                      \
	globus_libc_fnprintf message;                      \
    }                                                      \
} 

#else
#define GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(level, message)
#define GLOBUS_I_GSI_GSSAPI_DEBUG_FNPRINTF(level, message)
#endif

#define GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER \
            GLOBUS_I_GSI_GSSAPI_DEBUG_PRINTF( \
                1, (stderr, "%s entering\n", _function_name_))

#define GLOBUS_I_GSSAPI_DEBUG_EXIT \
            GLOBUS_I_GSI_GSSAPI_DEBUG_PRINTF( \
                1, (stderr, "%s exiting\n", _function_name_))

#endif

/* Compare OIDs */

#define g_OID_equal(o1, o2) \
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
    GSS_CON_ST_HANDSHAKE = 0,
    GSS_CON_ST_FLAGS,
    GSS_CON_ST_REQ,
    GSS_CON_ST_CERT,
    GSS_CON_ST_DONE
} gss_con_st_t;

typedef enum
{
    GSS_DELEGATION_START,
    GSS_DELEGATION_DONE,
    GSS_DELEGATION_COMPLETE_CRED,
    GSS_DELEGATION_SIGN_CERT
} gss_delegation_state_t;

typedef struct gss_name_desc_struct {
    /* gss_buffer_desc  name_buffer ; */
    gss_OID                             name_oid;
    X509_NAME *                         x509n;
    STACK *                             group;
    ASN1_BIT_STRING *                   group_types;
} gss_name_desc;

typedef struct gss_cred_id_desc_struct {
    globus_gsi_cred_handle_t            cred_handle;
    gss_name_desc *                     globusid;
    gss_cred_usage_t                    cred_usage;
} gss_cred_id_desc;

#error remove all goodtill code from context and callback data - now kept in credential handle

typedef struct gss_ctx_id_desc_struct{
    globus_mutex_t                          mutex;
    globus_gsi_credential_callback_data_t   callback_data;
    gss_cred_id_desc *                      peer_cred_handle;
    gss_cred_id_desc *                      cred_handle;
    globus_gsi_proxy_handle_t               proxy_handle;
    OM_uint32                               ret_flags;
    OM_uint32                               req_flags;
    OM_uint32                               ctx_flags;
    int                                     cred_obtained;
    SSL *                                   gss_ssl; 
    BIO *                                   gss_rbio;
    BIO *                                   gss_wbio;
    BIO *                                   gss_sslbio;
    gss_con_st_t                            gss_state;
    int                                     locally_initiated;
    time_t                                  goodtill;
    /* following used during delegation */

    gss_delegation_state_t                   delegation_state;
} gss_ctx_id_desc;

extern
const gss_OID_desc * const              gss_mech_globus_gssapi_openssl;

extern
const gss_OID_desc * const              gss_proxycertinfo_extension;

extern
globus_thread_once_t                    once_control;

#endif /* _GSSAPI_OPENSSL_H */
