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

#define GSS_C_QOP_GLOBUS_GSSAPI_SSLEAY_BIG 1
/* 
 * Use the SSLeay error facility with the ERR_LIB_USER
 */

#define GSSerr(f,r) ERR_PUT_error(ERR_user_lib_gsserr_num(),(f),(r),ERR_file_name,__LINE__)

/* 
 * defines for function codes our minor error codes
 * These match strings defined in gsserr.c
 */

#define GSSERR_F_ACCEPT_SEC            100
#define GSSERR_F_ACQUIRE_CRED          101
#define GSSERR_F_COMPARE_NAME          102
#define GSSERR_F_DELETE_SEC            103
#define GSSERR_F_EXPORT_NAME           104
#define GSSERR_F_GLOBUSFILE            105
#define GSSERR_F_IMPORT_NAME           106
#define GSSERR_F_INIT_SEC              107
#define GSSERR_F_RELEASE_BUFFER        108
#define GSSERR_F_RELEASE_CRED          109
#define GSSERR_F_RELEASE_NAME          110
 /* In gssutil.c: */
#define GSSERR_F_NAME_TO_NAME          111
#define GSSERR_F_CREATE_FILL           112
#define GSSERR_F_GS_HANDSHAKE          113
#define GSSERR_F_GS_RETRIVE_PEER       114    

#define GSSERR_F_WRAP                  115
#define GSSERR_F_UNWRAP                116
#define GSSERR_F_GET_MIC               117
#define GSSERR_F_VERIFY_MIC            118

#define GSSERR_F_IMPORT_SEC            119
#define GSSERR_F_EXPORT_SEC            120

#define GSSERR_F_IMPORT_CRED           121
#define GSSERR_F_EXPORT_CRED           122
#define GSSERR_F_READ                  123
#define GSSERR_F_WRITE                 124

/* 
 * defines for reasons 
 * The match strings defined in gsserr.c
 * These are also used for the minor_status codes 
 */

#define GSSERR_R_HANDSHAKE             100
#define GSSERR_R_NO_GLOBUSID           101
#define GSSERR_R_PROCESS_CERT          102
#define GSSERR_R_MUTUAL_AUTH           103
#define GSSERR_R_WRAP_BIO              104
#define GSSERR_R_PROXY_VIOLATION       105
#define GSSERR_R_PROXY_NOT_RECEIVED    106
#define GSSERR_R_IMPEXP_BAD_PARMS      107
#define GSSERR_R_IMPEXP_BIO_SSL        108
#define GSSERR_R_IMPEXP_NO_CIPHER      109
#define GSSERR_R_IMPEXP_BAD_LEN        110
#define GSSERR_R_CLASS_ADD_EXT         111
#define GSSERR_R_EXPORT_FAIL           112
#define GSSERR_R_IMPORT_FAIL           113
#define GSSERR_R_READ_BIO              114
#define GSSERR_R_WRITE_BIO             115
#define GSSERR_R_PASSED_NULL_PARAMETER 116
#define GSSERR_R_UNEXPECTED_FORMAT     117
#define GSSERR_R_PROXY_EXPIRED         118  
#define GSSERR_R_CERT_EXPIRED          119  
#define GSSERR_R_BAD_DATE              120
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

#define SSL3_RT_GSSAPI_SSLEAY			26



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
    int (*enc)();
    int (*mac)();
    int (*setup_key_block)();
    int (*generate_master_secret)();
    int (*change_cipher_state)();
    int (*final_finish_mac)();
    int finish_mac_length;
    int (*cert_verify_mac)();
    unsigned char client_finished[20];
    int client_finished_len;
    unsigned char server_finished[20];
    int server_finished_len;
    int (*alert_value)();
    } SSL3_ENC_METHOD;
#endif

typedef enum {
	GS_CON_ST_HANDSHAKE=0,
	GS_CON_ST_FLAGS,
	GS_CON_ST_REQ,
	GS_CON_ST_CERT,
	GS_CON_ST_DONE
} gs_con_st_t;

typedef struct gss_name_desc_struct {
  /* gss_buffer_desc  name_buffer ; */
  gss_OID		 name_oid;
  X509_NAME      * x509n ;
} gss_name_desc ;

typedef struct gss_cred_id_desc_struct {
  proxy_cred_desc		   *pcd;
  gss_name_desc			   *globusid ;
  gss_cred_usage_t         cred_usage ;
  BIO                      *gs_bio_err ;
} gss_cred_id_desc ;

typedef struct gss_ctx_id_desc_struct{
  proxy_verify_desc pvd; /* used for verify_callback */
  proxy_verify_ctx_desc pvxd;
  gss_name_desc     *source_name ;                 
  gss_name_desc     *target_name ;                 
  gss_cred_id_desc  *cred_handle ;
  OM_uint32			ret_flags ;
  OM_uint32			req_flags ;
  int				cred_obtained ;
  SSL               *gs_ssl ; 
  BIO               *gs_rbio ;
  BIO               *gs_wbio ;
  BIO               *gs_sslbio ;
  gs_con_st_t		gs_state;
  int				locally_initiated ;
	/* following used during delegation */
  EVP_PKEY			*dpkey;    /* new key for delegated proxy */
  X509				*dcert;	   /* delegated cert */
} gss_ctx_id_desc ;

/**********************************************************************
                               Global variables
**********************************************************************/

extern
const gss_OID_desc * const gss_mech_globus_gssapi_ssleay;

/**********************************************************************
                               Function prototypes
**********************************************************************/

int 
ERR_user_lib_gsserr_num();

int
ERR_load_gsserr_strings(int);

#endif /* _GSSAPI_SSLEAY_H */
