/**********************************************************************
sslutils.h:

Description:
	This header file used internally by the gssapi_ssleay
	routines

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

#ifndef _SSLUTILS_H
#define _SSLUTILS_H
#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
                             Include header files
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "openssl/crypto.h"


#if SSLEAY_VERSION_NUMBER < 0x0090581fL
#define RAND_add(a,b,c) RAND_seed(a,b)
#define RAND_status() 1
#endif

#if SSLEAY_VERSION_NUMBER >= 0x00904100L
/* Support both OpenSSL 0.9.4 and SSLeay 0.9.0 */
#define OPENSSL_PEM_CB(A,B)  A, B
#else
#define RAND_add(a,b,c) RAND_seed(a,b)
#define OPENSSL_PEM_CB(A,B)  A

#define STACK_OF(A) STACK

#define sk_X509_num  sk_num
#define sk_X509_value  (X509 *)sk_value
#define sk_X509_push(A, B) sk_push(A, (char *) B)
#define sk_X509_insert(A,B,C)  sk_insert(A, (char *) B, C)
#define sk_X509_delete  sk_delete
#define sk_X509_new_null sk_new_null
#define sk_X509_pop_free sk_pop_free

#define sk_X509_NAME_ENTRY_num  sk_num
#define sk_X509_NAME_ENTRY_value  (X509_NAME_ENTRY *)sk_value

#define sk_SSL_CIPHER_num  sk_num
#define sk_SSL_CIPHER_value  (SSL_CIPHER*)sk_value
#define sk_SSL_CIPHER_insert(A,B,C)  sk_insert(A, (char *) B, C)
#define sk_SSL_CIPHER_delete  sk_delete
#define sk_SSL_CIPHER_push(A, B) sk_push(A, (char *) B)
#define sk_SSL_CIPHER_shift(A) sk_shift(A)
#define sk_SSL_CIPHER_dup(A) sk_dup(A)
#define sk_SSL_CIPHER_unshift(A, B) sk_unshift(A, (char *) B)
#define sk_SSL_CIPHER_pop(A) sk_pop(A)
#define sk_SSL_CIPHER_delete_ptr(A, B) sk_delete_ptr(A, B)

#define sk_X509_EXTENSION_num sk_num
#define sk_X509_EXTENSION_value (X509_EXTENSION *)sk_value
#define sk_X509_EXTENSION_push(A, B) sk_push(A, (char *) B)
#define sk_X509_EXTENSION_new_null sk_new_null
#define sk_X509_EXTENSION_pop_free sk_pop_free

#define sk_X509_REVOKED_num sk_num
#define sk_X509_REVOKED_value (X509_REVOKED*)sk_value

#endif

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/stack.h"

/**********************************************************************
                               Define constants
**********************************************************************/

#define X509_CERT_DIR "X509_CERT_DIR"
#define X509_CERT_FILE  "X509_CERT_FILE"
#define X509_USER_PROXY "X509_USER_PROXY"
#define X509_USER_CERT  "X509_USER_CERT"
#define X509_USER_KEY   "X509_USER_KEY"
#define X509_USER_DELEG_PROXY   "X509_USER_DELEG_PROXY"
#define X509_USER_DELEG_FILE    "x509up_p"
#define X509_USER_PROXY_FILE    "x509up_u"

/* This is added after the CA name hash to make the policy filename */
#define SIGNING_POLICY_FILE_EXTENSION	".signing_policy"

#ifdef WIN32
#define GSI_REGISTRY_DIR "software\\Globus\\GSI"
#define X509_DEFAULT_CERT_DIR  	".globus\\certificates"
#define X509_DEFAULT_USER_CERT	".globus\\usercert.pem"
#define X509_DEFAULT_USER_KEY 	".globus\\userkey.pem"
#define X509_INSTALLED_CERT_DIR	"share\\certificates"
#define X509_INSTALLED_HOST_CERT_DIR "NEEDS_TO_BE_DETERMINED"
#define X509_DEFAULT_HOST_CERT  "NEEDS_TO_BE_DETERMINED"
#define X509_DEFAULT_HOST_KEY   "NEEDS_TO_BE_DETERMINED"
#else
#define X509_DEFAULT_CERT_DIR  	".globus/certificates"
#define X509_DEFAULT_USER_CERT	".globus/usercert.pem"
#define X509_DEFAULT_USER_KEY 	".globus/userkey.pem"
#define X509_INSTALLED_CERT_DIR	"share/certificates"
#define X509_INSTALLED_HOST_CERT_DIR "/etc/grid-security/certificates"
#define X509_DEFAULT_HOST_CERT  "/etc/grid-security/hostcert.pem"
#define X509_DEFAULT_HOST_KEY   "/etc/grid-security/hostkey.pem"
#endif

/*
 * To allow the use of the proxy_verify_callback with 
 * applications which already use the SSL_set_app_data,
 * we define here the index for use with the 
 * SSL_set_ex_data. This is hardcoded today, but
 * if needed we could add ours at the highest available,
 * then look at all of them for the magic number. 
 * To allow for recursive calls to proxy_verify_callback
 * when verifing a delegate cert_chain, we also have 
 * PVD_STORE_EX_DATA_IDX
 */

#define PVD_SSL_EX_DATA_IDX 	5
#define PVD_STORE_EX_DATA_IDX 	6


#define PVD_MAGIC_NUMBER	22222
#define PVXD_MAGIC_NUMBER	33333
/*
 * Use the SSLeay error facility with the ERR_LIB_USER
 */

#define PRXYerr(f,r) ERR_PUT_error(ERR_user_lib_prxyerr_num(),(f),(r),ERR_file_name,__LINE__)

/* 
 * SSLeay 0.9.0 added the error_data feature. We may be running
 * with 0.8.1 which does not have it, if so, define a dummy
 * ERR_add_error_data and ERR_get_error_line_data
	
 */

#if SSLEAY_VERSION_NUMBER < 0x0900
void ERR_add_error_data( VAR_PLIST( int, num ) );

unsigned long ERR_get_error_line_data(char **file,int *line,
        char **data, int *flags);
#endif

/*
 * defines for function codes our minor error codes
 * These match strings defined in gsserr.c
 */

#define PRXYERR_F_PROXY_GENREQ		100
#define PRXYERR_F_PROXY_SIGN 		101      
#define PRXYERR_F_VERIFY_CB			102         
#define PRXYERR_F_PROXY_LOAD		103       
#define PRXYERR_F_PROXY_TMP 		104
#define PRXYERR_F_INIT_CRED			105
#define PRXYERR_F_LOCAL_CREATE		106
#define PRXYERR_F_CB_NO_PW			107
#define PRXYERR_F_GET_CA_SIGN_PATH	108

/* 
 * defines for reasons 
 * The match strings defined in gsserr.c
 * These are also used for the minor_status codes 
 */


#define PRXYERR_R_PROCESS_PROXY_KEY 	101
#define PRXYERR_R_PROCESS_REQ       	102
#define PRXYERR_R_PROCESS_SIGN      	103
#define PRXYERR_R_MALFORM_REQ       	104
#define PRXYERR_R_SIG_VERIFY        	105
#define PRXYERR_R_SIG_BAD           	106
#define PRXYERR_R_PROCESS_PROXY     	107
#define PRXYERR_R_PROXY_NAME_BAD    	108
#define PRXYERR_R_PROCESS_SIGNC     	109
#define PRXYERR_R_BAD_PROXY_ISSUER  	110
#define PRXYERR_R_PROBLEM_PROXY_FILE    111
#define PRXYERR_R_SIGN_NOT_CA       	112
#define PRXYERR_R_PROCESS_KEY           113
#define PRXYERR_R_PROCESS_CERT          114
#define PRXYERR_R_PROCESS_CERTS         115
#define PRXYERR_R_NO_TRUSTED_CERTS      116
#define PRXYERR_R_PROBLEM_KEY_FILE      117
#define PRXYERR_R_PROBLEM_NOCERT_FILE   118
#define PRXYERR_R_PROBLEM_NOKEY_FILE    119
#define PRXYERR_R_CERT_EXPIERED         120
#define PRXYERR_R_CRL_SIGNATURE_FAILURE 121
#define PRXYERR_R_CRL_NEXT_UPDATE_FIELD 122
#define PRXYERR_R_CRL_HAS_EXPIRED		123
#define PRXYERR_R_CERT_REVOKED			124
#define PRXYERR_R_NO_HOME				125
#define PRXYERR_R_LPROXY_MISSED_USED	126
#define PRXYERR_R_LPROXY_REJECTED	    127
#define PRXYERR_R_KEY_CERT_MISMATCH		128
#define PRXYERR_R_WRONG_PASSPHRASE		129
#define PRXYERR_R_CA_POLICY	               130
#define PRXYERR_R_CA_POLICY_RETRIEVE  	 131
#define PRXYERR_R_CA_POLICY_PARSE		132
#define PRXYERR_R_PROBLEM_CLIENT_CA		133
#define PRXYERR_R_CB_NO_PW				134
#define PRXYERR_R_CB_CALLED_WITH_ERROR	135
#define PRXYERR_R_CLASS_ADD_OID			136
#define PRXYERR_R_CLASS_ADD_EXT			137
#define PRXYERR_R_DELEGATE_VERIFY		138
#define PRXYERR_R_EXT_ADD				139
#define PRXYERR_R_DELEGATE_COPY			140
#define PRXYERR_R_DELEGATE_CREATE		141
#define PRXYERR_R_BUFFER_TOO_SMALL		142

/**********************************************************************
                               Type definitions
**********************************************************************/

typedef struct proxy_cred_desc_struct {
	X509                     *ucert ;
	EVP_PKEY                 *upkey ;
	STACK_OF(X509)           *cert_chain ;
	SSL_CTX                  *gs_ctx ;
	unsigned long            hSession ; /* smart card session handle */
	unsigned long            hPrivKey ; /* private key session handle */
	char					 *certdir ;
	char					 *certfile;
	int						 num_null_enc_ciphers;
}  proxy_cred_desc;

/* proxy_verify_ctx_desc - common to all verifys */

typedef struct proxy_verify_ctx_desc_struct {
  int				magicnum ;  
  char				*certdir; 
  time_t			goodtill;
} proxy_verify_ctx_desc ;

/* proxy_verify_desc - allows for recursive verifys with delegation */

typedef struct proxy_verify_desc_struct proxy_verify_desc;

struct proxy_verify_desc_struct {
  int				magicnum;
  proxy_verify_desc *previous;
  proxy_verify_ctx_desc * pvxd;
  int				flags;
  X509_STORE_CTX    *cert_store;
  int				recursive_depth;
  int				proxy_depth ;
  int				cert_depth ;
  int				limited_proxy;
  STACK_OF(X509)	*cert_chain; /*  X509 */
};

/**********************************************************************
                               Global variables
**********************************************************************/

/**********************************************************************
                               Function prototypes
**********************************************************************/
int 
ERR_user_lib_prxyerr_num();

int
ERR_load_prxyerr_strings(int i);

proxy_cred_desc * 
proxy_cred_desc_new();

int
proxy_cred_desc_free(proxy_cred_desc * pcd);

int
proxy_get_filenames(int proxy_in,
		char ** p_cert_file,
		char ** p_cert_dir,
		char ** p_user_proxy,
		char ** p_user_cert,
		char ** p_user_key);

int
proxy_load_user_cert(proxy_cred_desc * pcd, 
			const char * user_cert,
			int (*pw_cb)(), BIO * bp);
int
proxy_load_user_key(proxy_cred_desc * pcd, 
			const char * user_key,
			int (*pw_cb)(), BIO * bp);

int
proxy_create_local(proxy_cred_desc * pcd,
			const char * outfile,
			int hours,
			int bits,
			int limited_proxy,
			int (*kpcallback)(),
			char * buffer,
			int length);


int
proxy_init_cred(proxy_cred_desc * pcd, int (*pw_cb)(), BIO *bp);

void
proxy_verify_init(proxy_verify_desc * pvd , proxy_verify_ctx_desc *pvxd);

void
proxy_verify_release(proxy_verify_desc * pvd);

int
proxy_check_proxy_name(X509 *);

int 
proxy_check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);

int
proxy_verify_certchain(STACK_OF(X509) *certchain, proxy_verify_desc * ppvd);

int
proxy_verify_callback(int ok, X509_STORE_CTX * ctx);

int
proxy_genreq(X509 *ucert,
             X509_REQ **reqp,
             EVP_PKEY **pkeyp,
             int bits,
             int (*callback)(),
			 proxy_cred_desc * pcd);

int
proxy_sign(X509 *ucert,
             EVP_PKEY *upkey,
             EVP_MD *method,
             X509_REQ *req,
             X509 **ncertp,
             int hours,
             int limit_proxy);

int
proxy_sign_ext(int function,
               X509 *ucert,
               EVP_PKEY *upkey,
               EVP_MD *method,
               X509_REQ *req,
               X509 **ncertp,
               int seconds,
               int limit_proxy,
               int serial,
               char * newcn,
			   STACK_OF(X509_EXTENSION) * extensions);

int
proxy_marshal_tmp(X509 *ncert,
				EVP_PKEY *npkey,
				X509 *ucert,
				STACK_OF(X509) *store_ctx,
				char **filename);

int
proxy_marshal_bp(BIO *bp,
                X509 *ncert,
                EVP_PKEY *npkey,
                X509 *ucert,
                STACK_OF(X509) *store_ctx);

int
proxy_load_user_proxy(STACK_OF(X509) *cert_chain, char *file, BIO * bp);

int
proxy_get_base_name(X509_NAME *subject);

int proxy_password_callback_no_prompt(char *, int, int);

X509_EXTENSION *
proxy_extension_class_add_create(void * buffer, 
			size_t length);
/*
 * SSLeay does not have a compare time function
 * So we add a convert to time_t function
 */

time_t
ASN1_UTCTIME_mktime(ASN1_UTCTIME * ctm);

#ifdef __cplusplus
} 
#endif

#endif /* _SSLUTILS_H */
