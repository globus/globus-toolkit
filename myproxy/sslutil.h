/* sslutil.h, vers. 1.1 , Miroslav Ruda

   types and functions from Globus sslutils needed for build of SSL
   client/server suporting globus proxy-credentials

   Most functions comes from Security/gssapi_ssleay/sslutils directory. These
   functions are available in libglobus_gss.a library, but several prototypes
   and structures are not defined in public header files. 
   
*/
#if !defined(SSLUTILS_H)
#define SSLUTILS_H

#if SSLEAY_VERSION_NUMBER <0x00904100L
#define STACK_OF(A) STACK
#endif

#include <globus_config.h>

/* Find out which version of GSI we are using. Globus 1.1.4 and former
 * versions are marked as "old" */
#if !defined(GLOBUS_RELEASE_MAJOR) || (GLOBUS_RELEASE_MAJOR >= 2)
#  define GSI_NEW 2
#else
#  if GLOBUS_RELEASE_MAJOR > 1
#     define GSI_NEW 2
#  else
#     if GLOBUS_RELEASE_BETA != GLOBUS_RELEASE_NOT_BETA
        /* standalone GSI v. 1.1.3a (beta),
         * ftp://ftp.globus.org/pub/gsi/gsi-041701.tar.gz */
#       define GSI_NEW 1
#     else
#       undef GSI_NEW
#     endif /* GLOBUS_RELEASE_BETA */
#  endif /* GLOBUS_RELEASE_MAJOR */
#endif /* GLOBUS_RELEASE */

#if GSI_NEW > 1
    /* Globus v. 2.0 */
#  include <sslutils.h>
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>
#  include <openssl/md5.h>

/* Backwards compatibility with Globus 1.x.  See below. */
#  define myproxy_get_filenames(pcd, a, b, c, d, e, f) \
     proxy_get_filenames(pcd, a, b, c, d, e, f)

#else
   /* not Globus 2.0 */

#  include <stdio.h> /* needed by ssl.h -- yuk! */
#  include <ssl.h>
#  include <x509.h>
#  include <pem.h>
#  include <err.h>
#  if SSLEAY_VERSION_NUMBER >= 0x0090581fL
#    include <x509v3.h>
#  endif
#  include <md5.h>

/* 
 * The globus v 2.0 API adds a new parametr to proxy_get_filenames(), which is 
 * removed here. In this way it is possible to simply use the older libraries 
 */
#  define myproxy_get_filenames(pcd, a, b, c, d, e, f) \
     proxy_get_filenames(a, b, c, d, e, f)

#  ifdef GSI_NEW
   /* Standalone GSI version 1.1.3a (beta) */

   typedef struct proxy_cred_desc_struct {
	   X509                     *ucert ;
	   EVP_PKEY                 *upkey ;
	   STACK_OF(X509)           *cert_chain ;
	   SSL_CTX                  *gs_ctx ;
	   unsigned long            hSession ; /* smart card session handle */
	   unsigned long            hPrivKey ; /* private key session handle */
	   char                                     *certdir ;
	   char                                     *certfile;
	   int                                      num_null_enc_ciphers;
   }  proxy_cred_desc;

   /* proxy_verify_ctx_desc - common to all verifys */

   typedef struct proxy_verify_ctx_desc_struct {
     int                           magicnum ;
     char                          *certdir;
     time_t                        goodtill;
   } proxy_verify_ctx_desc ;

   typedef struct proxy_verify_desc_struct proxy_verify_desc;

   struct proxy_verify_desc_struct {
     int                           magicnum;
     proxy_verify_desc *previous;
     proxy_verify_ctx_desc * pvxd;
     int                           flags;
     X509_STORE_CTX    *cert_store;
     int                           recursive_depth;
     int                           proxy_depth ;
     int                           cert_depth ;
     int                           limited_proxy;
     STACK_OF(X509)        *cert_chain; /*  X509 */
   };

   #define PVD_SSL_EX_DATA_IDX  5

   int
   proxy_init_cred(proxy_cred_desc * pcd, int (*pw_cb)(), BIO *bp);

   void
   proxy_verify_init(proxy_verify_desc * pvd , proxy_verify_ctx_desc *pvxd);

   void
   proxy_verify_release(proxy_verify_desc * pvd);

   void
   proxy_verify_ctx_init(proxy_verify_ctx_desc * pvxd);

   void
   proxy_verify_ctx_release(proxy_verify_ctx_desc * pvxd);

   int
   proxy_load_user_cert(proxy_cred_desc * pcd,
			   const char * user_cert,
			   int (*pw_cb)(), BIO * bp);
   int
   proxy_load_user_key(proxy_cred_desc * pcd,
			   const char * user_key,
			   int (*pw_cb)(), BIO * bp);

#  else
   /* Globus 1.1.4, Globus 1.1.3 */
#  define PVD_SSL_EX_DATA_IDX 0

   typedef struct proxy_cred_desc_struct {
	   X509                     *ucert ;
	   EVP_PKEY                 *upkey ;
	   STACK                    *cert_chain ;
	   SSL_CTX                  *gs_ctx ;
	   unsigned long            hSession ; /* smart card session handle */
	   unsigned long            hPrivKey ; /* private key session handle */
	   char                                     *certdir ;
	   char                                     *certfile;
   }  proxy_cred_desc;

   typedef struct proxy_verify_desc_struct {
     int                           magicnum ;
     int                           proxy_depth ;
     int                           cert_depth ;
     int                           limited_proxy;
     STACK                         *cert_chain; /*  X509 */
     char                          *certdir;
   } proxy_verify_desc ;

   int
   proxy_init_cred(proxy_cred_desc * pcd);

   void
   proxy_init_verify(proxy_verify_desc * pvd);

   void
   proxy_release_verify(proxy_verify_desc * pvd);

   int
   proxy_load_user_cert(proxy_cred_desc * pcd,
			   const char * user_cert,
			   int (*pw_cb)());
   int
   proxy_load_user_key(proxy_cred_desc * pcd,
			   const char * user_key,
			   int (*pw_cb)());
#  endif
  /* All versions prior Globus v. 2.0 */

int proxy_verify_callback(int ok, X509_STORE_CTX * ctx);

int
ERR_load_prxyerr_strings(int i);

proxy_cred_desc *
proxy_cred_desc_new();

int
proxy_cred_desc_free(proxy_cred_desc * pcd);

int
proxy_get_base_name(X509_NAME *subject);

int
proxy_password_callback_no_prompt(char *buffer, int size, int w);

time_t
ASN1_UTCTIME_mktime(ASN1_UTCTIME *ctm);

#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
   int
   proxy_check_issued(X509_STORE_CTX *ctx,
                      X509 *x, 
                      X509 *issuer);
#endif

#endif /* GSI_NEW > 1 */

#endif /* SSLUTILS.H */
