#ifndef _PROXY_H
#define _PROXY_H

#include <x509.h>
#include <globus_config.h>

#if SSLEAY_VERSION_NUMBER <0x00904100L
#define STACK_OF(A) STACK
#endif

/* Find out what version of GSI we are using. Globus 1.1.4 and former
 *  * versions are marked as "old" */
#if !defined(GLOBUS_RELEASE_MAJOR) || (GLOBUS_RELEASE_MAJOR >= 2)
#  define GSI_NEW 2
#else
#  if GLOBUS_RELEASE_MAJOR > 1
#     define GSI_NEW 1
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
#else 
   /* not Globus 2.0 */

#  ifdef GSI_NEW
   /* Standalone GSI version 1.1.3a (beta) */
#       define PVD_SSL_EX_DATA_IDX 5

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

#else
   /* Globus 1.1.4, Globus 1.1.3 */
#  define PVD_SSL_EX_DATA_IDX 0

        typedef struct proxy_verify_desc_struct {
          int                           magicnum ;
          int                           proxy_depth ;
          int                           cert_depth ;
          int                           limited_proxy;
          STACK                         *cert_chain; /*  X509 */
          char                          *certdir;
        } proxy_verify_desc ;

#endif /* ifdef GSI_NEW */

/* Functions imported from globus. They are already publicated in Globus 2.0 */
int proxy_verify_callback(int ok, X509_STORE_CTX * ctx);
int proxy_get_filenames(int proxy_in, char **p_cert_file, char **p_cert_dir,
                        char **p_user_proxy, char **p_user_cert, char **p_user_key);
int proxy_get_base_name(X509_NAME *subject);
#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
int proxy_check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
#endif

/* This must be put _after_ the proxy_get_filenames prototype. The globus v 2.0
 * API adds a new parametr to proxy_get_filenames(), which is removed here. In
 * this way it is possible to simply use the older libraries */
#define proxy_get_filenames(pcd, a, b, c, d, e, f) \
      proxy_get_filenames(a, b, c, d, e, f)

#endif /* GSI_NEW > 1 */

int 
proxy_pvd_init(const char *certdir, proxy_verify_desc *pvd);

void 
proxy_pvd_destroy(proxy_verify_desc *pvd);

#endif /* _PROXY_H */
