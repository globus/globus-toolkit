#include <stdio.h>
#include <string.h>
#include "gsi_proxy.h"

int proxy_pvd_init(const char *certdir, proxy_verify_desc *pvd)
{
#ifdef GSI_NEW
   /* standalone GSI (1.1.3a - beta) or Globus v. 2.0 */
   proxy_verify_ctx_desc *pvxd;

   pvxd = (proxy_verify_ctx_desc *)malloc(sizeof(*pvxd));
   if (pvxd == NULL) 
      return -1;
   proxy_verify_ctx_init(pvxd);
   if (certdir)
      pvxd->certdir = strdup(certdir);
   proxy_verify_init(pvd, pvxd);
#else
   proxy_init_verify(pvd);
   if (certdir)
      pvd->certdir = strdup(certdir);
#endif
   
   return 0;
}

void proxy_pvd_destroy(proxy_verify_desc *pvd)
{
#if GSI_NEW
   /* standalone GSI (1.1.3a - beta) or Globus v. 2.0 */
   if (pvd->pvxd) {
      proxy_verify_ctx_release(pvd->pvxd);
      free(pvd->pvxd);
   }
   proxy_verify_release(pvd);
#else
   proxy_release_verify(pvd);
#endif 
}
