#ifndef _PROXY_H
#define _PROXY_H

#include "sslutil.h"

int 
proxy_pvd_init(const char *certdir, proxy_verify_desc *pvd);

void 
proxy_pvd_destroy(proxy_verify_desc *pvd);

#endif /* _PROXY_H */
