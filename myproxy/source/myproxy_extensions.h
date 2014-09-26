/*
 * myproxy_extensions.h - set extensions in issued proxy certificates
 */
#ifndef __MYPROXY_EXTENSIONS_H
#define __MYPROXY_EXTENSIONS_H

/* We need a simple way to define a set of extensions for proxy
 * certificates using the myproxy-server context, and then add them
 * when we actually sign the proxy certificates. Since the proxy
 * certificate signing happens in a low-level API, and we don't want
 * to change the APIs to push the extensions down to this level, we
 * stash them here, relying on the fact that the myproxy-server is
 * multi-process and not multi-threaded, so we're only dealing with
 * one proxy certificate request in the lifetime of the active
 * process. It's not pretty and NOT THREAD SAFE but it minimizes
 * disruptions to the MyProxy APIs.
 */

/* The following all return 0 on success, -1 on error (setting verror). */

int myproxy_set_extensions_from_file(const char filename[]);
int myproxy_set_extensions_from_callout(const char path[],
                                        const char username[],
                                        const char location[]);
int myproxy_add_extension(X509_EXTENSION *extension);
int myproxy_get_extensions(STACK_OF(X509_EXTENSION) **extensions);
int myproxy_free_extensions(); /* Call this to cleanup! */

#endif
