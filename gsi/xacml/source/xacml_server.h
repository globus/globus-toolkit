#ifndef XACML_SERVER_H
#define XACML_SERVER_H

#include "xacml_datatypes.h"
#include "xacml.h"

EXTERN_C_BEGIN

/* Server Authz Processing */

typedef struct xacml_server_s * xacml_server_t;

int
xacml_server_init(
    xacml_server_t *                    server,
    xacml_authorization_handler_t       handler,
    void *                              arg);

int
xacml_server_set_port(
    xacml_server_t                      server,
    unsigned short                      port);

int
xacml_server_get_port(
    const xacml_server_t                server,
    unsigned short *                    port);

int
xacml_server_use_ssl(
    xacml_server_t                      server,
    const char *                        certificate_path,
    const char *                        key_path,
    const char *                        ca_path);

int
xacml_server_start(
    xacml_server_t                      server);

void
xacml_server_destroy(
    xacml_server_t                      server);

EXTERN_C_END

#endif /* XACML_SERVER_H */
