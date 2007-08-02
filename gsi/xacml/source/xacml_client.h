#ifndef XACML_CLIENT_H
#define XACML_CLIENT_H

#include "xacml_datatypes.h"
#include "xacml.h"

EXTERN_C_BEGIN

/* Client SOAP invocation */
int
xacml_request_add_obligation_handler(
    xacml_request_t                     request,
    xacml_obligation_handler_t          handler,
    void *                              handler_arg,
    const char *                        obligation_id);

int
xacml_request_use_ssl(
    xacml_request_t                     request,
    const char *                        certificate_path,
    const char *                        key_path,
    const char *                        ca_dir);

int
xacml_query(
    const char *                        endpoint,
    xacml_request_t                     request,
    xacml_response_t                    response);

EXTERN_C_END

#endif /* XACML_CLIENT_H */
