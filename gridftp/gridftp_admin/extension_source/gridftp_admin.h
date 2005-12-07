#if !defined GRIDFTP_REGISTRY_H
#define GRIDFTP_REGISTRY_H 1

#include "globus_soap_message.h"
#include "globus_wsrf_resource.h"
#include "globus_service_engine.h"
#include "globus_operation_provider.h"
#include "globus_wsrf_core_tools.h"
#include "globus_wsrf_service_group.h"
#include "globus_ws_addressing.h"

#include "globus_gridftp_server.h"
#include "globus_service_engine.h"

#define ELEMENT_NAME "GridFTPAdmin"
#define RESOURCE_NAME "GridFTPAdmin"
#define GRIDFTP_ADMIN_SERVICE_NAMESPACE "http://www.globus.org/namespaces/2005/09/GridFTPAdmin"


void
gridftpA_l_string_get_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void **                             property);

void
gridftpA_l_int_get_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void **                             property);

globus_bool_t
gridftpA_l_int_set_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void *                              property);

globus_bool_t
gridftpA_l_string_set_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void *                              property);

void
gridftpA_l_int_change_cb(
    const char *                        opt_name,
    int                                 val,
    void *                              user_arg);

void
gridftpA_l_string_change_cb(
    const char *                        opt_name,
    const char *                        val,
    void *                              user_arg);


#endif
