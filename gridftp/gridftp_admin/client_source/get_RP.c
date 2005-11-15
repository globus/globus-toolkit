#include "globus_wsrf_core_tools.h"
#include "GridFTPAdminService_client.h"

static
xsd_QName l_qname =
{
    "http://www.globus.org/namespaces/2005/09/GridFTPAdmin",
    NULL
};


void
gmon_test_result(
    globus_result_t                     result)
{
    if(result != GLOBUS_SUCCESS)
    {
        printf("%s\n", globus_error_print_friendly(globus_error_get(result)));
        exit(1);
    }
}

int
main(
    int                                 argc,
    char *                              argv[])
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_soap_client_handle_t         client_handle;
    globus_soap_message_handle_t        soap_handle;
    int                                 fault_type;
    xsd_any *                           fault;
    xsd_QName                           element_name;
    wsa_EndpointReferenceType *         epr;
    char *                              filename;
    wsrp_GetResourcePropertyResponseType *
                                        response;
    globus_soap_message_attr_t          attr = NULL;

    if(argc < 3)
    {
        fprintf(stderr, "usage: %s <filename> <rp name> <type 1 | 2>\n", 
            argv[0]);
        exit(1);
    }
    filename = argv[1];
    l_qname.local = argv[2];

    globus_module_activate(GLOBUS_SOAP_MESSAGE_MODULE);
    globus_module_activate(GRIDFTPADMINSERVICE_MODULE);

    element_name.Namespace = "GridFTPAdmin";
    element_name.local = "GridFTPAdmin";

   globus_soap_message_attr_init(&attr);

        globus_soap_message_attr_set(
                attr,
                GLOBUS_SOAP_MESSAGE_AUTHZ_METHOD_KEY,
                NULL,
                NULL,
                (void *) GLOBUS_SOAP_MESSAGE_AUTHZ_NONE);

    result = GridFTPAdminService_client_init(&client_handle, attr, NULL);
    gmon_test_result(result);

    result = globus_soap_message_handle_init_from_file(
        &soap_handle,
        filename);
    gmon_test_result(result);

    result = wsa_EndpointReferenceType_init(&epr);
    gmon_test_result(result);

    result = wsa_EndpointReferenceType_deserialize(
        &element_name,
        epr,
        soap_handle,
        0);
    gmon_test_result(result);
    globus_soap_message_handle_destroy(soap_handle);

    result = GridFTPAdminPortType_GetResourceProperty_epr(
        client_handle,
        epr,
        &l_qname,
        &response,
        (GridFTPAdminPortType_GetResourceProperty_fault_t*)&fault_type,
         &fault);
    if(result != GLOBUS_SUCCESS)
    {
        printf("%s\n", globus_error_print_friendly(globus_error_get(result)));
        return 1;
    }
    /* destroy client handle */

    if(strcmp(argv[3], "1") == 0)
    { 
        printf("%d\n", 
            *((int *)response->any.elements[0].value));
    }
    else
    {
        printf("%s\n", 
            *((char **)response->any.elements[0].value));
    }
    GridFTPAdminService_client_destroy(client_handle);

    globus_module_deactivate(GRIDFTPADMINSERVICE_MODULE);

    return 0;
}
