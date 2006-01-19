/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "GridFTPAdminService_client.h"
#include "globus_wsrf_core_tools.h"

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
    GridFTPAdminService_client_handle_t     client_handle;
    globus_soap_message_handle_t        soap_handle;
    int                                 fault_type;
    xsd_any *                           fault;
    xsd_QName                           element_name;
    wsa_EndpointReferenceType *         epr;
    char *                              filename;
    wsrp_SetResourcePropertiesResponseType *
                                        SetResourcePropertyResponse;
    wsrp_SetResourcePropertiesType *    SetResourceProperties;
    wsrp_SetResourcePropertiesType_choice *
                                        SetResourcePropertiesType_choice;
    xsd_any *                           any;
    globus_soap_message_attr_t          attr = NULL;

    if(argc < 4)
    {
        fprintf(stderr, "usage: %s <filename> <rp name> <type 1 | 2> new val\n",
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
        NULL,
        epr,
        soap_handle,
        0);
    gmon_test_result(result);
    globus_soap_message_handle_destroy(soap_handle);

    wsrp_SetResourcePropertiesType_init(&SetResourceProperties);
    SetResourcePropertiesType_choice =
        wsrp_SetResourcePropertiesType_choice_array_push(
            &SetResourceProperties->choice_value);
    SetResourcePropertiesType_choice->type =
        wsrp_SetResourcePropertiesType_Update;
    any = xsd_any_array_push(
        &SetResourcePropertiesType_choice->value.Update.any);
    any->registry = NULL;

    xsd_QName_copy(&any->element, &l_qname);
    if(strcmp(argv[3], "1") == 0)
    {
        int x;

        any->any_info = &xsd_int_info;
        x = atoi(argv[4]);
        xsd_int_init((xsd_int **) &any->value);
        *(xsd_int *)any->value = x;
    }
    else
    {
        any->any_info = &xsd_string_info;
        xsd_string_init_cstr((xsd_string **) &any->value, argv[4]);
    }


    result = GridFTPAdminPortType_SetResourceProperties_epr(
        client_handle,
        epr,
        SetResourceProperties,
        &SetResourcePropertyResponse,
        (GridFTPAdminPortType_SetResourceProperties_fault_t *)&fault_type,
         &fault);
    if(result != GLOBUS_SUCCESS)
    {
        printf("%s\n", globus_error_print_friendly(globus_error_get(result)));
        return 1;
    }

    globus_module_deactivate(GRIDFTPADMINSERVICE_MODULE);

    return 0;
}
