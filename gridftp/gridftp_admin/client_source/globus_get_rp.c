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

#include "globus_wsrf_core_tools.h"
#include "globus_get_rp.h"

enum get_rp_return_codes_e
{
    GETRP_RESOURCE_UNKNOWN = 1,
    GETRP_BAD_PARAMETERS,
    GETRP_UNKNOWN
};

static
void
getrp_l_test_result(
    globus_result_t                     result,
    int                                 rc)
{
    if(result != GLOBUS_SUCCESS)
    {
        printf("ERROR: %s\n", 
            globus_error_print_friendly(globus_error_get(result)));
        exit(rc);
    }
}

static
void
GetResourceProperty_deserialize_fault(
    globus_soap_message_handle_t        handle,
    const xsd_QName *                   fault_qname,
    int *                               fault_type,
    void *                              args)
{
    if(fault_qname)
    {
        if(fault_qname == (&wsnt_ResourceUnknownFaultType_qname) ||
           fault_qname == (&wsnt_ResourceUnknownFault_qname))
        {
            *fault_type = GETRP_RESOURCE_UNKNOWN;
            fprintf(stderr, "unknown resource.\n");
        }
        else
        {
             *fault_type = GETRP_UNKNOWN;
            fprintf(stderr, "unknown deserialize fault.\n");
        }
    }
}

static struct globus_xsd_type_info_s    getrp_l_info;

static
globus_soap_client_operation_t GetResourceProperty_operation =
{
    { "http://docs.oasis-open.org/wsrf/2004/06/wsrf-WS-ResourceProperties-1.2-draft-01.xsd", "GetResourceProperty" } ,
    &xsd_QName_info,

    { "http://docs.oasis-open.org/wsrf/2004/06/wsrf-WS-ResourceProperties-1.2-draft-01.xsd", "GetResourcePropertyResponse" },
    &getrp_l_info,

    NULL,
    "http://docs.oasis-open.org/wsrf/2004/06/wsrf-WS-ResourceProperties/GetResourceProperty",
    "http://docs.oasis-open.org/wsrf/2004/06/wsrf-WS-ResourceProperties/GetResourcePropertyResponse",

    GetResourceProperty_deserialize_fault

};

globus_result_t
getrp_l_test_deserialize(
    const xsd_QName *                   element_name,
    void **                             instance,
    globus_soap_message_handle_t        soap_message_handle,
    globus_xsd_element_options_t        options)
{
    globus_result_t                     result;
    globus_xml_buffer                   buffer_handle;

    result =
        globus_i_soap_message_deserialize_next_content(soap_message_handle);
    result = globus_xml_buffer_deserialize_contents(
        NULL,
        &buffer_handle,
        soap_message_handle,
        options);
    getrp_l_test_result(result, 10);

    printf("\n%s\n", buffer_handle.buffer);

    return GLOBUS_SUCCESS; 
}

static
void
getrp_l_handle_init(
    globus_soap_client_handle_t *       handle,
    globus_get_rp_info_t *              info)
{
    globus_result_t                     result;
    globus_handler_chain_t              tmp_chain = NULL;

    globus_handler_chain_init(&tmp_chain);

    result = globus_extension_activate(GLOBUS_HANDLER_WS_ADDRESSING_LIB);
    getrp_l_test_result(result, GETRP_UNKNOWN);

    result = globus_handler_chain_push(
        tmp_chain,
        GLOBUS_HANDLER_TYPE_REQUEST_ALL,
        GLOBUS_HANDLER_WS_ADDRESSING_CLIENT);
    getrp_l_test_result(result, GETRP_BAD_PARAMETERS);

    result = globus_handler_chain_push(
        tmp_chain,
        GLOBUS_HANDLER_TYPE_RESPONSE_ALL,
        GLOBUS_HANDLER_WS_ADDRESSING_CLIENT);
    getrp_l_test_result(result, GETRP_BAD_PARAMETERS);

    if(info->debug)
    {
        globus_extension_activate("globus_handler_debug");

        globus_handler_chain_push(
            tmp_chain,
            GLOBUS_HANDLER_TYPE_REQUEST|GLOBUS_HANDLER_TYPE_RESPONSE,
            "globus_handler_debug");
    }

    result = globus_soap_client_handle_init(
        handle,
        info->attr,
        tmp_chain);
    getrp_l_test_result(result, GETRP_BAD_PARAMETERS);
}

static
globus_result_t
getrp_l_opts_unknown(
    const char *                        parm,
    void *                              arg)
{
    return GLOBUS_SUCCESS;
}

static
globus_result_t
getrp_l_parse(
    int                                 argc,
    char **                             argv,
    globus_get_rp_info_t *              info)
{
    globus_options_handle_t             opt_h;
    globus_result_t                     result;

    globus_soap_message_attr_init(&info->attr);
    globus_options_init(&opt_h,getrp_l_opts_unknown,info,getrp_i_opts_table);

    result = globus_options_command_line_process(opt_h, argc, argv);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    return GLOBUS_SUCCESS;
error:
    return result;
}

int
main(
    int                                 argc,
    char *                              argv[])
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_get_rp_info_t *              info;
    char *                              ns;
    char *                              local;
    char *                              tmp_s;
    char *                              copy;
    wsrp_GetResourcePropertyResponseType * response;
    globus_soap_client_handle_t         client_handle;
    int                                 fault_type;
    xsd_any *                           fault;
    xsd_QName                           my_qname;

    globus_module_activate(GLOBUS_SOAP_MESSAGE_MODULE);

    getrp_l_info.type = wsrp_GetResourcePropertyResponseType_info.type;
    getrp_l_info.serialize =
        wsrp_GetResourcePropertyResponseType_info.serialize;
    getrp_l_info.deserialize =
        wsrp_GetResourcePropertyResponseType_info.deserialize;
    getrp_l_info.deserialize = getrp_l_test_deserialize;
    getrp_l_info.initialize =
        wsrp_GetResourcePropertyResponseType_info.initialize;
    getrp_l_info.destroy = wsrp_GetResourcePropertyResponseType_info.destroy;
    getrp_l_info.copy = wsrp_GetResourcePropertyResponseType_info.copy;
    getrp_l_info.initialize_contents =
        wsrp_GetResourcePropertyResponseType_info.initialize_contents;
    getrp_l_info.destroy_contents =
        wsrp_GetResourcePropertyResponseType_info.destroy_contents;
    getrp_l_info.copy_contents =
        wsrp_GetResourcePropertyResponseType_info.copy_contents;
    getrp_l_info.type_size =
        wsrp_GetResourcePropertyResponseType_info.type_size;
    getrp_l_info.push = wsrp_GetResourcePropertyResponseType_info.push;
    getrp_l_info.contents_info =
        wsrp_GetResourcePropertyResponseType_info.contents_info;
    getrp_l_info.array_info =
        wsrp_GetResourcePropertyResponseType_info.array_info;

    info = (globus_get_rp_info_t *) globus_calloc(
        1, sizeof(globus_get_rp_info_t));
    result = getrp_l_parse(argc, argv, info);
    getrp_l_test_result(result, GETRP_BAD_PARAMETERS);

    getrp_l_handle_init(&client_handle, info);
    copy = strdup(argv[argc-1]);
    tmp_s = strchr(copy, '{');
    if(tmp_s == NULL)
    {
        /* make an error */
        fprintf(stderr,
            "malformed resource, '{' not found: {namespace}local\n");
        goto error;
    }
    ns = tmp_s+1;
    tmp_s = strchr(ns, '}');
    if(tmp_s == NULL)
    {
        /* make an error */
        fprintf(stderr,
            "malformed resource, '}' not found: {namespace}local\n");
        goto error;
    }
    *tmp_s = '\0';
    local = tmp_s + 1;

    my_qname.Namespace = ns;
    my_qname.local = local;

    if(info->endpoint != NULL)
    {
        /* get with jsut the endpoint */
        result = globus_soap_client_operation(
            client_handle,
            info->endpoint,
            &GetResourceProperty_operation,
            (void *) &my_qname,
            (void *) &response,
            (int *) &fault_type,
            &fault);
        getrp_l_test_result(result, fault_type);
    }
    else
    {
        result = globus_soap_client_handle_attr_set(
            client_handle,
            WSADDR_EPR_KEY,
            wsa_EndpointReferenceType_copy_wrapper,
            wsa_EndpointReferenceType_destroy_wrapper,
            (void *) info->epr);
        getrp_l_test_result(result, GETRP_BAD_PARAMETERS);
        result = globus_soap_client_operation(
            client_handle,
            info->epr->Address.base_value,
            &GetResourceProperty_operation,
            (void *) &my_qname,
            (void **) &response,
            (int *) &fault_type,
            &fault);
        getrp_l_test_result(result, fault_type);
    }

    return 0;
error:
    printf("error\n");
    return GETRP_BAD_PARAMETERS;
}
