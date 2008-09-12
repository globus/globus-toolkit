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


#include "GridFTPAdvertiseService_skeleton.h"
#include "GridFTPAdvertiseService_internal_skeleton.h"
#include "gridftp_advertise_frontendInfo.h"
#include "gridftp_advertise_frontendInfoType.h"
#include "globus_wsrf_resource.h"

static
globus_result_t
gfsad_l_get_resource_id(
    xsd_any_array *                     reference_parameters,
    char **                             id);

#define RESOURCE_NAME "frontendInfo"

globus_result_t
GridFTPAdvertiseService_init(
    globus_service_descriptor_t *       service_desc)
{
    wsa_EndpointReferenceType           epr;
    globus_resource_t                   resource;

    GlobusFuncName(GridFTPAdvertiseService_init);
    GridFTPAdvertiseServiceDebugEnter();

    globus_module_activate(GLOBUS_WSRF_RESOURCE_MODULE);
    /*
     * There is only one resource associated with the service, so we
     * have a custom get_resource_id implementation that ignores the
     * ReferenceProperties in the EPR and just returns a copy of the static
     * value.
     */
    service_desc->get_resource_id = gfsad_l_get_resource_id;

    globus_resource_create(RESOURCE_NAME, &resource);

    wsa_EndpointReferenceType_init_contents(&epr);
    epr.Address.base_value = globus_common_create_string(
        "http://localhost:8080/GRIDFTPADVERTISESERVICE_BASE_PATH");
    GridFTPAdvertiseServiceInitResource(&epr);
    wsa_EndpointReferenceType_destroy_contents(&epr);

    globus_resource_finish(resource);

    GridFTPAdvertiseServiceDebugExit();
    return GLOBUS_SUCCESS;
}

globus_result_t
GridFTPAdvertiseService_finalize(
    globus_service_descriptor_t *       service_desc)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_resource_t                   resource = NULL;

    GlobusFuncName(GridFTPAdvertiseService_finalize);
    GridFTPAdvertiseServiceDebugEnter();

    globus_resource_find(RESOURCE_NAME, &resource);

    globus_resource_destroy(resource);

    globus_module_deactivate(GLOBUS_WSRF_RESOURCE_MODULE);

    GridFTPAdvertiseServiceDebugExit();
    return result;
}
/* GridFTPAdvertiseService_finalize() */

globus_result_t
GridFTPAdvertisePortType_SetTerminationTime_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsrl_SetTerminationTimeType * input,
    wsrl_SetTerminationTimeResponseType * output,
    xsd_any * fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPAdvertisePortType_SetTerminationTime_impl);
    GridFTPAdvertiseServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that input has
     * been initialized and filled with request values.  
     * output must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPAdvertiseServiceErrorNotImplemented("GridFTPAdvertisePortType_SetTerminationTime");

    GridFTPAdvertiseServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPAdvertisePortType_Destroy_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsrl_DestroyType * input,
    wsrl_DestroyResponseType * output,
    xsd_any * fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPAdvertisePortType_Destroy_impl);
    GridFTPAdvertiseServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that input has
     * been initialized and filled with request values.  
     * output must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPAdvertiseServiceErrorNotImplemented("GridFTPAdvertisePortType_Destroy");

    GridFTPAdvertiseServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPAdvertisePortType_GetCurrentMessage_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsnt_GetCurrentMessageType * input,
    wsnt_GetCurrentMessageResponseType * output,
    xsd_any * fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPAdvertisePortType_GetCurrentMessage_impl);
    GridFTPAdvertiseServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that input has
     * been initialized and filled with request values.  
     * output must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPAdvertiseServiceErrorNotImplemented("GridFTPAdvertisePortType_GetCurrentMessage");

    GridFTPAdvertiseServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPAdvertisePortType_Subscribe_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsnt_SubscribeType * input,
    wsnt_SubscribeResponseType * output,
    xsd_any * fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPAdvertisePortType_Subscribe_impl);
    GridFTPAdvertiseServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that input has
     * been initialized and filled with request values.  
     * output must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPAdvertiseServiceErrorNotImplemented("GridFTPAdvertisePortType_Subscribe");

    GridFTPAdvertiseServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPAdvertisePortType_GetMultipleResourceProperties_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsrp_GetMultipleResourcePropertiesType * input,
    wsrp_GetMultipleResourcePropertiesResponseType * output,
    xsd_any * fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPAdvertisePortType_GetMultipleResourceProperties_impl);
    GridFTPAdvertiseServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that input has
     * been initialized and filled with request values.  
     * output must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPAdvertiseServiceErrorNotImplemented("GridFTPAdvertisePortType_GetMultipleResourceProperties");

    GridFTPAdvertiseServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPAdvertisePortType_QueryResourceProperties_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsrp_QueryResourcePropertiesType * input,
    wsrp_QueryResourcePropertiesResponseType * output,
    xsd_any * fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPAdvertisePortType_QueryResourceProperties_impl);
    GridFTPAdvertiseServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that input has
     * been initialized and filled with request values.  
     * output must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPAdvertiseServiceErrorNotImplemented("GridFTPAdvertisePortType_QueryResourceProperties");

    GridFTPAdvertiseServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPAdvertisePortType_GetResourceProperty_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    xsd_QName * input,
    wsrp_GetResourcePropertyResponseType * output,
    xsd_any * fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPAdvertisePortType_GetResourceProperty_impl);
    GridFTPAdvertiseServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that input has
     * been initialized and filled with request values.  
     * output must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPAdvertiseServiceErrorNotImplemented("GridFTPAdvertisePortType_GetResourceProperty");

    GridFTPAdvertiseServiceDebugExit();
    return result;     
}

static
globus_result_t
gfsad_l_get_resource_id(
    xsd_any_array *                     reference_parameters,
    char **                             id)
{
    if (id)
    {
        *id = globus_libc_strdup(RESOURCE_NAME);

        if (*id)
        {
            return GLOBUS_SUCCESS;
        }
    }
    return GlobusSoapMessageErrorOutOfMemory;
}
/* gfsad_l_get_resource_id() */
