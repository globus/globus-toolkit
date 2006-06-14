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


#include "GridFTPServerInfoService_skeleton.h"
#include "GridFTPServerInfoService_internal_skeleton.h"

globus_result_t
GridFTPServerInfoService_init(
    globus_service_descriptor_t *       service_desc)
{
    GlobusFuncName(GridFTPServerInfoService_init);
    GridFTPServerInfoServiceDebugEnter();

    /* do any service specific init stuff here, such
     * as loading other operation providers and setting them
     * in the operation table of the service descriptor.  This
     * function is called at the end of service activation.
     */

    GridFTPServerInfoServiceDebugExit();
    return GLOBUS_SUCCESS;
}

globus_result_t
GridFTPServerInfoService_finalize(
    globus_service_descriptor_t *       service_desc)
{
    GlobusFuncName(GridFTPServerInfoService_finalize);
    GridFTPServerInfoServiceDebugEnter();

    /* do any service specific finalize stuff here, 
     * opposite of GridFTPServerInfoService_init
     */

    GridFTPServerInfoServiceDebugExit();
    return GLOBUS_SUCCESS;
}



globus_result_t
GridFTPServerInfoPortType_GetCurrentMessage_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsnt_GetCurrentMessageType * GetCurrentMessage,
    wsnt_GetCurrentMessageResponseType * GetCurrentMessageResponse,
    const char ** fault_name,
    void ** fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPServerInfoPortType_GetCurrentMessage_impl);
    GridFTPServerInfoServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that GetCurrentMessage has
     * been initialized and filled with request values.  
     * GetCurrentMessageResponse must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPServerInfoServiceErrorNotImplemented("GridFTPServerInfoPortType_GetCurrentMessage");

    GridFTPServerInfoServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPServerInfoPortType_Subscribe_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsnt_SubscribeType * Subscribe,
    wsnt_SubscribeResponseType * SubscribeResponse,
    const char ** fault_name,
    void ** fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPServerInfoPortType_Subscribe_impl);
    GridFTPServerInfoServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that Subscribe has
     * been initialized and filled with request values.  
     * SubscribeResponse must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPServerInfoServiceErrorNotImplemented("GridFTPServerInfoPortType_Subscribe");

    GridFTPServerInfoServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPServerInfoPortType_GetResourceProperty_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    xsd_QName * GetResourceProperty,
    wsrp_GetResourcePropertyResponseType * GetResourcePropertyResponse,
    const char ** fault_name,
    void ** fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPServerInfoPortType_GetResourceProperty_impl);
    GridFTPServerInfoServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that GetResourceProperty has
     * been initialized and filled with request values.  
     * GetResourcePropertyResponse must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPServerInfoServiceErrorNotImplemented("GridFTPServerInfoPortType_GetResourceProperty");

    GridFTPServerInfoServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPServerInfoPortType_GetMultipleResourceProperties_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsrp_GetMultipleResourcePropertiesType * GetMultipleResourceProperties,
    wsrp_GetMultipleResourcePropertiesResponseType * GetMultipleResourcePropertiesResponse,
    const char ** fault_name,
    void ** fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPServerInfoPortType_GetMultipleResourceProperties_impl);
    GridFTPServerInfoServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that GetMultipleResourceProperties has
     * been initialized and filled with request values.  
     * GetMultipleResourcePropertiesResponse must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPServerInfoServiceErrorNotImplemented("GridFTPServerInfoPortType_GetMultipleResourceProperties");

    GridFTPServerInfoServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPServerInfoPortType_SetResourceProperties_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsrp_SetResourcePropertiesType * SetResourceProperties,
    wsrp_SetResourcePropertiesResponseType * SetResourcePropertiesResponse,
    const char ** fault_name,
    void ** fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPServerInfoPortType_SetResourceProperties_impl);
    GridFTPServerInfoServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that SetResourceProperties has
     * been initialized and filled with request values.  
     * SetResourcePropertiesResponse must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPServerInfoServiceErrorNotImplemented("GridFTPServerInfoPortType_SetResourceProperties");

    GridFTPServerInfoServiceDebugExit();
    return result;     
}



globus_result_t
GridFTPServerInfoPortType_QueryResourceProperties_impl(
    globus_service_engine_t             engine,
    globus_soap_message_handle_t        message,
    globus_service_descriptor_t *       descriptor,
    wsrp_QueryResourcePropertiesType * QueryResourceProperties,
    wsrp_QueryResourcePropertiesResponseType * QueryResourcePropertiesResponse,
    const char ** fault_name,
    void ** fault)
{
    /* add function local variable declarations here */
    globus_result_t                     result = GLOBUS_SUCCESS;

    /* initialize trace debugging info */
    GlobusFuncName(GridFTPServerInfoPortType_QueryResourceProperties_impl);
    GridFTPServerInfoServiceDebugEnter();
     
    /* This is where it all happens.  Service implementer must 
     * implmenent this function.  Asume that QueryResourceProperties has
     * been initialized and filled with request values.  
     * QueryResourcePropertiesResponse must be set by the implementer.
     */
    
    /* do not use GLOBUS_FAILURE, you the error object construction api */
    result = GridFTPServerInfoServiceErrorNotImplemented("GridFTPServerInfoPortType_QueryResourceProperties");

    GridFTPServerInfoServiceDebugExit();
    return result;     
}


