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

#include "globus_options.h"
#include "globus_wsrf_core_tools.h"
#include "globus_common.h"
#include "globus_xml_buffer.h"
#include "gssapi.h"
#include "globus_soap_client.h"
#include "globus_soap_message.h"
#include "wsrp_GetResourcePropertyResponseType.h"
#include "globus_soap_message_handle.h"
#include "globus_soap_message_utils.h"
#include "wsnt_ResourceUnknownFaultType.h"
#include "wsnt_ResourceUnknownFault.h"
#include "globus_notification_consumer.h"
#include "globus_wsrf_core_tools.h"
#include "GridFTPServerInfoService_client.h"
#include "frontendInfo.h"
#include "frontendInfoType.h"
#include "backendPool.h"
#include "backendInfo.h"
#include "backendInfo_array.h"
#include "notif_ResourcePropertyValueChangeNotificationElementType.h"
#include <sys/types.h>
#include <sys/wait.h>


#define gmon_test_result(_r) gmon_test_result_real(_r, __LINE__)

static int                              l_connections = 0;
static globus_hashtable_t               l_host_table;

typedef struct backend_entry_s
{
    globus_bool_t                       timer_on;
} backend_entry_t;

globus_result_t
chosting_i_util_add_notification(
    globus_soap_client_handle_t         handle,
    globus_service_engine_t             engine,
    globus_xsd_type_info_t              info,
    wsa_EndpointReferenceType *         epr,
    xsd_QName *                         qname,
    globus_notification_consumer_func_t cb,
    void *                              arg)
{
    int                                 fault_type;
    globus_result_t                     result;
    wsnt_SubscribeType                  subscribe;
    wsnt_SubscribeResponseType *        subscribeResponse;
    xsd_any *                           fault;

    wsnt_SubscribeType_init_contents(&subscribe);
    result = xsd_any_init(&subscribe.TopicExpression.any);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    subscribe.TopicExpression.any->any_info = info;
    result = xsd_QName_copy(
        (xsd_QName **) &subscribe.TopicExpression.any->value,
        qname);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = xsd_anyURI_copy_cstr(
        &subscribe.TopicExpression._Dialect,
        "http://docs.oasis-open.org/wsn/2004/06/TopicExpression/Simple");
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = xsd_boolean_init(&subscribe.UseNotify);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    *subscribe.UseNotify = GLOBUS_TRUE;
    result = globus_notification_create_consumer(
        &subscribe.ConsumerReference, engine, cb, arg);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = GridFTPServerInfoPortType_Subscribe_epr(
        handle,
        epr,
        &subscribe,
        &subscribeResponse,
        (GridFTPServerInfoPortType_Subscribe_fault_t *)&fault_type,
        &fault);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    wsnt_SubscribeType_destroy_contents(&subscribe);

    return GLOBUS_SUCCESS;

error:
    wsnt_SubscribeType_destroy_contents(&subscribe);

    return result;
}



void
gmon_test_result_real(
    globus_result_t                     result,
    int                                 line)
{
    if(result != GLOBUS_SUCCESS)
    {
        printf("ERROR line %d: %s\n",
            line, globus_error_print_friendly(globus_error_get(result)));
        exit(1);
    }
}

static
void
monitor_l_engine_stop(
    globus_result_t                     result,
    globus_service_engine_t             engine,
    void *                              args)
{
    gmon_test_result(result);
}

static
void
l_backend_changed(
    void *                              arg,
    wsnt_TopicExpressionType *          topic,
    wsa_EndpointReferenceType *         producer,
    xsd_anyType *                       message)
{
    backend_entry_t *                   be_ent;
    globus_abstime_t                    now;
    backendInfo *                       bi;
    int                                 i;
    backendInfo_array *                 new;
    notif_ResourcePropertyValueChangeNotificationElementType * rpne;

    printf("l_backend_changed\n");

    rpne = (notif_ResourcePropertyValueChangeNotificationElementType*)
        message->value;

    new = (backendInfo_array *) 
        rpne->ResourcePropertyValueChangeNotification.NewValue->any.value;

    for(i = 0; new != NULL && i < new->length; i++)
    {
        bi = &new->elements[i];
        printf("\t---> %s\n", bi->indentifier);
    }


    {
        be_ent = (backend_entry_t *)
            globus_hashtable_lookup(&l_host_table, bi->indentifier);

        if(bi->openConnections == 0)
        {
            assert(!be_ent->timer_on);
            GlobusTimeAbstimeGetCurrent(now);
            be_ent->timer_on = GLOBUS_TRUE;
            printf("%s ON %ld.%ld", bi->indentifier, now.tv_sec, now.tv_nsec);
            /* start idle timer */
        }
        else
        {
            /* stop the timer */
            if(be_ent->timer_on)
            {
                GlobusTimeAbstimeGetCurrent(now);
                printf("%s OFF %ld.%ld",
                    bi->indentifieri, now.tv_sec, now.tv_nsec);
                be_ent->timer_on = GLOBUS_FALSE;
            }
        }
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
    xsd_QName                           element_name;
    wsa_EndpointReferenceType *         epr;
    char *                              filename;
    globus_soap_message_attr_t          attr = NULL;
    globus_service_engine_t             engine;

    if(argc < 2)
    {
        fprintf(stderr, "usage: %s <filename>\n", 
            argv[0]);
        exit(1);
    }
    filename = argv[1];

    globus_module_activate(GLOBUS_SOAP_MESSAGE_MODULE);
    globus_module_activate(GLOBUS_SERVICE_ENGINE_MODULE);
    globus_module_activate(GLOBUS_NOTIFICATION_CONSUMER_MODULE);
    globus_module_activate(GRIDFTPSERVERINFOSERVICE_MODULE);

    element_name.Namespace = "http://docs.oasis-open.org/wsrf/2004/06/wsrf-WS-ServiceGroup-1.2-draft-01.xsd";
    element_name.local = "MemberServiceEPR";

    globus_hashtable_init(
        &l_host_table,
        64,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    globus_soap_message_attr_init(&attr);

    globus_soap_message_attr_set(
            attr,
            GLOBUS_SOAP_MESSAGE_AUTHZ_METHOD_KEY,
            NULL,
            NULL,
            (void *) GLOBUS_SOAP_MESSAGE_AUTHZ_NONE);
    result = GridFTPServerInfoService_client_init(&client_handle, attr, NULL);
    gmon_test_result(result);

    printf("reading EPR\n");
    result = globus_soap_message_handle_init_from_file(
        &soap_handle,
        filename);
    gmon_test_result(result);

    result = wsa_EndpointReferenceType_init(&epr);
    gmon_test_result(result);

    result = wsa_EndpointReferenceType_deserialize(
        /*&element_name, */
        NULL,
        epr,
        soap_handle,
        0);
    gmon_test_result(result);
    globus_soap_message_handle_destroy(soap_handle);

    printf("starting engine\n");
    result = globus_service_engine_init(
        &engine,
        attr,
        NULL,
        NULL,
        GLOBUS_FALSE);
    gmon_test_result(result);

    printf("add backend notication\n");
    result = chosting_i_util_add_notification(
        client_handle,
        engine,
        &xsd_QName_contents_info,
        epr,
        &backendPool_qname,
        l_backend_changed,
        NULL);
    gmon_test_result(result);

    result = globus_service_engine_register_start(
        engine,
        monitor_l_engine_stop,
        NULL);
    gmon_test_result(result);

    printf("wait for events\n");
    while(1)
    {
        int     status;

        waitpid(-1, &status, WNOHANG);
        globus_poll();
    }


    GridFTPServerInfoService_client_destroy(client_handle);

    globus_module_deactivate(GRIDFTPSERVERINFOSERVICE_MODULE);

    return 0;
}
