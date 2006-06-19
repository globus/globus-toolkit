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

#include "WS_BaseNotificationService_client.h"


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
#include "notif_ResourcePropertyValueChangeNotificationElementType.h"
#include <sys/types.h>
#include <sys/wait.h>
#include "backendInfoType.h"
#include "backendPoolType_array.h"
#include "backendPool.h"
#include "backendPoolType.h"
#include "backendInfoType_array.h"
#include "GridFTPServerInfoService_client.h"

#define SIMPLE_TOPIC_EXPRESSION \
        "http://docs.oasis-open.org/wsn/2004/06/TopicExpression/Simple"
#define CONCRETE_TOPIC_EXPRESSION \
        "http://docs.oasis-open.org/wsn/2004/06/TopicExpression/Concrete"
#define FULL_TOPIC_EXPRESSION \
        "http://docs.oasis-open.org/wsn/2004/06/TopicExpression/Full"


#define gmon_test_result(_r) gmon_test_result_real(_r, __LINE__)

static globus_hashtable_t               l_host_table;
static FILE *                           l_time_log;
static globus_bool_t                    l_done = GLOBUS_FALSE;



typedef struct backend_entry_s
{
    globus_bool_t                       timer_on;
    int                                 connections;
    time_t                              start_time;
    time_t                              idle_time;
    char *                              name;
} backend_entry_t;

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
    time_t                              secs;
    time_t                              diff;
    backend_entry_t *                   be;
    backendInfoType *                   bI;
    backendPoolType *                   bP;
    int                                 i;
    notif_ResourcePropertyValueChangeNotificationElementType * rpne;

    rpne = (notif_ResourcePropertyValueChangeNotificationElementType*)
        message->value;

    bP = (backendPoolType *)
        rpne->ResourcePropertyValueChangeNotification.NewValue->any.value;
    printf("l_backend_changed : %s\n", 
        asctime(&bP->changedAt));
//globus_wsrf_core_export_timestamp(&bP->changedAt));

    secs = mktime(&bP->changedAt);

    for(i = 0; i < bP->backendInfo.length; i++)
    {
        bI = &bP->backendInfo.elements[i];

        be = (backend_entry_t *)
            globus_hashtable_lookup(&l_host_table, bI->indentifier);
        if(be == NULL)
        {
            be = globus_calloc(sizeof(backend_entry_t), 1);
            be->name = strdup(bI->indentifier);
            be->connections = -10; /* set to this so it changes when new */
            globus_hashtable_insert(&l_host_table, be->name, be);
            fprintf(l_time_log, "%s NEW\n", bI->indentifier);
        }

        /* make sure this is the one that changed */
        if(be->connections != bI->openConnections)
        {   
            be->connections = bI->openConnections;

            if(!be->timer_on && bI->openConnections == 0)
            {
                be->timer_on = GLOBUS_TRUE;
                be->start_time = secs;
                fprintf(l_time_log, "%s ON %ld 0\n", bI->indentifier, secs);
            }
            else if(be->timer_on && bI->openConnections > 0)
            {
                be->timer_on = GLOBUS_FALSE;
                diff = secs - be->start_time;
                be->idle_time += diff; 
                fprintf(l_time_log, "%s OFF %ld %ld\n",
                    bI->indentifier, secs, diff);
            }
        }
    }
    fflush(l_time_log);
}

int
main(
    int                                 argc,
    char *                              argv[])
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_soap_client_handle_t         client_handle;
    globus_soap_message_handle_t        soap_handle;
    wsa_EndpointReferenceType *         epr;
    char *                              filename;
    globus_soap_message_attr_t          attr = NULL;
    globus_service_engine_t             engine;
    xsd_anyURI                          dialect_choice = NULL;
    char *                              ns;
    char *                              local;
    xsd_QName *                         qn;
    GridFTPServerInfoPortType_Subscribe_fault_t
                                        fault_type;
    wsnt_SubscribeType                  subscribe;
    wsnt_SubscribeResponseType *        subscribeResponse;
    xsd_any *                           fault;


    l_time_log = stdout;
    local = "backendPool";
    ns = "http://gridftp.globus.org/2006/06/GridFTPServerInfo";

    if(argc < 2)
    {
        fprintf(stderr, "usage: %s <filename> [<log file>]\n", 
            argv[0]);
        exit(1);
    }
    filename = argv[1];
    if(argc > 2)
    {
        printf("openning %s for log\n", argv[2]);
        l_time_log = fopen(argv[2], "w");
        if(l_time_log == NULL) l_time_log = stdout;
    }

    globus_module_activate(WS_BASENOTIFICATIONSERVICE_MODULE);
    globus_module_activate(GLOBUS_NOTIFICATION_CONSUMER_MODULE);
    globus_module_activate(GRIDFTPSERVERINFOSERVICE_MODULE);

    globus_hashtable_init(
        &l_host_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    result = wsnt_SubscribeType_init_contents(&subscribe);
    gmon_test_result(result);
    result = xsd_boolean_init(&subscribe.UseNotify);
    gmon_test_result(result);
    *subscribe.UseNotify = GLOBUS_TRUE;
    result = xsd_any_init(&subscribe.TopicExpression.any);
    gmon_test_result(result);
    dialect_choice = SIMPLE_TOPIC_EXPRESSION;
    result = xsd_anyURI_copy(
            &subscribe.TopicExpression._Dialect,
            &dialect_choice);
    gmon_test_result(result);
    subscribe.TopicExpression.any->any_info = &xsd_QName_contents_info;
    result = xsd_QName_init(&qn);
    gmon_test_result(result);
    subscribe.TopicExpression.any->value = qn;
    result = xsd_string_copy_contents(
            &qn->Namespace,
            &ns);
    gmon_test_result(result);
    result = xsd_string_copy_contents(
                &qn->local,
                &local);
    gmon_test_result(result);
    globus_soap_message_attr_init(&attr);
    globus_soap_message_attr_set(
            attr,
            GLOBUS_SOAP_MESSAGE_AUTHZ_METHOD_KEY,
            NULL,
            NULL,
            (void *) GLOBUS_SOAP_MESSAGE_AUTHZ_NONE);
    gmon_test_result(result);

    printf("reading EPR\n");
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

    printf("creating engine\n");
    result = globus_service_engine_init(
        &engine,
        attr,
        NULL,
        NULL,
        GLOBUS_FALSE);
    gmon_test_result(result);

    printf("starting engine\n");
    result = globus_service_engine_register_start(
        engine,
        monitor_l_engine_stop,
        NULL);
    gmon_test_result(result);

    result = globus_notification_create_consumer(
            &subscribe.ConsumerReference,
            engine,
            l_backend_changed,
            NULL);
    gmon_test_result(result);

    result = GridFTPServerInfoService_client_init(&client_handle, attr, NULL);
    gmon_test_result(result);

    result = GridFTPServerInfoPortType_Subscribe_epr(
            client_handle,
            epr,
            &subscribe,
            &subscribeResponse,
            &fault_type,
            &fault);
    gmon_test_result(result);

    printf("wait for events\n");
    while(!l_done)
    {
        globus_poll();
    }

    return 0;
}
