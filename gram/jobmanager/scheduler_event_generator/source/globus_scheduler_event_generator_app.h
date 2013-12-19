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
#ifndef GLOBUS_SCHEDULER_EVENT_GENERATOR_APP_H
#define GLOBUS_SCHEDULER_EVENT_GENERATOR_APP_H 1

#include "globus_common.h"
#include "globus_gram_protocol.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
EXTERN_C_BEGIN
#endif

typedef enum
{
    GLOBUS_SCHEDULER_EVENT_PENDING = GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING,
    GLOBUS_SCHEDULER_EVENT_ACTIVE = GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
    GLOBUS_SCHEDULER_EVENT_FAILED = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED,
    GLOBUS_SCHEDULER_EVENT_DONE = GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE,
    GLOBUS_SCHEDULER_EVENT_RAW
}
globus_scheduler_event_type_t;

typedef struct
{
    globus_scheduler_event_type_t       event_type;
    char *                              job_id;
    time_t                              timestamp;
    /* only set if DONE */
    int                                 exit_code;
    /* only set if FAILED */
    int                                 failure_code;
    /* only set if RAW */
    char *                              raw_event;
}
globus_scheduler_event_t;

typedef globus_result_t (*globus_scheduler_event_generator_event_handler_t)(
    void *                              user_arg,
    const globus_scheduler_event_t *    event);

/* API used by executable which drives the SEG */
globus_result_t
globus_scheduler_event_generator_set_timestamp(
    time_t                              timestamp);

globus_result_t
globus_scheduler_event_generator_load_module(
    const char *                        module_name);

typedef void (*globus_scheduler_event_generator_fault_handler_t)(
    void *                              user_arg,
    globus_result_t                     result);

globus_result_t
globus_scheduler_event_generator_set_fault_handler(
    globus_scheduler_event_generator_fault_handler_t
                                        fault_handler,
    void *                              user_arg);

globus_result_t
globus_scheduler_event_generator_set_event_handler(
    globus_scheduler_event_generator_event_handler_t
                                        event_handler,
    void *                              user_arg);

void
globus_scheduler_event_generator_fault(
    globus_result_t                     result);

globus_result_t
globus_scheduler_event_copy(
    globus_scheduler_event_t **         copy,
    const globus_scheduler_event_t *    event);

void
globus_scheduler_event_destroy(
    globus_scheduler_event_t *          event);

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
EXTERN_C_END
#endif

#endif /* GLOBUS_SCHEDULER_EVENT_GENERATOR_APP_H */
