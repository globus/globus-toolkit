/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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
    GLOBUS_SCHEDULER_EVENT_DONE = GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE,
    GLOBUS_SCHEDULER_EVENT_FAILED = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED,
    GLOBUS_SCHEDULER_EVENT_RAW
}
globus_scheduler_event_type_t;

typedef union
{
    globus_scheduler_event_type_t       event_type;

    struct
    {
        globus_scheduler_event_type_t   event_type;
        const char *                    job_id;
        time_t                          timestamp;
    }
    pending;
    struct
    {
        globus_scheduler_event_type_t   event_type;
        const char *                    job_id;
        time_t                          timestamp;
    }
    active;
    struct
    {
        globus_scheduler_event_type_t   event_type;
        const char *                    job_id;
        time_t                          timestamp;
        int                             exit_code;
    }
    done;
    struct
    {
        globus_scheduler_event_type_t   event_type;
        const char *                    job_id;
        time_t                          timestamp;
        int                             failure_code;
    }
    failed;
    struct
    {
        globus_scheduler_event_type_t   event_type;
        const char *                    raw_event;
    }
    raw;
}
globus_scheduler_event_t;

typedef globus_result_t (*globus_scheduler_event_generator_event_handler_t)(
    void *                              user_arg,
    globus_scheduler_event_t *          event);

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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
EXTERN_C_END
#endif

#endif /* GLOBUS_SCHEDULER_EVENT_GENERATOR_APP_H */
