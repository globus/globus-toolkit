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
#ifndef GLOBUS_SCHEDULER_EVENT_GENERATOR_STDOUT_H
#define GLOBUS_SCHEDULER_EVENT_GENERATOR_STDOUT_H

#include "globus_common.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
EXTERN_C_BEGIN
#endif

extern globus_module_descriptor_t
globus_i_scheduler_event_generator_stdout_module;

#define GLOBUS_SCHEDULER_EVENT_GENERATOR_STDOUT_MODULE \
        (&globus_i_scheduler_event_generator_stdout_module)

extern 
globus_result_t
globus_scheduler_event_generator_stdout_handler(
    void *                              arg,
    globus_scheduler_event_t *          event);

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
EXTERN_C_END
#endif

#endif /* GLOBUS_SCHEDULER_EVENT_GENERATOR_H */
