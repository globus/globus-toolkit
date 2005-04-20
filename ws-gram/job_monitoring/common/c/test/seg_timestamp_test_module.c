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

#include "globus_common.h"
#include "globus_scheduler_event_generator.h"

static
int
globus_l_test_module_activate(void);

static
int
globus_l_test_module_deactivate(void);

globus_module_descriptor_t              globus_scheduler_event_module_ptr =
{
    "test module",
    globus_l_test_module_activate,
    globus_l_test_module_deactivate,
    NULL,
    NULL,
    NULL,
    NULL
};

int
globus_l_test_module_activate(void)
{
    char * env;
    time_t stamp;
    time_t expected;
    globus_result_t                     result;

    env = globus_libc_getenv("TEST_MODULE_TIMESTAMP");

    if (env == NULL)
    {
        printf ("not ok\n");
        return 0;
    }
    expected = atoi(env);

    if (expected < 0)
    {
        printf ("not ok\n");
        return 0;
    }

    result = globus_scheduler_event_generator_get_timestamp(&stamp);

    if (result != GLOBUS_SUCCESS)
    {
        printf ("not ok\n");
        return 0;
    }

    if (stamp != expected)
    {
        printf ("not ok\n");
        return 0;
    }
    printf("ok\n");
    return 0;
}

int
globus_l_test_module_deactivate(void)
{
    return 0;
}

/* main() */
