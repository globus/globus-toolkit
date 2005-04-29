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

/**
 * @page seg_timestamp_test SEG Timestamp Test
 *
 * Test that the SEG passes a timestamp to the module when requested to do so.
 */

#include "globus_common.h"
#include "globus_scheduler_event_generator.h"

int main(int argc, char *argv[])
{
    int                                 rc;
    globus_result_t                     result;
    char                                modname_fmt[] =
            "%s/test/globus_scheduler_event_generator_test"
            "/libglobus_seg_timestamp_test_module_%s.la";
    char *                              modname;
    time_t                              test_stamp=42;
    char                                test_stamp_str[] = "42";
    char *                              globus_loc = NULL;
    int                                 notok=2;



    printf("1..2\n");

    rc = globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_location(&globus_loc);
    if (result != GLOBUS_SUCCESS)
    {
        rc = 1;
        goto deactivate_error;
    }

    modname = malloc(sizeof(modname_fmt) + strlen(GLOBUS_FLAVOR_NAME)
            +strlen(globus_loc));
    sprintf(modname, modname_fmt, globus_loc, GLOBUS_FLAVOR_NAME);
    globus_libc_setenv("TEST_MODULE_TIMESTAMP", "0", GLOBUS_TRUE);

    result = globus_scheduler_event_generator_load_module(modname);

    if (result != GLOBUS_SUCCESS)
    {
        rc = 1;
        fprintf(stderr, "load_module failed: %s\n", globus_object_printable_to_string(globus_error_peek(result)));
        goto deactivate_error;
    }
    notok--;
    globus_module_deactivate_all();
    rc = globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_scheduler_event_generator_set_timestamp(test_stamp);
    if (result != GLOBUS_SUCCESS)
    {
        rc = 1;
        goto deactivate_error;
    }
    globus_libc_setenv("TEST_MODULE_TIMESTAMP", test_stamp_str, GLOBUS_TRUE);
    result = globus_scheduler_event_generator_load_module(modname);

    if (result != GLOBUS_SUCCESS)
    {
        rc = 1;
        fprintf(stderr, "load_module failed: %s\n", globus_object_printable_to_string(globus_error_peek(result)));
        goto deactivate_error;
    }
    notok--;

deactivate_error:
    globus_module_deactivate_all();
error:
    if (rc != 0)
    {
        while (notok-- > 0)
        {
            printf("not ok\n");
        }
    }
    return rc;
}
/* main() */
