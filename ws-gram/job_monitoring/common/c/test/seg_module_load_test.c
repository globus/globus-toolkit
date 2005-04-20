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
 * @page seg_load_test SEG Load Test
 *
 * Test that the SEG 
 * - loads the appropriate module when the
 *   globus_scheduler_event_generator_load_module() function is called.
 * - fails reasonably when the module cannot be loaded.
 */

#include "globus_common.h"
#include "globus_scheduler_event_generator.h"

int main(int argc, char *argv[])
{
    int                                 rc;
    globus_result_t                     result;
    char                                modname_fmt[] =
            "%s/test/globus_scheduler_event_generator_test"
            "/libglobus_seg_load_test_module_%s.la";
    char *                              modname;
    char *                              globus_loc = NULL;
    int                                 notok=3;

    printf("1..3\n");

    rc = globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_location(&globus_loc);
    if (result != GLOBUS_SUCCESS)
    {
        rc = 1;
        goto error;
    }

    modname = malloc(sizeof(modname_fmt) + strlen(globus_loc) + 
            strlen(GLOBUS_FLAVOR_NAME));
    sprintf(modname, modname_fmt, globus_loc, GLOBUS_FLAVOR_NAME);

    result = globus_scheduler_event_generator_load_module(modname);

    if (result != GLOBUS_SUCCESS)
    {
        rc = 1;
        goto deactivate_error;
    }
    notok--;
    globus_module_deactivate_all();
    notok--;
    rc = globus_module_activate(GLOBUS_SCHEDULER_EVENT_GENERATOR_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_scheduler_event_generator_load_module("bogus");

    if (result == GLOBUS_SUCCESS)
    {
        rc = 1;
        goto deactivate_error;
    }
    printf("ok\n");
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
