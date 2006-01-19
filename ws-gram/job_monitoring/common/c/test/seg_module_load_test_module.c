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

#include "globus_common.h"

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
    printf("ok\n");
    return 0;
}

int
globus_l_test_module_deactivate(void)
{
    printf("ok\n");
    return 0;
}

/* main() */
