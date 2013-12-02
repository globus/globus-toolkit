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
#include "globus_error_string.h"
#include "globus_test_tap.h"

#define myline 42
int main()
{
    globus_object_t * err;
    char * s;
    char * t;
    static char * myname = "main";

    printf("1..1\n");

    globus_module_activate(GLOBUS_COMMON_MODULE);

#line myline
    err = globus_error_construct_string(GLOBUS_COMMON_MODULE, GLOBUS_ERROR_NO_INFO, "[%s]: Error doing something hard at %s:%d\n", GLOBUS_COMMON_MODULE->module_name, myname, __LINE__);
    s = globus_object_printable_to_string(err);
#line myline
    t = globus_common_create_string( "[%s]: Error doing something hard at %s:%d\n", GLOBUS_COMMON_MODULE->module_name, myname, __LINE__);
    ok(strcmp(s, t) == 0, "globus_common_error_string");
    free(s);
    free(t);

    return TEST_EXIT_CODE;
}
