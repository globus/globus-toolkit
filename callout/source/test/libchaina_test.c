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

#include <stdlib.h>
#include <stdio.h>
#include "globus_common.h"

#ifndef WIN32
globus_result_t
chaina_test_callout(va_list ap)
#else
globus_result_t
__declspec(dllexport) chaina_test_callout(va_list ap)
#endif
{
    va_list cpy;
    const char *arg1, *arg2;

    va_copy(cpy, ap);
    arg1 = va_arg(cpy, char *);
    arg2 = va_arg(cpy, char *);
    va_end(cpy);

    if (strcmp(arg1, "foo") != 0 || strcmp(arg2, "bar") != 0)
    {
        printf("not ok 1 - callout a\n");
        fprintf(stderr, "#arg1 = %s\n#arg2 = %s\n", arg1, arg2);
        return GLOBUS_FAILURE;
    }
    printf("ok 1 - callout a\n");
    return GLOBUS_SUCCESS;
}
