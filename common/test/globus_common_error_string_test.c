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

int main()
{
    globus_object_t * err;
    char * s;
    static char * myname = "main";

    globus_module_activate(GLOBUS_COMMON_MODULE);

    err = globus_error_construct_string(GLOBUS_COMMON_MODULE,
	    GLOBUS_ERROR_NO_INFO,
	    "[%s]: Error doing something hard at %s:%d\n",
	    GLOBUS_COMMON_MODULE->module_name,
	    myname,
	    __LINE__);
    s = globus_object_printable_to_string(err);

    globus_libc_printf(s);
    return globus_module_deactivate_all();
}
