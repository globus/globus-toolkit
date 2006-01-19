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

/*
 * Append fail test: verify fix to bug #3472 (segmentation fault in
 * deactivate if globus_gass_open with append fails).
 */
#include "globus_gass_file.h"

#include <fcntl.h>

int main()
{
    int fd;

    globus_module_activate(GLOBUS_GASS_FILE_MODULE);
    fd = globus_gass_open(
	    "http://no_such_machine.globus.org/no/such/file",
	    O_WRONLY|O_APPEND,
	    0755);
    if(fd >= 0)
    {
	globus_gass_close(fd);
    }
    globus_module_deactivate_all();
    printf("ok\n");
    return 0;
}
