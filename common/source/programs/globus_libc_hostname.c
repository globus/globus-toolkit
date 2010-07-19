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
#if defined(HAVE_NETDB_H)
#    include <netdb.h>
#endif

#if !defined(MAXHOSTNAMELEN)
#    define MAXHOSTNAMELEN 1024
#endif

int main()
{
    int rc;
    char host[MAXHOSTNAMELEN];

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    rc = globus_libc_gethostname(host, MAXHOSTNAMELEN);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    globus_libc_printf("%s\n", host);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    return 0;
}
