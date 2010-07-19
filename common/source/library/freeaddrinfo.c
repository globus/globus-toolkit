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

#ifdef GLOBUS_IMPLEMENT_FREEADDRINFO
void
freeaddrinfo(
    globus_addrinfo_t *                 res)
{
    globus_addrinfo_t *                 tmp;
    globus_addrinfo_t *                 tmp2;

    tmp = res->ai_next;

    while (tmp != NULL)
    {
        if (tmp->ai_addr != NULL)
        {
            free(tmp->ai_addr);
        }
        tmp2 = tmp;
        tmp = tmp->ai_next;

        free(tmp2);

    }
    if (res->ai_addr != NULL)
    {
        free(res->ai_addr);
    }
    if (res->ai_canonname)
    {
        free(res->ai_canonname);
    }
    free(res);
}
#endif /* GLOBUS_IMPLEMENT_FREEADDRINFO */
