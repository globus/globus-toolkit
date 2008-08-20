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

#include "globus_i_xio_http.h"
#include "globus_i_xio_http_responses.h"

extern
const char *
globus_i_xio_http_lookup_reason(
    int                                 code)
{
    char                                code_str[4];
    int                                 i;

    if (code < 100 || code > 599)
    {
        return "Unknown status";
    }
    sprintf(&code_str[0], "%d", code);

    for (i = 0; i < GLOBUS_XIO_ARRAY_LENGTH(globus_l_http_descriptions); i+=2)
    {
        if (strcmp(code_str, globus_l_http_descriptions[i]) == 0)
        {
            return globus_l_http_descriptions[i+1];
        }
    }
    return "Unknown status";
}
/* globus_i_xio_http_lookup_reason() */
