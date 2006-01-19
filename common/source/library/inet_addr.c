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

#ifdef GLOBUS_IMPLEMENT_INET_ADDR
uint32_t
inet_addr(const char * cp)
{
    uint32_t output;
    int rc;
    unsigned int octets[4];

    rc = sscanf(
        cp,
        "%d.%d.%d.%d",
        &octets[0], &octets[1], &octets[2], &octets[3]);

    if (rc < 4)
    {
        return -1;
    }
    else
    {
        output = 0;
        output |= octets[3];
        output |= octets[2] << 8;
        output |= octets[1] << 16;
        output |= octets[0] << 24;

        return output;
    }
}
#endif /* GLOBUS_IMPLEMENT_INET_ADDR */
