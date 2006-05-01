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

#include "gaa.h"
#include "gaa_private.h"
#include <string.h>

/** gaa_i_new_string()
 *
 *  @ingroup gaa_internal
 *
 *  Create a new string and copy and old string into it.
 *
 *  @param dest
 *         output string to create
 *  @param src
 *         input string to copy
 */
gaa_status
gaa_i_new_string(char **dest, char *src)
{
    if (dest == 0 || src == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (((*dest) = strdup(src)) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    return(GAA_S_SUCCESS);
}

/** gaa_i_free_simple()
 *
 *  @ingroup gaa_internal
 *
 *  Free a pointer, if it's nonzero.
 *
 *  @param val
 *         value to free
 */
void
gaa_i_free_simple(void *val)
{
    if (val)
	free(val);
}
