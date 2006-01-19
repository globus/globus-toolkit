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

#ifdef GLOBUS_IMPLEMENT_REWINDDIR
extern
void
rewinddir(
    DIR *                               dir)
{
#ifdef TARGET_ARCH_NETOS
    int rc;
    int save_errno = 0;

    rc = tx_semaphore_get(&dir->sem, TX_WAIT_FOREVER);

    if (rc != TX_SUCCESS)
    {
        save_errno = EBADF;

        goto out;
    }
    dir->current_entry = 0;
out:
    errno = save_errno;
    return;
#endif /* TARGET_ARCH_NETOS */
}
#endif /* IMPLEMENT_DIR_FUNCTIONS */
