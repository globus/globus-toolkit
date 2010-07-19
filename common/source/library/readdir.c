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

#ifdef GLOBUS_IMPLEMENT_READDIR

extern
struct dirent *
readdir(
    DIR *                               dir)
{
#ifdef TARGET_ARCH_NETOS
    int                                 rc;
    int                                 save_errno = 0;
    NAFS_DIR_ENTRY_INFO *               entry;

    rc = tx_semaphore_get(&dir->sem, TX_WAIT_FOREVER);

    if (rc != TX_SUCCESS)
    {
        save_errno = EBADF;
        goto out;
    }

    entry = &dir->entries[dir->current_entry];

    switch (entry->entry_type)
    {
        case NAFS_FILE_TYPE_FILE:
            dir->d.d_type = DT_REG;
            break;
        case NAFS_FILE_TYPE_DIR:
            dir->d.d_type = DT_DIR;
            break;
        default:
            dir->d.d_type = DT_UNKNOWN;
            break;
    }
    
    strncpy(dir->d.d_name, entry->entry_name, 256);
    rc = tx_semaphore_put(&dir->sem);
    if (rc != TX_SUCCESS)
    {
        save_errno = EBADF;
    }
    dir->current_entry++;

out:
    errno = save_errno;
    return (save_errno == 0) ? &dir->d : NULL;
#endif /* TARGET_ARCH_NETOS */
}
#endif /* IMPLEMENT_DIR_FUNCTIONS */
