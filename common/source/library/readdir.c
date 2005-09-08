/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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
