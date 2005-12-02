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

#ifndef GLOBUS_NETOS_DIR_H
#define GLOBUS_NETOS_DIR_H

#ifdef TARGET_ARCH_NETOS

#include <tx_api.h>
#include <fs_api.h>
#include <sysAccess.h>

/* Only DT_UNKNOWN, DT_DIR, and DT_REG are handled by this filesystem */
enum
{
    DT_UNKNOWN,
    DT_FIFO,
    DT_CHR,
    DT_DIR,
    DT_BLK,
    DT_REG,
    DT_LNK,
    DT_SOCK,
    DT_WHT
};

#ifndef HAVE_DIR
#define HAVE_DIR 1
struct dirent
{
    int                                 d_ino;
    int                                 d_off;
    unsigned char                       d_type;
    char                                d_name[256];
};

typedef struct
{
    unsigned int                        dir_entry_count;
    NAFS_DIR_ENTRY_INFO *               entries;
    int                                 current_entry;
    int                                 error_code;
    struct dirent                       d;
    TX_SEMAPHORE                        sem;
} DIR;
#endif /* !HAVE_DIR */


#ifndef HAVE_OPENDIR
#define HAVE_OPENDIR 1
#define GLOBUS_IMPLEMENT_OPENDIR 1
extern DIR * opendir(const char *filename);
#endif /* !HAVE_OPENDIR */

#ifndef HAVE_READDIR
#define HAVE_READDIR 1
#define GLOBUS_IMPLEMENT_READDIR 1
extern struct dirent * readdir(DIR *dir); 
#endif /* !HAVE_READDIR */

#ifndef HAVE_CLOSEDIR
#define HAVE_CLOSEDIR 1
#define GLOBUS_IMPLEMENT_CLOSEDIR 1
extern int closedir(DIR *dir);
#endif /* !HAVE_CLOSEDIR */

#ifndef HAVE_REWINDDIR
#define HAVE_REWINDDIR 1
#define GLOBUS_IMPLEMENT_REWINDDIR 1
extern void rewinddir(DIR *dir);
#endif /* !HAVE_REWINDDIR */


#endif /* TARGET_ARCH_NETOS */

#endif /* GLOBUS_NETOS_DIR_H */
