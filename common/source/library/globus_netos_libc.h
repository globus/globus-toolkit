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

#endif /* TARGET_ARCH_NETOS */

#endif /* GLOBUS_NETOS_DIR_H */
