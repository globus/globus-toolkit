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

#include "globus_gridftp_server.h"
#include "globus_xio.h"
#include "globus_xio_file_driver.h"
#include "openssl/md5.h"
#include "version.h"


GlobusDebugDeclare(GLOBUS_GRIDFTP_SERVER_FILE);

#define GlobusGFSFileDebugPrintf(level, message)                             \
    GlobusDebugPrintf(GLOBUS_GRIDFTP_SERVER_FILE, level, message)

#define GlobusGFSFileDebugEnter()                                            \
    GlobusGFSFileDebugPrintf(                                                \
        GLOBUS_GFS_DEBUG_TRACE,                                              \
        ("[%s] Entering\n", _gfs_name))
        
#define GlobusGFSFileDebugExit()                                             \
    GlobusGFSFileDebugPrintf(                                                \
        GLOBUS_GFS_DEBUG_TRACE,                                              \
        ("[%s] Exiting\n", _gfs_name))

#define GlobusGFSFileDebugExitWithError()                                    \
    GlobusGFSFileDebugPrintf(                                                \
        GLOBUS_GFS_DEBUG_TRACE,                                              \
        ("[%s] Exiting with error\n", _gfs_name))

GlobusDebugDefine(GLOBUS_GRIDFTP_SERVER_FILE);

#define GLOBUS_L_GFS_FILE_CKSM_BS 1024*1024

typedef struct
{
    globus_mutex_t                      lock;
    globus_memory_t                     mem;
    globus_priority_q_t                 queue;
    globus_list_t *                     buffer_list;
    globus_gfs_operation_t              op;
    globus_xio_handle_t                 file_handle;
    globus_off_t                        file_offset;
    globus_off_t                        read_offset;
    globus_off_t                        read_length;
/*    
    globus_off_t                        write_delta;
    globus_off_t                        transfer_delta; */
    int                                 pending_writes;
    int                                 pending_reads;
    globus_size_t                       block_size;
    int                                 optimal_count;
    int                                 node_ndx;
    globus_object_t *                   error;
    globus_bool_t                       first_read;
    globus_bool_t                       eof;
    globus_bool_t                       aborted;
    int                                 concurrency_check;
    int                                 concurrency_check_interval;
} globus_l_file_monitor_t;


typedef struct
{
    globus_byte_t *                     buffer;
    globus_off_t                        offset;
    globus_size_t                       length;
} globus_l_buffer_info_t;

typedef struct gfs_l_file_stack_entry_s
{
    globus_xio_driver_t                 driver;
    char *                              driver_name;
    char *                              opts;
} gfs_l_file_stack_entry_t;

static globus_xio_driver_t              globus_l_gfs_file_driver;

static
globus_result_t
globus_l_gfs_file_make_stack(
    globus_l_file_monitor_t *           mon,
    globus_xio_attr_t                   attr,
    globus_xio_stack_t                  stack)
{
    char *                              value;
    char *                              driver_name;
    char *                              ptr;
    char *                              opts;
    globus_result_t                     result;
    globus_bool_t                       done = GLOBUS_FALSE;
    gfs_l_file_stack_entry_t *          stack_ent;
    globus_xio_driver_t                 driver;
    globus_list_t *                     list;
    globus_list_t *                     driver_list = NULL;
    GlobusGFSName(globus_l_gfs_file_make_stack);

    value = globus_gfs_config_get_string("file_stack");

    if(value == NULL)
    {
        result = globus_xio_stack_push_driver(
            stack, globus_l_gfs_file_driver);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_xio_stack_push_driver", result);
            goto error_push;
        }
    }
    else
    {
        value = strdup(value);
        while(!done)
        {
            driver_name = value;
            ptr = strchr(driver_name, ',');
            if(ptr != NULL)
            {
                *ptr = '\0';
                value = ptr+1; /* move to next line */
            }
            else
            {
                done = GLOBUS_TRUE;
            }
            opts = strchr(driver_name, ':');
            if(opts != NULL)
            {
                *opts = '\0';
                opts++;
            }

            if(strcmp(driver_name, "file") == 0)
            {
                driver = globus_l_gfs_file_driver;
            }
            else
            {
                result = globus_xio_driver_load(driver_name, &driver);
                if(result != GLOBUS_SUCCESS)
                {
                    goto error_load;
                }
            }
            stack_ent = (gfs_l_file_stack_entry_t *)
                globus_calloc(1, sizeof(gfs_l_file_stack_entry_t));
            stack_ent->opts = opts;
            stack_ent->driver = driver;
            stack_ent->driver_name = driver_name;

            globus_list_insert(&driver_list, stack_ent);
        }
        for(list = driver_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            stack_ent = (gfs_l_file_stack_entry_t *) globus_list_first(list);

            result = globus_xio_stack_push_driver(stack, stack_ent->driver);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusGFSErrorWrapFailed(
                    "globus_xio_stack_push_driver", result);
                goto error_push;
            }
            /* this should go away after demo? */
            if(stack_ent->opts != NULL)
            {
                globus_xio_attr_cntl(
                    attr,
                    stack_ent->driver,
                    GLOBUS_XIO_SET_STRING_OPTIONS,
                    stack_ent->opts);
            }
        }
        
        globus_list_destroy_all(driver_list, globus_libc_free);
        globus_free(value);
    }
    return GLOBUS_SUCCESS;

error_load:
    globus_list_destroy_all(driver_list, globus_libc_free);
    globus_free(value);

error_push:
    return result;
}



/*
 * if priority_1 comes after priority_2, return > 0
 * else if priority_1 comes before priority_2, return < 0
 * else return 0
 */
 
static
int
globus_l_gfs_file_queue_compare(
    void *                              priority_1,
    void *                              priority_2)
{
    globus_l_buffer_info_t *            buf_info1;
    globus_l_buffer_info_t *            buf_info2;
    int                                 rc = 0;
    GlobusGFSName(globus_l_gfs_file_queue_compare);
    GlobusGFSFileDebugEnter();

    buf_info1 = (globus_l_buffer_info_t *) priority_1;
    buf_info2 = (globus_l_buffer_info_t *) priority_2;
    
    /* the void * are really just offsets */
    if(buf_info1->offset > buf_info2->offset)
    {
        rc = 1;
    }
    if(buf_info1->offset < buf_info2->offset)
    {
        rc = -1;
    }
    
    GlobusGFSFileDebugExit();
    return rc;
}

static
globus_result_t
globus_l_gfs_file_monitor_init(
    globus_l_file_monitor_t **          u_monitor,
    globus_size_t                       block_size,
    int                                 optimal_count)
{
    globus_l_file_monitor_t *           monitor;
    globus_result_t                     result;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_file_monitor_init);
    GlobusGFSFileDebugEnter();
        
    monitor = (globus_l_file_monitor_t *) globus_malloc(
        sizeof(globus_l_file_monitor_t));
    if(!monitor)
    {
        result = GlobusGFSErrorMemory("monitor");
        goto error_alloc;
    }
       
    rc = globus_memory_init(&monitor->mem, block_size, optimal_count);
    if(!rc)
    {
        globus_free(monitor);
        result = GlobusGFSErrorMemory("buffer");
        goto error_alloc;
    } 
    
    globus_mutex_init(&monitor->lock, NULL);
    globus_priority_q_init(
        &monitor->queue, globus_l_gfs_file_queue_compare);
    monitor->buffer_list = NULL;
    monitor->op = NULL;
    monitor->file_handle = NULL;
    monitor->pending_reads = 0;
    monitor->pending_writes = 0;
    monitor->file_offset = 0;
/*
    monitor->write_delta = 0;
    monitor->transfer_delta = 0;  */  
    monitor->block_size = block_size;
    monitor->optimal_count = optimal_count;
    monitor->error = NULL;
    monitor->eof = GLOBUS_FALSE;
    monitor->aborted = GLOBUS_FALSE;
    monitor->concurrency_check = 2;
    monitor->concurrency_check_interval = 2;
        
    *u_monitor = monitor;
    
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;

error_alloc:
    GlobusGFSFileDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_file_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_file_close_cb);
    GlobusGFSFileDebugEnter();
    /* dont need to do anything here */
    GlobusGFSFileDebugExit();
}

static
void
globus_l_gfs_file_monitor_destroy(
    globus_l_file_monitor_t *           monitor)
{
    globus_l_buffer_info_t *            buf_info;
    globus_list_t *                     list;
    globus_byte_t *                     buffer;
    GlobusGFSName(globus_l_gfs_file_monitor_destroy);
    GlobusGFSFileDebugEnter();
    
    if(monitor->file_handle)
    {
        globus_xio_register_close(
            monitor->file_handle,
            NULL,
            globus_l_gfs_file_close_cb,
            NULL);
    }
            
    while(!globus_priority_q_empty(&monitor->queue))
    {
        buf_info = (globus_l_buffer_info_t *)
            globus_priority_q_dequeue(&monitor->queue);
        if(buf_info)
        {
            if(buf_info->buffer)
            {
                globus_memory_push_node(&monitor->mem, buf_info->buffer);
            }
            globus_free(buf_info);
        }
    }
    
    for(list = monitor->buffer_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        buffer = (globus_byte_t *) globus_list_first(list);
        globus_memory_push_node(&monitor->mem, buffer);
    }
    
    globus_priority_q_destroy(&monitor->queue);
    globus_list_free(monitor->buffer_list);
    globus_memory_destroy(&monitor->mem);
    globus_mutex_destroy(&monitor->lock);
    globus_free(monitor);

    GlobusGFSFileDebugExit();
}

/**
 * stat calls
 */
 
/* basepath and filename must be MAXPATHLEN long 
 * the pathname may be absolute or relative, basepath will be the same */
static
void
globus_l_gfs_file_partition_path(
    const char *                        pathname,
    char *                              basepath,
    char *                              filename)
{
    char                                buf[MAXPATHLEN];
    char *                              filepart;
    GlobusGFSName(globus_l_gfs_file_partition_path);
    GlobusGFSFileDebugEnter();
    
    strncpy(buf, pathname, MAXPATHLEN);
    buf[MAXPATHLEN - 1] = '\0';
    
    filepart = strrchr(buf, '/');
    while(filepart && !*(filepart + 1) && filepart != buf)
    {
        *filepart = '\0';
        filepart = strrchr(buf, '/');
    }

    if(!filepart)
    {
        strcpy(filename, buf);
        basepath[0] = '\0';
    }
    else
    {
        if(filepart == buf)
        {
            if(!*(filepart + 1))
            {
                basepath[0] = '\0';
                filename[0] = '/';
                filename[1] = '\0';
            }
            else
            {
                *filepart++ = '\0';
                basepath[0] = '/';
                basepath[1] = '\0';
                strcpy(filename, filepart);
            }
        }
        else
        {                
            *filepart++ = '\0';
            strcpy(basepath, buf);
            strcpy(filename, filepart);
        }
    }    

    GlobusGFSFileDebugExit();
}

static
void
globus_l_gfs_file_copy_stat(
    globus_gfs_stat_t *                 stat_object,
    struct stat *                       stat_buf,
    const char *                        filename,
    const char *                        symlink_target)
{
    GlobusGFSName(globus_l_gfs_file_copy_stat);
    GlobusGFSFileDebugEnter();

    stat_object->mode     = stat_buf->st_mode;
    stat_object->nlink    = stat_buf->st_nlink;
    stat_object->uid      = stat_buf->st_uid;
    stat_object->gid      = stat_buf->st_gid;
    stat_object->size     = stat_buf->st_size;
    stat_object->mtime    = stat_buf->st_mtime;
    stat_object->atime    = stat_buf->st_atime;
    stat_object->ctime    = stat_buf->st_ctime;
    stat_object->dev      = stat_buf->st_dev;
    stat_object->ino      = stat_buf->st_ino;
    
    if(filename && *filename)
    {
        stat_object->name = globus_libc_strdup(filename);
    }
    else
    {
        stat_object->name = NULL;
    }
    if(symlink_target && *symlink_target)
    {
        stat_object->symlink_target = globus_libc_strdup(symlink_target);
    }
    else
    {
        stat_object->symlink_target = NULL;
    }

    GlobusGFSFileDebugExit();
}
static
void
globus_l_gfs_file_destroy_stat(
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count)
{
    int                                 i;
    GlobusGFSName(globus_l_gfs_file_destroy_stat);
    GlobusGFSFileDebugEnter();
        
    for(i = 0; i < stat_count; i++)
    {
        if(stat_array[i].name != NULL)
        {
            globus_free(stat_array[i].name);
        }        
        if(stat_array[i].symlink_target != NULL)
        {
            globus_free(stat_array[i].symlink_target);
        }
    }
    globus_free(stat_array);     

    GlobusGFSFileDebugExit();
}
    

static
void
globus_l_gfs_file_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    struct stat                         stat_buf;
    globus_gfs_stat_t *                 stat_array;
    int                                 stat_count = 0;
    DIR *                               dir;
    char                                basepath[MAXPATHLEN];
    char                                filename[MAXPATHLEN];
    char                                symlink_target[MAXPATHLEN];
    GlobusGFSName(globus_l_gfs_file_stat);
    GlobusGFSFileDebugEnter();
    
    /* lstat is the same as stat when not operating on a link */
    if(lstat(stat_info->pathname, &stat_buf) != 0)
    {
        result = GlobusGFSErrorSystemError("stat", errno);
        goto error_stat1;
    }
    /* if this is a link we still need to stat to get the info we are 
        interested in and then use realpath() to get the full path of 
        the symlink target */
    *symlink_target = '\0';
    if(S_ISLNK(stat_buf.st_mode))
    {
        if(stat(stat_info->pathname, &stat_buf) != 0)
        {
            result = GlobusGFSErrorSystemError("stat", errno);
            goto error_stat1;
        }
        if(realpath(stat_info->pathname, symlink_target) == NULL)
        {
            result = GlobusGFSErrorSystemError("realpath", errno);
            goto error_stat1;
        }
    }    
    globus_l_gfs_file_partition_path(stat_info->pathname, basepath, filename);
    
    if(!S_ISDIR(stat_buf.st_mode) || stat_info->file_only)
    {
        stat_array = (globus_gfs_stat_t *)
            globus_malloc(sizeof(globus_gfs_stat_t));
        if(!stat_array)
        {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc1;
        }
        
        globus_l_gfs_file_copy_stat(
            stat_array, &stat_buf, filename, symlink_target);
        stat_count = 1;
    }
    else
    {
        struct dirent *                 dir_entry;
        int                             i;
        char                            dir_path[MAXPATHLEN];
    
        dir = globus_libc_opendir(stat_info->pathname);
        if(!dir)
        {
            result = GlobusGFSErrorSystemError("opendir", errno);
            goto error_open;
        }
        
        stat_count = 0;
        while(globus_libc_readdir_r(dir, &dir_entry) == 0 && dir_entry)
        {
            stat_count++;
            globus_free(dir_entry);
        }
        
        globus_libc_rewinddir(dir);
        
        stat_array = (globus_gfs_stat_t *)
            globus_malloc(sizeof(globus_gfs_stat_t) * stat_count);
        if(!stat_array)
        {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc2;
        }
        
        snprintf(dir_path, sizeof(dir_path), "%s/%s", basepath, filename);
        dir_path[MAXPATHLEN - 1] = '\0';
        
        for(i = 0;
            globus_libc_readdir_r(dir, &dir_entry) == 0 && dir_entry;
            i++)
        {
            char                        path[MAXPATHLEN];
                
            snprintf(path, sizeof(path), "%s/%s", dir_path, dir_entry->d_name);
            path[MAXPATHLEN - 1] = '\0';
        
            /* lstat is the same as stat when not operating on a link */
            if(lstat(path, &stat_buf) != 0)
            {
                result = GlobusGFSErrorSystemError("lstat", errno);
                globus_free(dir_entry);
                /* just skip invalid entries */
                stat_count--;
                i--;
                continue;
            }
            /* if this is a link we still need to stat to get the info we are 
                interested in and then use realpath() to get the full path of 
                the symlink target */
            *symlink_target = '\0';
            if(S_ISLNK(stat_buf.st_mode))
            {
                if(stat(path, &stat_buf) != 0)
                {
                    result = GlobusGFSErrorSystemError("stat", errno);
                    globus_free(dir_entry);
                    /* just skip invalid entries */
                    stat_count--;
                    i--;
                    continue;
                }
                if(realpath(path, symlink_target) == NULL)
                {
                    result = GlobusGFSErrorSystemError("realpath", errno);
                    globus_free(dir_entry);
                    /* just skip invalid entries */
                    stat_count--;
                    i--;
                    continue;
                }
            }    
     
            globus_l_gfs_file_copy_stat(
                &stat_array[i], &stat_buf, dir_entry->d_name, symlink_target);
            globus_free(dir_entry);
        }
        
        if(i != stat_count)
        {
            result = GlobusGFSErrorSystemError("readdir", errno);
            goto error_read;
        }
        
        closedir(dir);
    }
    
    globus_gridftp_server_finished_stat(
        op, GLOBUS_SUCCESS, stat_array, stat_count);
    
    
    globus_l_gfs_file_destroy_stat(stat_array, stat_count);
    
    GlobusGFSFileDebugExit();
    return;

error_read:
    globus_l_gfs_file_destroy_stat(stat_array, stat_count);
    
error_alloc2:
    closedir(dir);
    
error_open:
error_alloc1:
error_stat1:
    globus_gridftp_server_finished_stat(op, result, NULL, 0);

    GlobusGFSFileDebugExitWithError();
}

static
globus_result_t
globus_l_gfs_file_mkdir(
    globus_gfs_operation_t   op,
    const char *                        pathname)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_mkdir);
    GlobusGFSFileDebugEnter();

    rc = mkdir(pathname, 0777);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("mkdir", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, NULL);
        
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;
    
error:
    GlobusGFSFileDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_gfs_file_rmdir(
    globus_gfs_operation_t   op,
    const char *                        pathname)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_rmdir);
    GlobusGFSFileDebugEnter();

    rc = rmdir(pathname);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("rmdir", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, NULL);
        
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;
    
error:
    GlobusGFSFileDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_gfs_file_delete_dir(
    const char *                        pathname)
{

    globus_result_t                     result;
    int                                 rc;
    DIR *                               dir;
    struct stat                         stat_buf;
    struct dirent *                     dir_entry;
    int                                 i;
    char                                path[MAXPATHLEN];
    GlobusGFSName(globus_l_gfs_file_delete_dir);
    GlobusGFSFileDebugEnter();
    
    /* lstat is the same as stat when not operating on a link */
    if(lstat(pathname, &stat_buf) != 0)
    {
        result = GlobusGFSErrorSystemError("stat", errno);
        goto error_stat;
    }
    
    if(!S_ISDIR(stat_buf.st_mode))
    {
        /* remove anything that isn't a dir -- don't follow links */
        rc = unlink(pathname);       
        if(rc != 0)
        {
            result = GlobusGFSErrorSystemError("unlink", errno);
            goto error_unlink1;
        }
    }
    else
    {
        dir = globus_libc_opendir(pathname);
        if(!dir)
        {
            result = GlobusGFSErrorSystemError("opendir", errno);
            goto error_open;
        }
        
        for(i = 0;
            globus_libc_readdir_r(dir, &dir_entry) == 0 && dir_entry;
            i++)
        {   
            if(dir_entry->d_name[0] == '.' && 
                (dir_entry->d_name[1] == '\0' || 
                (dir_entry->d_name[1] == '.' && dir_entry->d_name[2] == '\0')))
            {
                globus_free(dir_entry);
                continue;
            }
            snprintf(path, sizeof(path), "%s/%s", pathname, dir_entry->d_name);
            path[MAXPATHLEN - 1] = '\0';
              
            /* lstat is the same as stat when not operating on a link */
            if(lstat(path, &stat_buf) != 0)
            {
                result = GlobusGFSErrorSystemError("lstat", errno);
                globus_free(dir_entry);
                /* just skip invalid entries */
                continue;
            }
            
            if(!S_ISDIR(stat_buf.st_mode))
            {
                /* remove anything that isn't a dir -- don't follow links */
                rc = unlink(path);       
                if(rc != 0)
                {
                    result = GlobusGFSErrorSystemError("unlink", errno);
                    goto error_unlink2;
                }
            }
            else
            {
                result = globus_l_gfs_file_delete_dir(path);
                if(result != GLOBUS_SUCCESS)
                {
                    goto error_recurse;
                }
            }

            globus_free(dir_entry);
        }

        closedir(dir);
        rc = rmdir(pathname);
        if(rc != 0)
        {
            result = GlobusGFSErrorSystemError("rmmdir", errno);
            goto error_rmdir;
        }
    } 
    
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;

error_rmdir:    
error_recurse:
error_unlink2:
        closedir(dir);
        globus_free(dir_entry);
error_open: 
error_stat:
error_unlink1:
    GlobusGFSFileDebugExitWithError();
    return result; 
}
    
static
globus_result_t
globus_l_gfs_file_delete(
    globus_gfs_operation_t              op,
    const char *                        pathname,
    globus_bool_t                       recurse)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_delete);
    GlobusGFSFileDebugEnter();

    if(!recurse)
    {
        rc = unlink(pathname);
        if(rc != 0)
        {
            result = GlobusGFSErrorSystemError("unlink", errno);
            goto error;
        }
    }
    else
    {
        result = globus_l_gfs_file_delete_dir(pathname);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed("recursion", result);
            goto error;
        }
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, NULL);
        
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;
    
error:
    GlobusGFSFileDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_gfs_file_rename(
    globus_gfs_operation_t   op,
    const char *                        from_pathname,
    const char *                        to_pathname)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_rename);
    GlobusGFSFileDebugEnter();

    rc = rename(from_pathname, to_pathname);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("rename", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, NULL);
        
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;
    
error:
    GlobusGFSFileDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_gfs_file_chmod(
    globus_gfs_operation_t   op,
    const char *                        pathname,
    mode_t                              mode)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_chmod);
    GlobusGFSFileDebugEnter();

    rc = chmod(pathname, mode);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("chmod", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, NULL);
        
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;
    
error:
    GlobusGFSFileDebugExitWithError();
    return result;
}

typedef struct globus_l_gfs_file_cksm_monitor_s
{

    globus_gfs_operation_t              op;
    globus_off_t                        offset;
    globus_off_t                        length;
    globus_off_t                        count;
    globus_off_t                        read_left;
    globus_size_t                       block_size;
    MD5_CTX                             mdctx;
    globus_byte_t                       buffer[1];
} globus_l_gfs_file_cksm_monitor_t;

static
void
globus_l_gfs_file_cksm_read_cb(
    globus_xio_handle_t                 handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_gfs_file_cksm_monitor_t *  monitor;
    globus_bool_t                       eof = GLOBUS_FALSE;
    char *                              md5ptr;
    unsigned char                       md[MD5_DIGEST_LENGTH];
    char                                md5sum[MD5_DIGEST_LENGTH * 2 + 1];
    int                                 i;    
    GlobusGFSName(globus_l_gfs_file_cksm_read_cb);
    GlobusGFSFileDebugEnter();
    
    monitor = (globus_l_gfs_file_cksm_monitor_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        if(globus_xio_error_is_eof(result))
        {
            eof = GLOBUS_TRUE;
        }
        else
        {
            result = GlobusGFSErrorWrapFailed(
                "checksum read callback", result);
            goto error_read;
        }
    }        
    if(monitor->length >= 0)
    {
        monitor->read_left -= nbytes;
        monitor->count = (monitor->read_left > monitor->block_size) ? 
            monitor->block_size : monitor->read_left;
        if(monitor->read_left == 0)
        {
            eof = GLOBUS_TRUE;
        }
    }

    MD5_Update(&monitor->mdctx, buffer, nbytes);

    if(!eof)
    {
        result = globus_xio_register_read(
            handle,
            monitor->buffer,
            monitor->count,
            monitor->count,
            NULL,
            globus_l_gfs_file_cksm_read_cb,
            monitor);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_xio_register_read", result);
            goto error_register;
        }
    }
    else
    {
        MD5_Final(md, &monitor->mdctx);
    
        globus_xio_register_close(
            handle,
            NULL,
            globus_l_gfs_file_close_cb,
            NULL);
            
        md5ptr = md5sum;
        for(i = 0; i < MD5_DIGEST_LENGTH; i++)
        {
           sprintf(md5ptr, "%02x", md[i]);
           md5ptr++;
           md5ptr++;
        }
        md5ptr = '\0';
            
        globus_gridftp_server_finished_command(
            monitor->op, GLOBUS_SUCCESS, md5sum);
        
        globus_free(monitor);
            
    }        
    GlobusGFSFileDebugExit();
    return;
        

error_register:
error_read:
    globus_xio_close(handle, NULL);
    handle = NULL;
    globus_gridftp_server_finished_command(monitor->op, result, NULL);    
    globus_free(monitor);
    
    GlobusGFSFileDebugExitWithError();
}



static
void
globus_l_gfs_file_open_cksm_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{  
    globus_l_gfs_file_cksm_monitor_t *  monitor;
    GlobusGFSName(globus_l_gfs_file_open_cksm_cb);
    GlobusGFSFileDebugEnter();
    
    monitor = (globus_l_gfs_file_cksm_monitor_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "open", result);
        goto error_open;  
    }  
    
    if(monitor->length >= 0)
    {
        monitor->read_left = monitor->length;
        monitor->count = (monitor->read_left > monitor->block_size) ? 
            monitor->block_size : monitor->read_left;
    }
    else
    {
        monitor->count = monitor->block_size;
    }
    
    if(monitor->offset > 0)
    {
        result = globus_xio_handle_cntl(
            handle,
            globus_l_gfs_file_driver,
            GLOBUS_XIO_FILE_SEEK,
            &monitor->offset,
            GLOBUS_XIO_FILE_SEEK_SET);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_xio_handle_cntl", result);
            goto error_seek;
        }
    }
    
    MD5_Init(&monitor->mdctx);  
    
    result = globus_xio_register_read(
        handle,
        monitor->buffer,
        monitor->count,
        monitor->count,
        NULL,
        globus_l_gfs_file_cksm_read_cb,
        monitor);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_xio_register_read", result);
        goto error_register;
    }

    GlobusGFSFileDebugExit();
    return;
        
error_register:
error_seek:
error_open:
    globus_xio_close(handle, NULL);
    handle = NULL;
    globus_gridftp_server_finished_command(monitor->op, result, NULL);    
    globus_free(monitor);
    
    GlobusGFSFileDebugExitWithError();
}


static
globus_result_t
globus_l_gfs_file_cksm(
    globus_gfs_operation_t              op,
    const char *                        pathname,
    const char *                        algorithm,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    globus_result_t                     result;
    globus_xio_attr_t                   attr;
    globus_xio_stack_t                  stack;
    globus_xio_handle_t                 file_handle;
    globus_l_gfs_file_cksm_monitor_t *  monitor;
    globus_size_t                       block_size;
    GlobusGFSName(globus_l_gfs_file_cksm);
    GlobusGFSFileDebugEnter();
    
    if(offset < 0)
    {
        result = GlobusGFSErrorGeneric("Invalid offset.");
        goto param_error;
    }
        
    result = globus_xio_attr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_attr_init", result);
        goto error_attr;
    }

    result = globus_xio_attr_cntl(
        attr,
        globus_l_gfs_file_driver,
        GLOBUS_XIO_FILE_SET_FLAGS,
        O_RDONLY);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_attr_init", result);
        goto error_cntl;
    }
    
    result = globus_xio_stack_init(&stack, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_stack_init", result);
        goto error_stack;
    }
    
    result = globus_xio_stack_push_driver(stack, globus_l_gfs_file_driver);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_xio_stack_push_driver", result);
        goto error_push;
    }

    result = globus_xio_handle_create(&file_handle, stack);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_handle_create", result);
        goto error_create;
    }

    block_size = GLOBUS_L_GFS_FILE_CKSM_BS;

    monitor = (globus_l_gfs_file_cksm_monitor_t *) globus_calloc(
        1, sizeof(globus_l_gfs_file_cksm_monitor_t) + block_size);
    if(monitor == NULL)
    {
        result = GlobusGFSErrorMemory("cheksum buffer");
        goto error_mem;
    }
    
    monitor->op = op;
    monitor->offset = offset;
    monitor->length = length;
    monitor->block_size = block_size;

    result = globus_xio_register_open(
        file_handle,
        pathname,
        attr,
        globus_l_gfs_file_open_cksm_cb,
        monitor);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_register_open", result);
        goto error_register;
    }
    
    globus_xio_attr_destroy(attr);
    globus_xio_stack_destroy(stack);
    
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    globus_xio_close(file_handle, NULL);
    file_handle = NULL;
    globus_free(monitor);
    
error_mem:
error_create:
error_push:
    globus_xio_stack_destroy(stack);
    
error_stack:
error_cntl:    
    globus_xio_attr_destroy(attr);
    
error_attr:
param_error:
    GlobusGFSFileDebugExitWithError();
    return result;
}     

static
void
globus_l_gfs_file_command(
    globus_gfs_operation_t   op,
    globus_gfs_command_info_t *        cmd_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_command);
    GlobusGFSFileDebugEnter();

    switch(cmd_info->command)
    {
      case GLOBUS_GFS_CMD_MKD:
        result = globus_l_gfs_file_mkdir(op, cmd_info->pathname);
        break;
      case GLOBUS_GFS_CMD_RMD:
        result = globus_l_gfs_file_rmdir(op, cmd_info->pathname);
        break;
      case GLOBUS_GFS_CMD_DELE:
        result = globus_l_gfs_file_delete(
            op, cmd_info->pathname, GLOBUS_FALSE);
        break;
      case GLOBUS_GFS_CMD_SITE_RDEL:
        result = globus_l_gfs_file_delete(
            op, cmd_info->pathname, GLOBUS_TRUE);
        break;
      case GLOBUS_GFS_CMD_RNTO:
        result = globus_l_gfs_file_rename(
            op, cmd_info->rnfr_pathname, cmd_info->pathname);
        break;
      case GLOBUS_GFS_CMD_SITE_CHMOD:
        result = globus_l_gfs_file_chmod(
            op, cmd_info->pathname, cmd_info->chmod_mode);
        break;
      case GLOBUS_GFS_CMD_CKSM:
        result = globus_l_gfs_file_cksm(
            op, 
            cmd_info->pathname, 
            cmd_info->cksm_alg,
            cmd_info->cksm_offset,
            cmd_info->cksm_length);
        break;
      
      default:
        result = GLOBUS_FAILURE;
        break;
    }

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    GlobusGFSFileDebugExit();
    return;

error:
    globus_gridftp_server_finished_command(op, result, NULL);    

    GlobusGFSFileDebugExitWithError();
}

/**
 * recv calls
 */

static
void
globus_l_gfs_file_server_read_cb(
    globus_gfs_operation_t   op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg);

static
globus_result_t
globus_l_gfs_file_dispatch_write(
    globus_l_file_monitor_t *           monitor);
    
static
void
globus_l_gfs_file_write_cb(
    globus_xio_handle_t                 xio_handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_file_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_write_cb);
    GlobusGFSFileDebugEnter();
    
    monitor = (globus_l_file_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    { 
        monitor->pending_writes--;
        globus_gridftp_server_update_bytes_written(
            monitor->op, 
            monitor->file_offset /* + monitor->transfer_delta */,
            nbytes);
        monitor->file_offset += nbytes;

        if(result != GLOBUS_SUCCESS && monitor->error == NULL)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed("callback", result);
        }
        if(monitor->error != NULL)
        {
            goto error;
        }
        
        if(!monitor->eof)
        {
            result = globus_gridftp_server_register_read(
                monitor->op,
                buffer,
                monitor->block_size,
                globus_l_gfs_file_server_read_cb,
                monitor);
            if(result != GLOBUS_SUCCESS)
            {
                monitor->error = GlobusGFSErrorObjWrapFailed(
                    "globus_gridftp_server_register_read", result);
                goto error;
            }
            
            monitor->pending_reads++;
        }
        else
        {
            globus_memory_push_node(&monitor->mem, buffer);
        }
        
        result = globus_l_gfs_file_dispatch_write(monitor);
        if(result != GLOBUS_SUCCESS)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed(
                "globus_l_gfs_file_dispatch_write", result);
            goto error_dispatch;
        }
        
        if(monitor->pending_reads == 0 && monitor->pending_writes == 0)
        {
            globus_assert(monitor->eof || monitor->aborted);
            globus_mutex_unlock(&monitor->lock);
            globus_gridftp_server_finished_transfer(
                monitor->op, GLOBUS_SUCCESS);
            globus_l_gfs_file_monitor_destroy(monitor);
        }
        else
        {
            globus_mutex_unlock(&monitor->lock);
        }
    }
    /* already unlocked */
    
    GlobusGFSFileDebugExit();
    return;

error:
    globus_memory_push_node(&monitor->mem, buffer);
error_dispatch:
    if(monitor->pending_reads != 0 || monitor->pending_writes != 0)
    {
        /* there are still outstanding callbacks, wait for them */
        globus_mutex_unlock(&monitor->lock);
    
        GlobusGFSFileDebugExitWithError();
        return;
    }
    globus_mutex_unlock(&monitor->lock);

    globus_gridftp_server_finished_transfer(
        monitor->op, globus_error_put(monitor->error));
    globus_l_gfs_file_monitor_destroy(monitor);

    GlobusGFSFileDebugExitWithError();
}

/* Called LOCKED */
static
globus_result_t
globus_l_gfs_file_dispatch_write(
    globus_l_file_monitor_t *           monitor)
{
    globus_l_buffer_info_t *            buf_info;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_dispatch_write);
    GlobusGFSFileDebugEnter();
    
    if(monitor->pending_writes == 0 && !monitor->aborted)
    {
        buf_info = (globus_l_buffer_info_t *)
            globus_priority_q_dequeue(&monitor->queue);
        if(buf_info)
        {
            if(buf_info->offset != monitor->file_offset)
            { 
                globus_off_t            seek_tmp;

                monitor->file_offset = buf_info->offset;
                seek_tmp = monitor->file_offset;

                result = globus_xio_handle_cntl(
                    monitor->file_handle,
                    globus_l_gfs_file_driver,
                    GLOBUS_XIO_FILE_SEEK,
                    &seek_tmp,
                    GLOBUS_XIO_FILE_SEEK_SET);
                if(result != GLOBUS_SUCCESS)
                {
                    result = GlobusGFSErrorWrapFailed(
                        "globus_xio_handle_cntl", result);
                    goto error_seek;
                }
            }
            
            result = globus_xio_register_write(
                monitor->file_handle,
                buf_info->buffer,
                buf_info->length,
                buf_info->length,
                NULL,
                globus_l_gfs_file_write_cb,
                monitor);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusGFSErrorWrapFailed(
                    "globus_xio_register_write", result);
                goto error_register;
            }
            
            monitor->pending_writes++;
            
            globus_free(buf_info);
        }
    }
    
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;

error_register:
error_seek:
    if(buf_info->buffer)
    {
        globus_memory_push_node(&monitor->mem, buf_info->buffer);
    }
    globus_free(buf_info);

    GlobusGFSFileDebugExitWithError();
    return result;
}

/* called locked */
static
void
globus_l_gfs_file_update_concurrency(
    globus_l_file_monitor_t *           monitor)
{
    globus_result_t                     result;
    int                                 optimal_count;
    int                                 extra;
    GlobusGFSName(globus_l_gfs_file_update_concurrency);
    GlobusGFSFileDebugEnter();
    
    if(!monitor->eof)
    {
        monitor->concurrency_check = monitor->concurrency_check_interval;
        monitor->concurrency_check_interval *= 2;
        if(monitor->concurrency_check_interval > 1024)
        {
            monitor->concurrency_check_interval = 1024;
        }
        
        globus_gridftp_server_get_optimal_concurrency(
            monitor->op, &optimal_count);
        extra = optimal_count - monitor->optimal_count;
            
        monitor->optimal_count = optimal_count;
        while(extra-- > 0)
        {
            globus_byte_t *             buffer;
            
            buffer = globus_memory_pop_node(&monitor->mem);
            result = globus_gridftp_server_register_read(
                monitor->op,
                buffer,
                monitor->block_size,
                globus_l_gfs_file_server_read_cb,
                monitor);
            if(result != GLOBUS_SUCCESS)
            {
                globus_memory_push_node(&monitor->mem, buffer);
                result = GlobusGFSErrorWrapFailed(
                    "globus_gridftp_server_register_read", result);
                goto error_register;
            }
            
            monitor->pending_reads++;
        }
    }
    
    GlobusGFSFileDebugExit();
    return;

error_register:
    GlobusGFSFileDebugExitWithError();
}

static
void
globus_l_gfs_file_server_read_cb(
    globus_gfs_operation_t   op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg)
{
    globus_l_file_monitor_t *           monitor;
    globus_l_buffer_info_t *            buf_info;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_file_server_read_cb);
    GlobusGFSFileDebugEnter();
    
    monitor = (globus_l_file_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    {
        monitor->pending_reads--;
        if(result != GLOBUS_SUCCESS && monitor->error == NULL)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed("callback", result);
        }
        if(monitor->error != NULL)
        {
            goto error;
        }
        
        if(eof)
        {
            monitor->eof = GLOBUS_TRUE;
        }
        
        buf_info = (globus_l_buffer_info_t *) 
            globus_malloc(sizeof(globus_l_buffer_info_t));
        if(!buf_info)
        {
            monitor->error = GlobusGFSErrorObjMemory("buf_info");
            goto error_alloc;
        }
        
        /* XXX offset may need some interpretation here depending on type of
         * transfer (may need to remember original start offset)
         */
        buf_info->buffer = buffer;
        buf_info->offset = offset;
        buf_info->length = nbytes;
        
        rc = globus_priority_q_enqueue(
            &monitor->queue, buf_info, buf_info);
        if(rc != GLOBUS_SUCCESS)
        {
            monitor->error = GlobusGFSErrorObjGeneric(
                "globus_priority_q_enqueue failed");
            goto error_enqueue;
        }

        monitor->concurrency_check--;
        if(monitor->concurrency_check == 0 && !eof)
        {
            globus_l_gfs_file_update_concurrency(monitor);
        }        
        
        result = globus_l_gfs_file_dispatch_write(monitor);
        if(result != GLOBUS_SUCCESS)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed(
                "globus_l_gfs_file_dispatch_write", result);
            goto error_dispatch;
        }
    }
    globus_mutex_unlock(&monitor->lock);
    
    GlobusGFSFileDebugExit();
    return;
    
error_dispatch:
    /* can't free buf_info, its in queue */
    if(0)
    {
error_enqueue:
        globus_free(buf_info);
    }
    
error_alloc:
error:
    globus_memory_push_node(&monitor->mem, buffer);
    if(monitor->pending_reads != 0 || monitor->pending_writes != 0)
    {
        /* there are still outstanding callbacks, wait for them */
        globus_mutex_unlock(&monitor->lock);

        GlobusGFSFileDebugExitWithError();
        return;
    }
    globus_mutex_unlock(&monitor->lock);

    globus_gridftp_server_finished_transfer(
        monitor->op, globus_error_put(monitor->error));
    globus_l_gfs_file_monitor_destroy(monitor);

    GlobusGFSFileDebugExitWithError();
}

static
void
globus_l_gfs_file_open_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_file_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_open_write_cb);
    GlobusGFSFileDebugEnter();
    
    monitor = (globus_l_file_monitor_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_file_open_write_cb", result);
        monitor->file_handle = NULL;
        goto error_open;
    }

    globus_gridftp_server_begin_transfer(
        monitor->op, 0, monitor);
    
    globus_mutex_lock(&monitor->lock);
    {
        int                             optimal_count;
        globus_size_t                   block_size;
        
        optimal_count = monitor->optimal_count;
        block_size = monitor->block_size;
        while(optimal_count--)
        {
            globus_byte_t *             buffer;
            
            buffer = globus_memory_pop_node(&monitor->mem);
            result = globus_gridftp_server_register_read(
                monitor->op,
                buffer,
                block_size,
                globus_l_gfs_file_server_read_cb,
                monitor);
            if(result != GLOBUS_SUCCESS)
            {
                globus_memory_push_node(&monitor->mem, buffer);
                result = GlobusGFSErrorWrapFailed(
                    "globus_gridftp_server_register_read", result);
                goto error_register;
            }
            
            monitor->pending_reads++;
        }
    }
    globus_mutex_unlock(&monitor->lock);
    
    GlobusGFSFileDebugExit();
    return;

error_register:
    if(monitor->pending_reads != 0)
    {
        /* there are pending reads, need to wait for them */
        monitor->error = globus_error_get(result);
        globus_mutex_unlock(&monitor->lock);

        GlobusGFSFileDebugExitWithError();
        return;
    }
    globus_mutex_unlock(&monitor->lock);

error_open:
    globus_gridftp_server_finished_transfer(monitor->op, result);
    globus_l_gfs_file_monitor_destroy(monitor);

    GlobusGFSFileDebugExitWithError();
}

static
void
globus_l_gfs_file_open_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg);
    
static
globus_result_t
globus_l_gfs_file_open(
    globus_xio_handle_t *               file_handle,
    const char *                        pathname,
    globus_xio_file_flag_t              open_flags,
    void *                              arg)
{
    globus_result_t                     result;
    globus_xio_attr_t                   attr;
    globus_xio_stack_t                  stack;
    GlobusGFSName(globus_l_gfs_file_open);
    GlobusGFSFileDebugEnter();
    
    result = globus_xio_attr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_attr_init", result);
        goto error_attr;
    }
    
    /* XXX should probably have an option to specify create mode.
     * for now, just the default (u+rw)
     */     
    result = globus_xio_attr_cntl(
        attr,
        globus_l_gfs_file_driver,
        GLOBUS_XIO_FILE_SET_FLAGS,
        open_flags);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_attr_init", result);
        goto error_cntl;
    }
    
    result = globus_xio_stack_init(&stack, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_stack_init", result);
        goto error_stack;
    }
    result = globus_l_gfs_file_make_stack(arg, attr, stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_push;
    }

    result = globus_xio_handle_create(file_handle, stack);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_handle_create", result);
        goto error_create;
    }
    
    result = globus_xio_register_open(
        *file_handle,
        pathname,
        attr,
        (open_flags & GLOBUS_XIO_FILE_CREAT) ? 
            globus_l_gfs_file_open_write_cb : 
            globus_l_gfs_file_open_read_cb,
        arg);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_xio_register_open", result);
        goto error_register;
    }
    
    globus_xio_attr_destroy(attr);
    globus_xio_stack_destroy(stack);
    
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;

error_register:
    globus_xio_close(*file_handle, NULL);
    *file_handle = NULL;
error_create:
error_push:
    globus_xio_stack_destroy(stack);
    
error_stack:
error_cntl:    
    globus_xio_attr_destroy(attr);
    
error_attr:
    GlobusGFSFileDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_file_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_file_monitor_t *           monitor;
    int                                 optimal_count;
    globus_size_t                       block_size;
    globus_xio_file_flag_t              open_flags;
    globus_off_t                        offset;
    globus_off_t                        length;
    GlobusGFSName(globus_l_gfs_file_recv);
    GlobusGFSFileDebugEnter();

    globus_gridftp_server_get_optimal_concurrency(op, &optimal_count);
    globus_gridftp_server_get_block_size(op, &block_size);
    globus_assert(optimal_count > 0 && block_size > 0);

    result = globus_l_gfs_file_monitor_init(
        &monitor, block_size, optimal_count);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_file_monitor_init", result);
        goto error_alloc;
    }
    
    globus_gridftp_server_get_write_range(
        op,
        &offset,
        &length);  /*,
        &monitor->write_delta, 
        &monitor->transfer_delta);*/
    
    monitor->op = op;
    open_flags = GLOBUS_XIO_FILE_BINARY | 
        GLOBUS_XIO_FILE_CREAT | 
        GLOBUS_XIO_FILE_WRONLY;
    if(transfer_info->truncate)
    {
        open_flags |= GLOBUS_XIO_FILE_TRUNC;
    }
        
    result = globus_l_gfs_file_open(
        &monitor->file_handle, transfer_info->pathname, open_flags, monitor);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_l_gfs_file_open", result);
        goto error_open;
    }
    
    GlobusGFSFileDebugExit();
    return;

error_open:
    globus_l_gfs_file_monitor_destroy(monitor);
    
error_alloc:
    globus_gridftp_server_finished_transfer(op, result);

    GlobusGFSFileDebugExitWithError();
}

/**
 * send calls
 */

static
void
globus_l_gfs_file_read_cb(
    globus_xio_handle_t                 xio_handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);
    
/* called LOCKED */
static
globus_result_t
globus_l_gfs_file_dispatch_read(
    globus_l_file_monitor_t *           monitor)
{
    globus_result_t                     result;
    globus_byte_t *                     buffer;
    globus_size_t                       read_length;
    GlobusGFSName(globus_l_gfs_file_dispatch_read);
    GlobusGFSFileDebugEnter();
    
    if(monitor->first_read && monitor->pending_reads == 0 && 
        !monitor->eof && !globus_list_empty(monitor->buffer_list) &&
        !monitor->aborted)
    {
        globus_gridftp_server_get_read_range(
            monitor->op,
            &monitor->read_offset,
            &monitor->read_length); /*,
            &monitor->write_delta); */
        if(monitor->read_length == 0)
        {
            monitor->eof = GLOBUS_TRUE;
        }
        else
        {                                        
            if (monitor->file_offset != monitor->read_offset)
            {
                globus_off_t            seek_tmp;
                seek_tmp = monitor->read_offset;
                
                result = globus_xio_handle_cntl(
                    monitor->file_handle,
                    globus_l_gfs_file_driver,
                    GLOBUS_XIO_FILE_SEEK,
                    &seek_tmp,
                    GLOBUS_XIO_FILE_SEEK_SET);
            
                if(result != GLOBUS_SUCCESS)
                {
                    result = GlobusGFSErrorWrapFailed(
                        "globus_xio_handle_cntl", result);
                    goto error_seek;
                }
                monitor->file_offset = monitor->read_offset;
            }
            
        }
        monitor->first_read = GLOBUS_FALSE;
    }             

    if(monitor->pending_reads == 0 && !monitor->eof && 
        !globus_list_empty(monitor->buffer_list) && !monitor->aborted)
    {
        buffer = globus_list_remove(
            &monitor->buffer_list, monitor->buffer_list);
        globus_assert(buffer);
             
        if(monitor->read_length != -1 && 
            monitor->block_size > monitor->read_length)
        {
            read_length = monitor->read_length;
        }
        else
        {
            read_length = monitor->block_size;
        }
        
        result = globus_xio_register_read(
            monitor->file_handle,
            buffer,
            read_length,
            read_length,
            NULL,
            globus_l_gfs_file_read_cb,
            monitor);
        if(result != GLOBUS_SUCCESS)
        {
            globus_list_insert(&monitor->buffer_list, buffer);
            result = GlobusGFSErrorWrapFailed(
                "globus_xio_register_read", result);
            goto error_register;
        }
        
        monitor->pending_reads++;
    }
    
    GlobusGFSFileDebugExit();
    return GLOBUS_SUCCESS;

error_seek:
error_register:
    GlobusGFSFileDebugExitWithError();
    return result;
}

static
void
globus_l_gfs_file_server_write_cb(
    globus_gfs_operation_t   op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_l_file_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_server_write_cb);
    GlobusGFSFileDebugEnter();
    
    monitor = (globus_l_file_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    { 
        monitor->pending_writes--;
        globus_list_insert(&monitor->buffer_list, buffer);

        if(result != GLOBUS_SUCCESS && monitor->error == NULL)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed("callback", result);
        }
        if(monitor->error != NULL)
        {
            goto error;
        }
        
        result = globus_l_gfs_file_dispatch_read(monitor);
        if(result != GLOBUS_SUCCESS)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed(
                "globus_l_gfs_file_dispatch_read", result);
            goto error;
        }
        
        if(monitor->pending_reads == 0 && monitor->pending_writes == 0)
        {
            globus_assert(monitor->eof || monitor->aborted);
            globus_mutex_unlock(&monitor->lock);
            globus_gridftp_server_finished_transfer(
                monitor->op, GLOBUS_SUCCESS);
            globus_l_gfs_file_monitor_destroy(monitor);
        }
        else
        {
            globus_mutex_unlock(&monitor->lock);
        }
    }
    /* already unlocked */
    
    GlobusGFSFileDebugExit();
    return;

error:
    if(monitor->pending_reads != 0 || monitor->pending_writes != 0)
    {
        /* there are still outstanding callbacks, wait for them */
        globus_mutex_unlock(&monitor->lock);
    
        GlobusGFSFileDebugExitWithError();
        return;
    }
    globus_mutex_unlock(&monitor->lock);

    globus_gridftp_server_finished_transfer(
        monitor->op, globus_error_put(monitor->error));
    globus_l_gfs_file_monitor_destroy(monitor);

    GlobusGFSFileDebugExitWithError();
}

static
void
globus_l_gfs_file_read_cb(
    globus_xio_handle_t                 xio_handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_l_file_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_read_cb);
    GlobusGFSFileDebugEnter();
    
    monitor = (globus_l_file_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    {
        monitor->pending_reads--;
        if(result != GLOBUS_SUCCESS && monitor->error == NULL)
        {
            if(globus_xio_error_is_eof(result))
            {
                monitor->eof = GLOBUS_TRUE;
            }
            else
            {
                monitor->error = GlobusGFSErrorObjWrapFailed(
                    "callback", result);
            }
        }
        if(monitor->error != NULL)
        {
            globus_list_insert(&monitor->buffer_list, buffer);
            goto error;
        }
        
        if(nbytes > 0)
        {
            result = globus_gridftp_server_register_write(
                monitor->op,
                buffer,
                nbytes,
                monitor->file_offset /* + monitor->write_delta */,
                -1,
                globus_l_gfs_file_server_write_cb,
                monitor);
            if(result != GLOBUS_SUCCESS)
            {
                globus_list_insert(&monitor->buffer_list, buffer);
                monitor->error = GlobusGFSErrorObjWrapFailed(
                    "globus_gridftp_server_register_write", result);
                goto error;
            }
            
            monitor->pending_writes++;
            monitor->file_offset += nbytes;
            if(monitor->read_length != -1)
            {
                monitor->read_length -= nbytes;
            }
        }
        else
        {
            globus_list_insert(&monitor->buffer_list, buffer);
        }
                    
        if(monitor->read_length == 0)
        {
            monitor->first_read = GLOBUS_TRUE;
        }
        
        result = globus_l_gfs_file_dispatch_read(monitor);
        if(result != GLOBUS_SUCCESS)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed(
                "globus_l_gfs_file_dispatch_read", result);
            goto error;
        }
       
        if(monitor->pending_reads == 0 && monitor->pending_writes == 0)
        {
            globus_assert(monitor->eof || monitor->aborted);
            globus_mutex_unlock(&monitor->lock);
            globus_gridftp_server_finished_transfer(
                monitor->op, GLOBUS_SUCCESS);
            globus_l_gfs_file_monitor_destroy(monitor);
        }
        else
        {
            globus_mutex_unlock(&monitor->lock);
        }
    }
    /* already unlocked */

    GlobusGFSFileDebugExit();
    return;

error:
    globus_assert(monitor->pending_reads == 0);
    if(monitor->pending_writes != 0)
    {
        /* there are still outstanding callbacks, wait for them */
        globus_mutex_unlock(&monitor->lock);
    
        GlobusGFSFileDebugExitWithError();
        return;
    }
    globus_mutex_unlock(&monitor->lock);

    globus_gridftp_server_finished_transfer(
        monitor->op, globus_error_put(monitor->error));
    globus_l_gfs_file_monitor_destroy(monitor);

    GlobusGFSFileDebugExitWithError();
}

static
void
globus_l_gfs_file_open_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_file_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_open_read_cb);
    GlobusGFSFileDebugEnter();
    
    monitor = (globus_l_file_monitor_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_file_open_write_cb", result);
        monitor->file_handle = NULL;
        goto error_open;
    }
    
    globus_gridftp_server_begin_transfer(
        monitor->op, 0, monitor);
    
    globus_mutex_lock(&monitor->lock);
    monitor->first_read = GLOBUS_TRUE;
    result = globus_l_gfs_file_dispatch_read(monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor->error = GlobusGFSErrorObjWrapFailed(
            "globus_l_gfs_file_dispatch_read", result);
        goto error_dispatch;
    }
    
    if(monitor->pending_reads == 0 && monitor->pending_writes == 0)
    {
        globus_assert(monitor->eof || monitor->aborted);
        globus_mutex_unlock(&monitor->lock);
        globus_gridftp_server_finished_transfer(
            monitor->op, GLOBUS_SUCCESS);
        globus_l_gfs_file_monitor_destroy(monitor);
    }
    else
    {
        globus_mutex_unlock(&monitor->lock);
    }
    
    GlobusGFSFileDebugExit();
    return;

error_dispatch:
    globus_mutex_unlock(&monitor->lock);

error_open:
    globus_gridftp_server_finished_transfer(monitor->op, result);
    globus_l_gfs_file_monitor_destroy(monitor);

    GlobusGFSFileDebugExitWithError();
}

static
void
globus_l_gfs_file_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_file_monitor_t *           monitor;
    int                                 optimal_count;
    globus_size_t                       block_size;
    globus_xio_file_flag_t              open_flags;
    GlobusGFSName(globus_l_gfs_file_send);
    GlobusGFSFileDebugEnter();
    
    globus_gridftp_server_get_optimal_concurrency(op, &optimal_count);
    globus_gridftp_server_get_block_size(op, &block_size);
    globus_assert(optimal_count > 0 && block_size > 0);
    
    result = globus_l_gfs_file_monitor_init(
        &monitor, block_size, optimal_count);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_file_monitor_init", result);
        goto error_alloc;
    }
          
    while(optimal_count--)
    {
        globus_byte_t *                 buffer;
        buffer = globus_memory_pop_node(&monitor->mem);
        globus_list_insert(&monitor->buffer_list, buffer);
    }

    monitor->op = op;
    open_flags = GLOBUS_XIO_FILE_BINARY | GLOBUS_XIO_FILE_RDONLY;

    result = globus_l_gfs_file_open(
        &monitor->file_handle, transfer_info->pathname, open_flags, monitor);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed("globus_l_gfs_file_open", result);
        goto error_open;
    }
    
    GlobusGFSFileDebugExit();
    return;

error_open:
    globus_l_gfs_file_monitor_destroy(monitor);
    
error_alloc:  
    globus_gridftp_server_finished_transfer(op, result);

    GlobusGFSFileDebugExitWithError();
}

static
void
globus_l_gfs_file_event(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg)
{
    globus_l_file_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_event);
    GlobusGFSFileDebugEnter();
        
    monitor = (globus_l_file_monitor_t *) event_info->event_arg;

    switch(event_info->type)
    {
        case GLOBUS_GFS_EVENT_TRANSFER_ABORT:
            /* currently this will just prevent any further reads
              or writes from being registered.  should probably
              cancel/flush pending/current reads and writes somehow */
            globus_mutex_lock(&monitor->lock);
            {
                monitor->aborted = GLOBUS_TRUE;
            }
            globus_mutex_unlock(&monitor->lock);
            fprintf(stderr, "globus_l_gfs_file_event: aborted.\n");
            break;
            
        default:
            break;
    }
    
    GlobusGFSFileDebugExit();
}

static
int
globus_l_gfs_file_activate(void);

static
int
globus_l_gfs_file_deactivate(void);

static globus_gfs_storage_iface_t       globus_l_gfs_file_dsi_iface = 
{
    GLOBUS_GFS_DSI_DESCRIPTOR_SENDER,
    NULL, /* globus_l_gfs_file_init, */
    NULL, /* globus_l_gfs_file_destroy, */
    NULL, /* list */
    globus_l_gfs_file_send,
    globus_l_gfs_file_recv,
    globus_l_gfs_file_event, /* trev */
    NULL, /* active */
    NULL, /* passive */
    NULL, /* data destroy */
    globus_l_gfs_file_command, 
    globus_l_gfs_file_stat,
    NULL,
    NULL
};

GlobusExtensionDefineModule(globus_gridftp_server_file) =
{
    "globus_gridftp_server_file",
    globus_l_gfs_file_activate,
    globus_l_gfs_file_deactivate,
    NULL,
    NULL,
    &local_version
};

static
int
globus_l_gfs_file_activate(void)
{
    if(globus_module_activate(GLOBUS_XIO_MODULE) != GLOBUS_SUCCESS)
    {
        goto error_activate;
    }
    
    if(globus_xio_driver_load(
        "file", &globus_l_gfs_file_driver) != GLOBUS_SUCCESS)
    {
        goto error_load_file;
    }
    
    globus_extension_registry_add(
        GLOBUS_GFS_DSI_REGISTRY,
        "file",
        GlobusExtensionMyModule(globus_gridftp_server_file),
        &globus_l_gfs_file_dsi_iface);

    GlobusDebugInit(GLOBUS_GRIDFTP_SERVER_FILE,
        ERROR WARNING TRACE INTERNAL_TRACE INFO STATE INFO_VERBOSE);
    
    return GLOBUS_SUCCESS;
    
error_load_file:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    
error_activate:
    return GLOBUS_FAILURE;
}

static
int
globus_l_gfs_file_deactivate(void)
{
    globus_extension_registry_remove(
        GLOBUS_GFS_DSI_REGISTRY, "file");
        
    globus_xio_driver_unload(globus_l_gfs_file_driver);
    
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
