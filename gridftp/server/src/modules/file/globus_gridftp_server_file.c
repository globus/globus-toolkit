
#include "globus_gridftp_server.h"
#include "globus_xio.h"
#include "globus_xio_file_driver.h"
#include "openssl/md5.h"
#include "version.h"

typedef struct
{
    globus_mutex_t                      lock;
    globus_list_t *                     buffer_list;
    globus_gfs_operation_t   op;
    globus_xio_handle_t                 file_handle;
    globus_off_t                        file_offset;
    globus_off_t                        read_offset;
    globus_off_t                        read_length;
    globus_off_t                        write_delta;
    int                                 pending_writes;
    int                                 pending_read;
    globus_size_t                       block_size;
    int                                 optimal_count;
    globus_object_t *                   error;
    globus_bool_t                       first_read;
    globus_bool_t                       eof;
    globus_byte_t                       buffer_block[1];
} globus_l_send_monitor_t;

typedef struct
{
    globus_mutex_t                      lock;
    globus_priority_q_t                 queue;
    globus_gfs_operation_t   op;
    globus_xio_handle_t                 file_handle;
    int                                 pending_reads;
    int                                 pending_write;
    globus_off_t                        file_offset;
    globus_off_t                        write_delta;
    globus_off_t                        transfer_delta;
    globus_size_t                       block_size;
    int                                 optimal_count;
    int                                 node_ndx;
    globus_object_t *                   error;
    globus_bool_t                       eof;
    globus_byte_t                       buffer_block[1];
} globus_l_recv_monitor_t;

typedef struct
{
    globus_byte_t *                     buffer;
    globus_off_t                        offset;
    globus_size_t                       length;
} globus_l_buffer_info_t;

static globus_xio_driver_t              globus_l_gfs_file_driver;

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
    
    strncpy(buf, pathname, MAXPATHLEN);
    buf[MAXPATHLEN - 1] = '\0';
    
    filepart = strrchr(buf, '/');
    if(filepart && !*(filepart + 1) && filepart != buf)
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
            basepath[0] = '/';
            basepath[1] = '\0';
        }
        else
        {
            *filepart = '\0';
            strcpy(basepath, buf);
        }
        
        strcpy(filename, filepart + 1);
    }    
}

static
void
globus_l_gfs_file_copy_stat(
    globus_gfs_stat_t *                 stat_object,
    struct stat *                       stat_buf,
    const char *                        filename)
{
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
    
    strcpy(stat_object->name, filename);
}

static
globus_result_t
globus_l_gfs_file_stat(
    globus_gfs_operation_t   op,
    globus_gfs_stat_info_t *           stat_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    struct stat                         stat_buf;
    globus_gfs_stat_t *                 stat_array;
    int                                 stat_count;
    DIR *                               dir;
    char                                basepath[MAXPATHLEN];
    char                                filename[MAXPATHLEN];
    GlobusGFSName(globus_l_gfs_file_stat);

    if(stat(stat_info->pathname, &stat_buf) != 0)
    {
        result = GlobusGFSErrorSystemError("stat", errno);
        goto error_stat1;
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
        
        globus_l_gfs_file_copy_stat(stat_array, &stat_buf, filename);
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
        
            if(stat(path, &stat_buf) != 0)
            {
                result = GlobusGFSErrorSystemError("stat", errno);
                globus_free(dir_entry);
                /* just skip invalid entries */
                stat_count--;
                i--;
                continue;
            }
            
            globus_l_gfs_file_copy_stat(
                &stat_array[i], &stat_buf, dir_entry->d_name);
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
    
    globus_free(stat_array);
    
    return GLOBUS_SUCCESS;

error_read:
    globus_free(stat_array);
    
error_alloc2:
    closedir(dir);
    
error_open:
error_alloc1:
error_stat1:
    globus_gridftp_server_finished_stat(op, result, NULL, 0);
    return result;
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

    rc = mkdir(pathname, 0777);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("mkdir", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);
        
    return GLOBUS_SUCCESS;
    
error:
    return result;
}

globus_result_t
globus_l_gfs_file_rmdir(
    globus_gfs_operation_t   op,
    const char *                        pathname)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_rmdir);

    rc = rmdir(pathname);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("rmdir", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);
        
    return GLOBUS_SUCCESS;
    
error:
    return result;
}

globus_result_t
globus_l_gfs_file_delete(
    globus_gfs_operation_t   op,
    const char *                        pathname)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_delete);

    rc = unlink(pathname);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("unlink", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);
        
    return GLOBUS_SUCCESS;
    
error:
    return result;
}

globus_result_t
globus_l_gfs_file_rename(
    globus_gfs_operation_t   op,
    const char *                        from_pathname,
    const char *                        to_pathname)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_rename);

    rc = rename(from_pathname, to_pathname);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("rename", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);
        
    return GLOBUS_SUCCESS;
    
error:
    return result;
}

globus_result_t
globus_l_gfs_file_chmod(
    globus_gfs_operation_t   op,
    const char *                        pathname,
    mode_t                              mode)
{
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_chmod);

    rc = chmod(pathname, mode);
    if(rc != 0)
    {
        result = GlobusGFSErrorSystemError("chmod", errno);
        goto error;
    }
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);
        
    return GLOBUS_SUCCESS;
    
error:
    return result;
}

#define GFS_CKSM_BUFSIZE 1024*1024

globus_result_t
globus_l_gfs_file_cksm(
    globus_gfs_operation_t   op,
    const char *                        pathname,
    const char *                        algorithm,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_cksm);
    
    MD5_CTX                             mdctx;
    char *                              md5ptr;
    unsigned char                       md[MD5_DIGEST_LENGTH];
    char                                md5sum[MD5_DIGEST_LENGTH * 2 + 1];
    char                                buf[GFS_CKSM_BUFSIZE];

    int                                 i;
    int                                 fd;
    int                                 n;
    globus_off_t                        count;
    globus_off_t                        read_left;
    

    if(offset < 0)
    {
        goto param_error;
    }
       
    if(length >= 0)
    {
        read_left = length;
        count = (read_left > GFS_CKSM_BUFSIZE) ? GFS_CKSM_BUFSIZE : read_left;
    }
    else
    {
        count = GFS_CKSM_BUFSIZE;
    }
    
    fd = open(pathname, O_RDONLY);        
    if(fd < 0)
    {
        goto fd_error;
    }

    if (lseek(fd, offset, SEEK_SET) == -1)
    {
        goto seek_error;
    }

    
    MD5_Init(&mdctx);        

    while((n = read(fd, buf, count)) > 0)
    {
        if(length >= 0)
        {
            read_left -= n;
            count = (read_left > GFS_CKSM_BUFSIZE) ? GFS_CKSM_BUFSIZE : read_left;
        }

        MD5_Update(&mdctx, buf, n);
    }

    MD5_Final(md, &mdctx);
    
    close(fd);
        
    md5ptr = md5sum;
    for(i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
       sprintf(md5ptr, "%02x", md[i]);
       md5ptr++;
       md5ptr++;
    }
    md5ptr = '\0';
    
    /* reply(213, "%s", md5sum); */
    
    globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, md5sum);
        
    return GLOBUS_SUCCESS;
        
seek_error:
    close(fd);
fd_error:
param_error:
     /* reply(501, "Error calculating checksum"); */

    return result;
}


globus_result_t
globus_l_gfs_file_command(
    globus_gfs_operation_t   op,
    globus_gfs_command_info_t *        cmd_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    
    switch(cmd_info->command)
    {
      case GLOBUS_GFS_CMD_MKD:
        result = globus_l_gfs_file_mkdir(op, cmd_info->pathname);
        break;
      case GLOBUS_GFS_CMD_RMD:
        result = globus_l_gfs_file_rmdir(op, cmd_info->pathname);
        break;
      case GLOBUS_GFS_CMD_DELE:
        result = globus_l_gfs_file_delete(op, cmd_info->pathname);
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
    
    return GLOBUS_SUCCESS;

error:
    globus_gridftp_server_finished_command(op, result, NULL);    
    return result;
}



/**
 * recv calls
 */

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
    
    buf_info1 = (globus_l_buffer_info_t *) priority_1;
    buf_info2 = (globus_l_buffer_info_t *) priority_2;
    
    /* the void * are really just offsets */
    if(buf_info1->offset > buf_info2->offset)
        return 1;
    if(buf_info1->offset < buf_info2->offset)
        return -1;
    return 0;
}

static
globus_result_t
globus_l_gfs_recv_monitor_init(
    globus_l_recv_monitor_t **          u_monitor,
    globus_size_t                       block_size,
    int                                 optimal_count)
{
    globus_l_recv_monitor_t *           monitor;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_recv_monitor_init);
    
    monitor = (globus_l_recv_monitor_t *) globus_malloc(
        sizeof(globus_l_recv_monitor_t) - 1 + (block_size * optimal_count));
    if(!monitor)
    {
        result = GlobusGFSErrorMemory("monitor/buffer");
        goto error_alloc;
    }
    
    globus_mutex_init(&monitor->lock, GLOBUS_NULL);
    globus_priority_q_init(
        &monitor->queue, globus_l_gfs_file_queue_compare);
    monitor->op = GLOBUS_NULL;
    monitor->file_handle = GLOBUS_NULL;
    monitor->pending_reads = 0;
    monitor->pending_write = 0;
    monitor->file_offset = 0;
    monitor->write_delta = 0;
    monitor->transfer_delta = 0;    
    monitor->block_size = block_size;
    monitor->optimal_count = optimal_count;
    monitor->error = GLOBUS_NULL;
    monitor->eof = GLOBUS_FALSE;
    
    *u_monitor = monitor;
    
    return GLOBUS_SUCCESS;

error_alloc:
    return result;
}

static
void
globus_l_gfs_file_close_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    /* dont need to do anything here */
}

static
void
globus_l_gfs_recv_monitor_destroy(
    globus_l_recv_monitor_t *           monitor)
{
    if(monitor->file_handle)
    {
        globus_xio_register_close(
            monitor->file_handle,
            GLOBUS_NULL,
            globus_l_gfs_file_close_cb,
            GLOBUS_NULL);
    }
            
    /* maybe dequeue all and free buf infos */
    globus_priority_q_destroy(&monitor->queue);
    globus_mutex_destroy(&monitor->lock);
    globus_free(monitor);
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
    void *                              user_arg);

static
globus_result_t
globus_l_gfs_file_dispatch_write(
    globus_l_recv_monitor_t *           monitor);
    
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
    globus_l_recv_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_write_cb);
    
    monitor = (globus_l_recv_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    { 
        monitor->pending_write--;
        globus_gridftp_server_update_bytes_written(
            monitor->op, 
            monitor->file_offset + monitor->transfer_delta,
            nbytes);
        monitor->file_offset += nbytes;

        if(result != GLOBUS_SUCCESS && monitor->error == GLOBUS_NULL)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed("callback", result);
        }
        if(monitor->error != GLOBUS_NULL)
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
        
        result = globus_l_gfs_file_dispatch_write(monitor);
        if(result != GLOBUS_SUCCESS)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed(
                "globus_l_gfs_file_dispatch_write", result);
            goto error;
        }
        
        if(monitor->pending_reads == 0 && monitor->pending_write == 0)
        {
            globus_assert(monitor->eof);
            globus_mutex_unlock(&monitor->lock);
            globus_gridftp_server_finished_transfer(
                monitor->op, GLOBUS_SUCCESS);
            globus_l_gfs_recv_monitor_destroy(monitor);
        }
        else
        {
            globus_mutex_unlock(&monitor->lock);
        }
    }
    /* already unlocked */
    
    return;

error:
    if(monitor->pending_reads != 0 || monitor->pending_write != 0)
    {
        /* there are still outstanding callbacks, wait for them */
        globus_mutex_unlock(&monitor->lock);
        return;
    }
    globus_mutex_unlock(&monitor->lock);

    globus_gridftp_server_finished_transfer(
        monitor->op, globus_error_put(monitor->error));
    globus_l_gfs_recv_monitor_destroy(monitor);
}

/* Called LOCKED */
static
globus_result_t
globus_l_gfs_file_dispatch_write(
    globus_l_recv_monitor_t *           monitor)
{
    globus_l_buffer_info_t *            buf_info;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_file_dispatch_write);
    
    if(monitor->pending_write == 0)
    {
        buf_info = (globus_l_buffer_info_t *)
            globus_priority_q_dequeue(&monitor->queue);
        if(buf_info)
        {
            if(buf_info->offset + monitor->write_delta != 
                monitor->file_offset)
            { 
                monitor->file_offset = 
                    buf_info->offset + monitor->write_delta;

                result = globus_xio_handle_cntl(
                    monitor->file_handle,
                    globus_l_gfs_file_driver,
                    GLOBUS_XIO_FILE_SEEK,
                    &monitor->file_offset,
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
                GLOBUS_NULL,
                globus_l_gfs_file_write_cb,
                monitor);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusGFSErrorWrapFailed(
                    "globus_xio_register_write", result);
                goto error_register;
            }
            
            monitor->pending_write++;
            globus_free(buf_info);
        }
    }
    
    return GLOBUS_SUCCESS;

error_seek:
error_register:
    globus_free(buf_info);
    return result;
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
    globus_l_recv_monitor_t *           monitor;
    globus_l_buffer_info_t *            buf_info;
    int                                 rc;
    GlobusGFSName(globus_l_gfs_file_server_read_cb);
    
    monitor = (globus_l_recv_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    {
        monitor->pending_reads--;
        
        if(result != GLOBUS_SUCCESS && monitor->error == GLOBUS_NULL)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed("callback", result);
        }
        if(monitor->error != GLOBUS_NULL)
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
        
        result = globus_l_gfs_file_dispatch_write(monitor);
        if(result != GLOBUS_SUCCESS)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed(
                "globus_l_gfs_file_dispatch_write", result);
            goto error_dispatch;
        }
    }
    globus_mutex_unlock(&monitor->lock);
    
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
    if(monitor->pending_reads != 0 || monitor->pending_write != 0)
    {
        /* there are still outstanding callbacks, wait for them */
        globus_mutex_unlock(&monitor->lock);
        return;
    }
    globus_mutex_unlock(&monitor->lock);

    globus_gridftp_server_finished_transfer(
        monitor->op, globus_error_put(monitor->error));
    globus_l_gfs_recv_monitor_destroy(monitor);
}

static
void
globus_l_gfs_file_open_write_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_recv_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_open_write_cb);
    
    monitor = (globus_l_recv_monitor_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_file_open_write_cb", result);
        monitor->file_handle = GLOBUS_NULL;
        goto error_open;
    }

    globus_gridftp_server_begin_transfer(monitor->op, 0, monitor);
    
    globus_mutex_lock(&monitor->lock);
    {
        int                             optimal_count;
        globus_size_t                   block_size;
        
        optimal_count = monitor->optimal_count;
        block_size = monitor->block_size;
        while(optimal_count--)
        {
            globus_byte_t *             buffer;
            
            buffer = monitor->buffer_block + (optimal_count * block_size);
            result = globus_gridftp_server_register_read(
                monitor->op,
                buffer,
                block_size,
                globus_l_gfs_file_server_read_cb,
                monitor);
            if(result != GLOBUS_SUCCESS)
            {
                result = GlobusGFSErrorWrapFailed(
                    "globus_gridftp_server_register_read", result);
                goto error_register;
            }
            
            monitor->pending_reads++;
        }
    }
    globus_mutex_unlock(&monitor->lock);
    
    return;

error_register:
    if(monitor->pending_reads != 0)
    {
        /* there are pending reads, need to wait for them */
        monitor->error = globus_error_get(result);
        globus_mutex_unlock(&monitor->lock);
        return;
    }
    globus_mutex_unlock(&monitor->lock);

error_open:
    globus_gridftp_server_finished_transfer(monitor->op, result);
    globus_l_gfs_recv_monitor_destroy(monitor);
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
    
    result = globus_xio_stack_init(&stack, GLOBUS_NULL);
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
    
    return GLOBUS_SUCCESS;

error_register:
    globus_xio_close(*file_handle, GLOBUS_NULL);
    *file_handle = GLOBUS_NULL;
error_create:
error_push:
    globus_xio_stack_destroy(stack);
    
error_stack:
error_cntl:    
    globus_xio_attr_destroy(attr);
    
error_attr:
    return result;
}

static
globus_result_t
globus_l_gfs_file_recv(
    globus_gfs_operation_t   op,
    globus_gfs_transfer_info_t *       transfer_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_recv_monitor_t *           monitor;
    int                                 optimal_count;
    globus_size_t                       block_size;
    globus_xio_file_flag_t              open_flags;
    globus_off_t                        offset;
    globus_off_t                        length;
    GlobusGFSName(globus_l_gfs_file_recv);

    globus_gridftp_server_get_optimal_concurrency(op, &optimal_count);
    globus_gridftp_server_get_block_size(op, &block_size);
    globus_assert(optimal_count > 0 && block_size > 0);

    result = globus_l_gfs_recv_monitor_init(
        &monitor, block_size, optimal_count);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_recv_monitor_init", result);
        goto error_alloc;
    }
    
    globus_gridftp_server_get_write_range(
        op,
        &offset,
        &length,
        &monitor->write_delta, 
        &monitor->transfer_delta);
    
    monitor->op = op;
    open_flags = GLOBUS_XIO_FILE_BINARY | 
        GLOBUS_XIO_FILE_CREAT | 
        GLOBUS_XIO_FILE_WRONLY;
    if(offset == 0 && length == -1)
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
    
    return GLOBUS_SUCCESS;

error_open:
    globus_l_gfs_recv_monitor_destroy(monitor);
    
error_alloc:
    globus_gridftp_server_finished_transfer(op, result);
    return result;
}

/**
 * send calls
 */

static
globus_result_t
globus_l_gfs_send_monitor_init(
    globus_l_send_monitor_t **          u_monitor,
    globus_size_t                       block_size,
    int                                 optimal_count)
{
    globus_l_send_monitor_t *           monitor;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_send_monitor_init);
    
    monitor = (globus_l_send_monitor_t *) globus_malloc(
        sizeof(globus_l_send_monitor_t) - 1 + (block_size * optimal_count));
    if(!monitor)
    {
        result = GlobusGFSErrorMemory("monitor/buffer");
        goto error_alloc;
    }
    
    globus_mutex_init(&monitor->lock, GLOBUS_NULL);
    monitor->buffer_list = GLOBUS_NULL;
    monitor->op = GLOBUS_NULL;
    monitor->file_handle = GLOBUS_NULL;
    monitor->pending_writes = 0;
    monitor->pending_read = 0;
    monitor->file_offset = 0;
    monitor->read_offset = 0;
    monitor->read_length = -1;
    monitor->write_delta = 0;
    monitor->block_size = block_size;
    monitor->optimal_count = optimal_count;
    monitor->error = GLOBUS_NULL;
    monitor->eof = GLOBUS_FALSE;
    
    while(optimal_count--)
    {
        globus_byte_t *                 buffer;
        
        buffer = monitor->buffer_block + (optimal_count * block_size);
        globus_list_insert(&monitor->buffer_list, buffer);
    }
    
    *u_monitor = monitor;
    
    return GLOBUS_SUCCESS;

error_alloc:
    return result;
}

static
void
globus_l_gfs_send_monitor_destroy(
    globus_l_send_monitor_t *           monitor)
{
    if(monitor->file_handle)
    {
        globus_xio_register_close(
            monitor->file_handle,
            GLOBUS_NULL,
            globus_l_gfs_file_close_cb,
            GLOBUS_NULL);
    }
            
    /* maybe dequeue all and free buf infos */
    globus_list_free(monitor->buffer_list);
    globus_mutex_destroy(&monitor->lock);
    globus_free(monitor);
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
    void *                              user_arg);
    
/* called LOCKED */
static
globus_result_t
globus_l_gfs_file_dispatch_read(
    globus_l_send_monitor_t *           monitor)
{
    globus_result_t                     result;
    globus_byte_t *                     buffer;
    globus_size_t                       read_length;
    GlobusGFSName(globus_l_gfs_file_dispatch_read);
    
    if(monitor->first_read && monitor->pending_read == 0 && 
        !monitor->eof && !globus_list_empty(monitor->buffer_list))
    {
        globus_gridftp_server_get_read_range(
            monitor->op,
            &monitor->read_offset,
            &monitor->read_length,
            &monitor->write_delta);
        if(monitor->read_length == 0)
        {
            monitor->eof = GLOBUS_TRUE;
        }
        else
        {                                        
            if (monitor->file_offset != monitor->read_offset)
            {
                result = globus_xio_handle_cntl(
                    monitor->file_handle,
                    globus_l_gfs_file_driver,
                    GLOBUS_XIO_FILE_SEEK,
                    &monitor->read_offset,
                    SEEK_SET);
            
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

    if(monitor->pending_read == 0 && !monitor->eof && 
        !globus_list_empty(monitor->buffer_list))
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
            GLOBUS_NULL,
            globus_l_gfs_file_read_cb,
            monitor);
        if(result != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorWrapFailed(
                "globus_xio_register_read", result);
            goto error_register;
        }
        
        monitor->pending_read++;
    }
    
    return GLOBUS_SUCCESS;

error_seek:
error_register:
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
    globus_l_send_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_server_write_cb);
    
    monitor = (globus_l_send_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    { 
        monitor->pending_writes--;

        if(result != GLOBUS_SUCCESS && monitor->error == GLOBUS_NULL)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed("callback", result);
        }
        if(monitor->error != GLOBUS_NULL)
        {
            goto error;
        }
        
        globus_list_insert(&monitor->buffer_list, buffer);
        
        result = globus_l_gfs_file_dispatch_read(monitor);
        if(result != GLOBUS_SUCCESS)
        {
            monitor->error = GlobusGFSErrorObjWrapFailed(
                "globus_l_gfs_file_dispatch_read", result);
            goto error;
        }
        
        if(monitor->pending_read == 0 && monitor->pending_writes == 0)
        {
            globus_assert(monitor->eof);
            globus_mutex_unlock(&monitor->lock);
            globus_gridftp_server_finished_transfer(
                monitor->op, GLOBUS_SUCCESS);
            globus_l_gfs_send_monitor_destroy(monitor);
        }
        else
        {
            globus_mutex_unlock(&monitor->lock);
        }
    }
    /* already unlocked */
    
    return;

error:
    if(monitor->pending_read != 0 || monitor->pending_writes != 0)
    {
        /* there are still outstanding callbacks, wait for them */
        globus_mutex_unlock(&monitor->lock);
        return;
    }
    globus_mutex_unlock(&monitor->lock);

    globus_gridftp_server_finished_transfer(
        monitor->op, globus_error_put(monitor->error));
    globus_l_gfs_send_monitor_destroy(monitor);
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
    globus_l_send_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_read_cb);
    
    monitor = (globus_l_send_monitor_t *) user_arg;
    
    globus_mutex_lock(&monitor->lock);
    {
        monitor->pending_read--;
        if(result != GLOBUS_SUCCESS && monitor->error == GLOBUS_NULL)
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
        if(monitor->error != GLOBUS_NULL)
        {
            goto error;
        }
        
        if(nbytes > 0)
        {
            result = globus_gridftp_server_register_write(
                monitor->op,
                buffer,
                nbytes,
                monitor->file_offset + monitor->write_delta,
                -1,
                globus_l_gfs_file_server_write_cb,
                monitor);
            if(result != GLOBUS_SUCCESS)
            {
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
       
        if(monitor->pending_read == 0 && monitor->pending_writes == 0)
        {
            globus_assert(monitor->eof);
            globus_mutex_unlock(&monitor->lock);
            globus_gridftp_server_finished_transfer(
                monitor->op, GLOBUS_SUCCESS);
            globus_l_gfs_send_monitor_destroy(monitor);
        }
        else
        {
            globus_mutex_unlock(&monitor->lock);
        }
    }
    /* already unlocked */

    return;

error:
    globus_assert(monitor->pending_read == 0);
    if(monitor->pending_writes != 0)
    {
        /* there are still outstanding callbacks, wait for them */
        globus_mutex_unlock(&monitor->lock);
        return;
    }
    globus_mutex_unlock(&monitor->lock);

    globus_gridftp_server_finished_transfer(
        monitor->op, globus_error_put(monitor->error));
    globus_l_gfs_send_monitor_destroy(monitor);
}

static
void
globus_l_gfs_file_open_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_send_monitor_t *           monitor;
    GlobusGFSName(globus_l_gfs_file_open_read_cb);
    
    monitor = (globus_l_send_monitor_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_file_open_write_cb", result);
        monitor->file_handle = GLOBUS_NULL;
        goto error_open;
    }
    
    globus_gridftp_server_begin_transfer(monitor->op, 0, monitor);
    
    globus_mutex_lock(&monitor->lock);
    monitor->first_read = GLOBUS_TRUE;
    result = globus_l_gfs_file_dispatch_read(monitor);
    if(result != GLOBUS_SUCCESS)
    {
        monitor->error = GlobusGFSErrorObjWrapFailed(
            "globus_l_gfs_file_dispatch_read", result);
        goto error_dispatch;
    }

    globus_mutex_unlock(&monitor->lock);
    
    return;

error_dispatch:
    globus_mutex_unlock(&monitor->lock);

error_open:
    globus_gridftp_server_finished_transfer(monitor->op, result);
    globus_l_gfs_send_monitor_destroy(monitor);
}

static
globus_result_t
globus_l_gfs_file_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_l_send_monitor_t *           monitor;
    int                                 optimal_count;
    globus_size_t                       block_size;
    globus_xio_file_flag_t              open_flags;
    GlobusGFSName(globus_l_gfs_file_send);
    
    globus_gridftp_server_get_optimal_concurrency(op, &optimal_count);
    globus_gridftp_server_get_block_size(op, &block_size);
    globus_assert(optimal_count > 0 && block_size > 0);
    
    result = globus_l_gfs_send_monitor_init(
        &monitor, block_size, optimal_count);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusGFSErrorWrapFailed(
            "globus_l_gfs_send_monitor_init", result);
        goto error_alloc;
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
    
    return GLOBUS_SUCCESS;

error_open:
    globus_l_gfs_send_monitor_destroy(monitor);
    
error_alloc:  
    globus_gridftp_server_finished_transfer(op, result);
    return result;
}

static
int
globus_l_gfs_file_activate(void);

static
int
globus_l_gfs_file_deactivate(void);

static globus_gfs_storage_iface_t       globus_l_gfs_file_dsi_iface = 
{
    NULL, /* globus_l_gfs_file_init, */
    NULL, /* globus_l_gfs_file_destroy, */
    NULL, /* list */
    globus_l_gfs_file_send,
    globus_l_gfs_file_recv,
    NULL, /* trev */
    NULL, /* active */
    NULL, /* passive */
    NULL, /* data destroy */
    globus_l_gfs_file_command, 
    globus_l_gfs_file_stat,
    NULL
};

GlobusExtensionDefineModule(globus_gridftp_server_file) =
{
    "globus_gridftp_server_file",
    globus_l_gfs_file_activate,
    globus_l_gfs_file_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
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
