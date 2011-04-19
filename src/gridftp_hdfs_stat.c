
#include "gridftp_hdfs.h"

/*************************************************************************
 *  stat
 *  ----
 *  This interface function is called whenever the server needs 
 *  information about a given file or resource.  It is called then an
 *  LIST is sent by the client, when the server needs to verify that 
 *  a file exists and has the proper permissions, etc.
 ************************************************************************/
void
globus_l_gfs_hdfs_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_stat_t *                 stat_array;
    int                                 stat_count = 0;
    DIR *                               dir;
    char                                basepath[MAXPATHLEN];
    char                                filename[MAXPATHLEN];
    char                                symlink_target[MAXPATHLEN];
    char *                              PathName;
    globus_l_gfs_hdfs_handle_t *       hdfs_handle;
    GlobusGFSName(globus_l_gfs_hdfs_stat);

    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;
    PathName=stat_info->pathname;
    while (PathName[0] == '/' && PathName[1] == '/')
    {
        PathName++;
    }
    if (strncmp(PathName, hdfs_handle->mount_point, hdfs_handle->mount_point_len)==0) {
        PathName += hdfs_handle->mount_point_len;
    }
    while (PathName[0] == '/' && PathName[1] == '/')
    {   
        PathName++;
    }

    snprintf(err_msg, MSG_SIZE, "Going to do stat on file %s.\n", PathName);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
 

    hdfsFileInfo * fileInfo = NULL;

    /* lstat is the same as stat when not operating on a link */
    if((fileInfo = hdfsGetPathInfo(hdfs_handle->fs, PathName)) == NULL)
    {
        result = GlobusGFSErrorSystemError("stat", errno);
        goto error_stat1;
    }
    snprintf(err_msg, MSG_SIZE, "Finished HDFS stat operation.\n");
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);

    mode_t mode = (fileInfo->mKind == kObjectKindDirectory) ? (S_IFDIR | 0777) :  (S_IFREG | 0666);

    globus_l_gfs_file_partition_path(PathName, basepath, filename);
    
    if(!S_ISDIR(mode) || stat_info->file_only)
    {
        stat_array = (globus_gfs_stat_t *)
            globus_malloc(sizeof(globus_gfs_stat_t));
        if(!stat_array)
        {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc1;
        }
        
        globus_l_gfs_file_copy_stat(
            stat_array, fileInfo, filename, symlink_target);
        hdfsFreeFileInfo(fileInfo, 1);
        stat_count = 1;
    }
    else
    {
        int                             i;
    
        hdfsFileInfo * dir = hdfsListDirectory(hdfs_handle->fs, PathName, &stat_count);
        if(dir == NULL)
        {
            result = GlobusGFSErrorSystemError("opendir", errno);
            goto error_open;
        }
        
        stat_array = (globus_gfs_stat_t *)
            globus_malloc(sizeof(globus_gfs_stat_t) * stat_count);
        if(!stat_array)
        {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc2;
        }

        for(i = 0; i<stat_count; i++)
        {
            globus_l_gfs_file_copy_stat(
                stat_array + i, dir + i, dir[i].mName, 0);
        }
        hdfsFreeFileInfo(dir, stat_count);
        
        if(i != stat_count)
        {
            result = GlobusGFSErrorSystemError("readdir", errno);
            goto error_read;
        }
        
    }
    
    globus_gridftp_server_finished_stat(
        op, GLOBUS_SUCCESS, stat_array, stat_count);
    
    
    globus_l_gfs_file_destroy_stat(stat_array, stat_count);
    return;

error_read:
    globus_l_gfs_file_destroy_stat(stat_array, stat_count);
    
error_alloc2:
    closedir(dir);
    
error_open:
error_alloc1:
error_stat1:
    globus_gridftp_server_finished_stat(op, result, NULL, 0);

/*    GlobusGFSFileDebugExitWithError();  */
}

/* basepath and filename must be MAXPATHLEN long
 * the pathname may be absolute or relative, basepath will be the same */
void
globus_l_gfs_file_partition_path(
    const char *                        pathname,
    char *                              basepath,
    char *                              filename)
{
    char                                buf[MAXPATHLEN];
    char *                              filepart;
    GlobusGFSName(globus_l_gfs_file_partition_path);

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
}

void
globus_l_gfs_file_destroy_stat(
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count)
{
    int                                 i;
    GlobusGFSName(globus_l_gfs_file_destroy_stat);

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
}

void
globus_l_gfs_file_copy_stat(
    globus_gfs_stat_t *                 stat_object,
    hdfsFileInfo *                      fileInfo,
    const char *                        filename,
    const char *                        symlink_target)
{
    GlobusGFSName(globus_l_gfs_file_copy_stat);

    stat_object->mode     = (fileInfo->mKind == kObjectKindDirectory) ? (S_IFDIR | 0777) :  (S_IFREG | 0666);
    stat_object->nlink    = (fileInfo->mKind == kObjectKindDirectory) ? 0 : 1;
    stat_object->uid      = default_id;
    stat_object->gid      = default_id;
    stat_object->size     = (fileInfo->mKind == kObjectKindDirectory) ? 4096 : fileInfo->mSize;
    stat_object->mtime    = fileInfo->mLastMod;
    stat_object->atime    = fileInfo->mLastMod;
    stat_object->ctime    = fileInfo->mLastMod;
    stat_object->dev      = 0;
    stat_object->ino      = 0;

    stat_object->name = NULL;
    if(filename && *filename)
    {
        // If the filename starts with hdfs://hostname/, strip out the hdfs://hostname
        const char prefix[] = "hdfs://";
        int prefix_len = strlen(prefix);
        const char * real_filename = strstr(filename, prefix);
        if (real_filename == filename) // Check if filename starts with hdfs://
        {
            real_filename += prefix_len;
            real_filename = strchr(real_filename, '/');
            if (real_filename != NULL)
            {
                stat_object->name = strdup(real_filename);
            }
        }
        if (stat_object->name == NULL)
        {
            stat_object->name = strdup(filename);
        }
    }
    if(symlink_target && *symlink_target)
    {
        stat_object->symlink_target = strdup(symlink_target);
    }
    else
    {
        stat_object->symlink_target = NULL;
    }
}

