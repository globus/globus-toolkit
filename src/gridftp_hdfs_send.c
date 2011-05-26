
#include "gridftp_hdfs.h"

/*************************************************************************
 *  send
 *  ----
 *  This interface function is called when the client requests to receive
 *  a file from the server.
 *
 *  To send a file to the client the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_write();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
void
globus_l_gfs_hdfs_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_hdfs_handle_t *       hdfs_handle;
    GlobusGFSName(globus_l_gfs_hdfs_send);
    globus_result_t                     rc;

    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;
    hdfs_handle->pathname = transfer_info->pathname;
    while (hdfs_handle->pathname[0] == '/' && hdfs_handle->pathname[1] == '/')
    {
        hdfs_handle->pathname++;
    }
    if (strncmp(hdfs_handle->pathname, hdfs_handle->mount_point, hdfs_handle->mount_point_len)==0) {
        hdfs_handle->pathname += hdfs_handle->mount_point_len;
    }
    while (hdfs_handle->pathname[0] == '/' && hdfs_handle->pathname[1] == '/')
    {
        hdfs_handle->pathname++;
    }

    hdfs_handle->op = op;
    hdfs_handle->outstanding = 0;
    hdfs_handle->done = GLOBUS_FALSE;
    globus_gridftp_server_get_block_size(op, &hdfs_handle->block_size);

    globus_gridftp_server_get_read_range(hdfs_handle->op,
                                         &hdfs_handle->offset,
                                         &hdfs_handle->block_length);



    globus_gridftp_server_begin_transfer(hdfs_handle->op, 0, hdfs_handle);

    if (hdfsExists(hdfs_handle->fs, hdfs_handle->pathname) == 0)
    {
        hdfsFileInfo *fileInfo;
        int hasStat = 1;

        if((fileInfo = hdfsGetPathInfo(hdfs_handle->fs, hdfs_handle->pathname)) == NULL)
            hasStat = 0;

        if (hasStat && fileInfo->mKind == kObjectKindDirectory) {
            char * hostname = globus_malloc(sizeof(char)*256);
            memset(hostname, '\0', sizeof(char)*256);
            if (gethostname(hostname, 255) != 0) {
                sprintf(hostname, "UNKNOWN");
            }
            snprintf(err_msg, MSG_SIZE, "Error for user %s accessing gridftp server %s.  The file you are trying to"
                " read, %s, is a directory.", hdfs_handle->username, hostname, hdfs_handle->pathname);
            rc = GlobusGFSErrorGeneric(err_msg);
            globus_free(hostname);
            globus_gridftp_server_finished_transfer(op, rc);
            return;
        }
    } else {
        char * hostname = globus_malloc(sizeof(char)*256);
        memset(hostname, '\0', sizeof(char)*256);
        if (gethostname(hostname, 255) != 0) {
            sprintf(hostname, "UNKNOWN");
        }
        snprintf(err_msg, MSG_SIZE, "Error for user %s accessing gridftp server %s.  The file you are trying to "
                "read, %s, does not exist.", hdfs_handle->username, hostname, hdfs_handle->pathname);
        rc = GlobusGFSErrorGeneric(err_msg);
        globus_free(hostname);
        globus_gridftp_server_finished_transfer(op, rc);
        return;
    }


    hdfs_handle->fd = hdfsOpenFile(hdfs_handle->fs, hdfs_handle->pathname, O_RDONLY, 0, 1, 0);
    if (!hdfs_handle->fd)
    {
        char * hostname = globus_malloc(sizeof(char)*256);
        memset(hostname, '\0', sizeof(char)*256);
        if (gethostname(hostname, 255) != 0) {
            sprintf(hostname, "UNKNOWN");
        }
        if (errno == EINTERNAL) {
            snprintf(err_msg, MSG_SIZE, "Failed to open file %s in HDFS for user %s due to an internal error in HDFS "
                "on server %s; could be a misconfiguration or bad installation at the site",
                hdfs_handle->pathname, hdfs_handle->username, hostname);
            rc = GlobusGFSErrorSystemError(err_msg, errno);
        } else if (errno == EACCES) {
            snprintf(err_msg, MSG_SIZE, "Permission error in HDFS from gridftp server %s; user %s is not allowed"
                " to open the HDFS file %s", hostname,
                hdfs_handle->username, hdfs_handle->pathname);
            rc = GlobusGFSErrorSystemError(err_msg, errno);
        } else if (errno == ENOENT) {
            snprintf(err_msg, MSG_SIZE, "Failure for user %s on server %s; the requested file %s does not exist", hdfs_handle->username,
                hostname, hdfs_handle->pathname);
            rc = GlobusGFSErrorSystemError(err_msg, errno);
        } else {
            snprintf(err_msg, MSG_SIZE, "Failed to open file %s in HDFS for user %s on server %s; unknown error from HDFS",
                hdfs_handle->pathname, hdfs_handle->username, hostname);
            rc = GlobusGFSErrorSystemError(err_msg, errno);
        }
        globus_gridftp_server_finished_transfer(op, rc);
        globus_free(hostname);
        return;
    }

    if (! strcmp(hdfs_handle->pathname,"/dev/zero"))
    {
    }
    else 
    {
        if (hdfsSeek(hdfs_handle->fs, hdfs_handle->fd, hdfs_handle->offset) == -1) {
            rc = GlobusGFSErrorGeneric("seek() fail");
            globus_gridftp_server_finished_transfer(op, rc);
        }
    }

    globus_gridftp_server_get_optimal_concurrency(hdfs_handle->op,
                                                  &hdfs_handle->optimal_count);
    globus_l_gfs_hdfs_read_from_storage(hdfs_handle);
    return;
}

void
globus_l_gfs_hdfs_read_from_storage_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_hdfs_read_from_storage_cb);
    globus_l_gfs_hdfs_handle_t *      hdfs_handle;
 
    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;

    hdfs_handle->outstanding--;
    globus_free(buffer);
    globus_l_gfs_hdfs_read_from_storage(hdfs_handle);
}


void
globus_l_gfs_hdfs_read_from_storage(
    globus_l_gfs_hdfs_handle_t *      hdfs_handle)
{
    globus_byte_t *                     buffer;
    globus_size_t                       nbytes;
    globus_size_t                       read_length;
    globus_result_t                     rc;

    GlobusGFSName(globus_l_gfs_hdfs_read_from_storage);

    globus_mutex_lock(&hdfs_handle->mutex);
    while (hdfs_handle->outstanding < hdfs_handle->optimal_count &&
           ! hdfs_handle->done) 
    {
        buffer = globus_malloc(hdfs_handle->block_size);
        if (buffer == NULL)
        {
            rc = GlobusGFSErrorMemory("Fail to allocate buffer for HDFS.");
            globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
            return;
        }
        /* block_length == -1 indicates transferring data to eof */
        if (hdfs_handle->block_length < 0 ||   
            hdfs_handle->block_length > hdfs_handle->block_size)
        {
            read_length = hdfs_handle->block_size;
        }
        else
        {
            read_length = hdfs_handle->block_length;
        }

        if (hdfs_handle->syslog_host != NULL)
            syslog(LOG_INFO, hdfs_handle->syslog_msg, "READ", read_length, local_io_count);
        nbytes = hdfsRead(hdfs_handle->fs, hdfs_handle->fd, buffer, read_length);
        if (nbytes == 0)    /* eof */
        {
            hdfs_handle->done = GLOBUS_TRUE;
            snprintf(err_msg, MSG_SIZE, "send %d blocks of size %d bytes\n",
                            local_io_count,local_io_block_size);
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);
            local_io_count = 0;
            local_io_block_size = 0;
        }
        else
        {
            if (nbytes != local_io_block_size)
            {
                 if (local_io_block_size != 0)
                 {
                      snprintf(err_msg, MSG_SIZE, "send %d blocks of size %d bytes\n",
                                      local_io_count,local_io_block_size);
                      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);
                 }
                 local_io_block_size = nbytes;
                 local_io_count=1;
            }
            else
            {
                 local_io_count++;
            }
        }
        if (! hdfs_handle->done) 
        {
            hdfs_handle->outstanding++;
            hdfs_handle->offset += nbytes;
            hdfs_handle->block_length -= nbytes;
            rc = globus_gridftp_server_register_write(hdfs_handle->op,
                                       buffer,
                                       nbytes,
                                       hdfs_handle->offset - nbytes,
                                       -1,
                                       globus_l_gfs_hdfs_read_from_storage_cb,
                                       hdfs_handle);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GlobusGFSErrorGeneric("globus_gridftp_server_register_write() fail");
                globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
            }
        }
    }
    if (hdfs_handle->outstanding == 0)
    {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Trying to close file in HDFS.\n");
        if ((hdfs_handle->fd != NULL) && (hdfs_handle->fs != NULL) && (hdfsCloseFile(hdfs_handle->fs, hdfs_handle->fd) == -1))
        {
             hdfs_handle->fd = NULL;
             rc = GlobusGFSErrorGeneric("Failed to close file in HDFS.");
             globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
        } else {
        globus_gridftp_server_finished_transfer(hdfs_handle->op, 
                                                GLOBUS_SUCCESS);
        }
    }
    globus_mutex_unlock(&hdfs_handle->mutex);
    return;
}

