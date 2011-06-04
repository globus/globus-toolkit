
#include "gridftp_hdfs.h"

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}

/*************************************************************************
 * determine_replicas
 * ------------------
 * Determine the number of replicas for this file based on the pathname.
 *************************************************************************/
#define DEFAULT_LINE_LENGTH 256
int determine_replicas (const char * path) {
    int num_replicas = 0;
    char * replica_map = getenv("GRIDFTP_HDFS_REPLICA_MAP");
    if (!replica_map) return num_replicas;

    char *map_line = (char *)globus_malloc(sizeof(char) * DEFAULT_LINE_LENGTH);
    if (!map_line) return num_replicas;

    size_t line_length = DEFAULT_LINE_LENGTH;
    char *map_line_index;
    const char *filename_index;
    ssize_t bytes_read = 0;
    FILE *replica_map_fd = fopen(replica_map, "r");
    if (replica_map_fd == NULL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Could not open %s for reading.\n", replica_map);
        free(map_line);
        return num_replicas;
    }
    while ( (bytes_read = getline(&map_line, &line_length, replica_map_fd)) > -1) {
        map_line_index = map_line;
        filename_index = path;
        // Skip comment lines
        if (map_line && map_line[0] == '#') continue;

        // Skip over leading whitespace
        while(*map_line_index && *map_line_index == ' ') map_line_index++;

        // Try and match the map line and filename
        while(*map_line_index && *filename_index && (*map_line_index == *filename_index)) { map_line_index++; filename_index++; }

        /*
        * If we've reached the end of the pattern, then we've found
        * a match with the hdfs filename.  Snarf up the # replicas
        * from the remainder of the line.
        */
        while (*map_line_index && (*map_line_index == ' ' || *map_line_index == '=' || *map_line_index == '\t')) map_line_index++;
        if (sscanf(map_line_index, "%d", &num_replicas) != 1) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Unable to determine the number of replicas for %s", map_line);
        }
    }

    if (map_line != NULL) free(map_line);
    fclose(replica_map_fd);

    return num_replicas;
}

/*************************************************************************
 * prepare_handle
 * --------------
 * Do all the prep work for preparing an hdfs_handle to be opened
 *************************************************************************/
globus_result_t prepare_handle(hdfs_handle_t *hdfs_handle) {
    GlobusGFSName(prepare_handle);
    globus_result_t rc;

    const char *path = hdfs_handle->pathname;

    ADVANCE_SLASHES(path);
    if (strncmp(path, hdfs_handle->mount_point, hdfs_handle->mount_point_len) == 0) {
        path += hdfs_handle->mount_point_len;
    }
    ADVANCE_SLASHES(path);

    hdfs_handle->pathname = (char*)globus_malloc(strlen(path));
    if (!hdfs_handle->pathname) {MemoryError(hdfs_handle, "Unable to make a copy of the path name.", rc); return rc;}
    strcpy(hdfs_handle->pathname, path);
   
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "We are going to open file %s.\n", hdfs_handle->pathname);
    hdfs_handle->outstanding = 0;
    hdfs_handle->done = GLOBUS_FALSE;
    hdfs_handle->done_status = GLOBUS_SUCCESS;
    globus_gridftp_server_get_block_size(hdfs_handle->op, &hdfs_handle->block_size);


    // HDFS cannot start transfers in the middle of a file.
    globus_gridftp_server_get_write_range(hdfs_handle->op,
                                          &hdfs_handle->offset,
                                          &hdfs_handle->block_length);

    if (hdfs_handle->offset) {GenericError(hdfs_handle, "Non-zero offsets are not supported.", rc); return rc;}

    globus_gridftp_server_get_optimal_concurrency(hdfs_handle->op,
                                                  &hdfs_handle->optimal_count);
    hdfs_handle->buffer_count = hdfs_handle->optimal_count;
    hdfs_handle->nbytes = globus_malloc(hdfs_handle->buffer_count*sizeof(globus_size_t));
    hdfs_handle->offsets = globus_malloc(hdfs_handle->buffer_count*sizeof(globus_off_t));
    hdfs_handle->used = globus_malloc(hdfs_handle->buffer_count*sizeof(short));
    int i;
    for (i=0; i<hdfs_handle->buffer_count; i++)
        hdfs_handle->used[i] = 0;
    hdfs_handle->buffer = globus_malloc(hdfs_handle->buffer_count*hdfs_handle->block_size*sizeof(globus_byte_t));
    if (hdfs_handle->buffer == NULL || hdfs_handle->nbytes==NULL || hdfs_handle->offsets==NULL || hdfs_handle->used==NULL) {
        MemoryError(hdfs_handle, "Memory allocation error.", rc);
        return rc;
    }
    return GLOBUS_SUCCESS;
}


/*************************************************************************
 *  hdfs_recv
 *  ---------
 *  This interface function is called when the client requests that a
 *  file be transfered to the server.
 *
 ************************************************************************/
void
hdfs_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_hdfs_handle_t *        hdfs_handle;
    globus_result_t                     rc = GLOBUS_SUCCESS; 

    GlobusGFSName(hdfs_recv);

    globus_mutex_lock(&hdfs_handle->mutex);

    hdfs_handle = (hdfs_handle_t *) user_arg;
    hdfs_handle->op = op;
    hdfs_handle->pathname = transfer_info->pathname;

    if ((rc = prepare_handle(hdfs_handle)) != GLOBUS_SUCCESS) goto cleanup;

    int num_replicas = determine_replicas(hdfs_handle->pathname);
    if (!num_replicas && hdfs_handle->replicas) num_replicas = hdfs_handle->replicas;

    if (num_replicas == 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Open file %s.\n", hdfs_handle->pathname);
    } else {
	globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Open file %s with %d replicas.\n", hdfs_handle->pathname, num_replicas);
    }

    hdfsFileInfo *fileInfo;
    if ( ((fileInfo = hdfsGetPathInfo(hdfs_handle->fs, hdfs_handle->pathname)) != NULL)
            && (fileInfo->mKind == kObjectKindDirectory)){
        GenericError(hdfs_handle, "Destination path is a directory; cannot overwrite.", rc);
        goto cleanup;
    }

    hdfs_handle->fd = hdfsOpenFile(hdfs_handle->fs, hdfs_handle->pathname, O_WRONLY, 0, num_replicas, 0);
    if (!hdfs_handle->fd)
    {
        if (errno == EINTERNAL) {
            SystemError(hdfs_handle, "Failed to open file due to an internal HDFS error; could be a misconfiguration or bad installation at the site.", rc);
        } else if (errno == EACCES) {
            SystemError(hdfs_handle, "Permission error in HDFS.", rc);
        } else {
            SystemError(hdfs_handle, "Failed to open file due to unknown error in HDFS.", rc);
        }
        goto cleanup;
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Successfully opened file %s for user %s.\n", hdfs_handle->pathname, hdfs_handle->username);

    globus_gridftp_server_begin_transfer(hdfs_handle->op, 0, hdfs_handle);
    hdfs_write_to_storage(hdfs_handle);

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        globus_gridftp_server_finished_transfer(op, rc);
    }
    globus_mutex_unlock(&hdfs_handle->mutex);
}

void 
hdfs_write_to_storage_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg)
{
    globus_result_t                     rc = GLOBUS_SUCCESS; 
    globus_l_gfs_hdfs_handle_t *        hdfs_handle;
                                                                                                                                           
    GlobusGFSName(globus_l_gfs_hdfs_write_to_storage_cb);
    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;

    globus_mutex_lock(&hdfs_handle->mutex);

    if (hdfs_handle->done && hdfs_handle->done_status != GLOBUS_SUCCESS) {
        rc = hdfs_handle->done_status;
        goto cleanup;
    }

    if (result != GLOBUS_SUCCESS) {
        hdfs_handle->done = GLOBUS_TRUE;
        hdfs_handle->done_status = rc;
        goto cleanup;
    } else if (eof) {
        hdfs_handle->done = GLOBUS_TRUE;
    }

    if (nbytes > 0) {
        // First, see if we can dump this block immediately.
        if (offset == hdfs_handle->offset) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Dumping this block immediately.\n");
            if (hdfs_handle->syslog_host != NULL) {
                syslog(LOG_INFO, hdfs_handle->syslog_msg, "WRITE", nbytes, hdfs_handle->offset);
            }
            globus_size_t bytes_written = hdfsWrite(hdfs_handle->fs, hdfs_handle->fd, buffer, nbytes);
            if (bytes_written != nbytes) {
                SystemError(hdfs_handle, "Write into HDFS failed", rc);
                hdfs_handle->done = GLOBUS_TRUE;
            } else {
                hdfs_handle->offset += bytes_written;
                // Try to write out as many buffers as we can to HDFS.
                rc = hdfs_dump_buffers(hdfs_handle);
                if (rc != GLOBUS_SUCCESS) {
                    hdfs_handle->done = GLOBUS_TRUE;
                }
                globus_gridftp_server_update_bytes_written(op, offset, nbytes);
            }
        } else {
            // Try to store the buffer into memory.
            rc = hdfs_store_buffer(hdfs_handle, buffer, offset, nbytes);
            if (rc != GLOBUS_SUCCESS) {
                hdfs_handle->done = GLOBUS_TRUE;
            } else {
                // Try to write out as many buffers as we can to HDFS.
                rc = hdfs_dump_buffers(hdfs_handle);
                if (rc != GLOBUS_SUCCESS) {
                    hdfs_handle->done = GLOBUS_TRUE;
                }
                globus_gridftp_server_update_bytes_written(op, offset, nbytes);
            }
        }

        // Do some statistics
        if (nbytes != hdfs_handle->io_block_size) {
            if (hdfs_handle->io_block_size != 0) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "receive %d blocks of size %d bytes\n",
                                hdfs_handle->io_count,hdfs_handle->io_block_size);
            }
            hdfs_handle->io_block_size = nbytes;
            hdfs_handle->io_count=1;
        } else {
            hdfs_handle->io_count++;
        }
    }
    globus_free(buffer);

cleanup:

    hdfs_handle->outstanding--;
    if (! hdfs_handle->done) {
        hdfs_write_to_storage(hdfs_handle);
    } else if (hdfs_handle->outstanding == 0) {

        // Destroy handle. TODO: factor out
        if (hdfs_handle->using_file_buffer == 0) {
            globus_free(hdfs_handle->buffer);
        } else {
            munmap(hdfs_handle->buffer, hdfs_handle->block_size*hdfs_handle->buffer_count*sizeof(globus_byte_t));
            hdfs_handle->using_file_buffer = 0;
            close(hdfs_handle->tmpfilefd);
        }
        globus_free(hdfs_handle->used);
        globus_free(hdfs_handle->nbytes);
        globus_free(hdfs_handle->offsets);

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Trying to close file in HDFS; zero outstanding blocks.\n");
        if ((hdfs_handle->fd != NULL) && (hdfs_handle->fs != NULL) && (hdfsCloseFile(hdfs_handle->fs, hdfs_handle->fd) == -1)) {
             GenericError(hdfs_handle, "Failed to close file in HDFS.", rc);
             set_done(hdfs_handle, rc);
             hdfs_handle->fd = NULL;
        }

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "receive %d blocks of size %d bytes\n",
            hdfs_handle->io_count, hdfs_handle->io_block_size);

        hdfs_handle->done_status = rc;

        globus_gridftp_server_finished_transfer(op, rc);
    } else if (rc != GLOBUS_SUCCESS) {  // Done is set, but we have outstanding I/O = failed somewhere.
        // Don't close the file because the other transfers will want to finish up.
        snprintf(err_msg, MSG_SIZE, "We failed to finish the transfer, but there are %i outstanding writes left over.\n", hdfs_handle->outstanding);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);
        hdfs_handle->done_status = rc;
    }
    globus_mutex_unlock(&hdfs_handle->mutex);
}

// Note: The hdfs_handle mutex *must* be locked prior to calling
void
hdfs_write_to_storage(
    globus_l_gfs_hdfs_handle_t *      hdfs_handle)
{
    globus_byte_t *                     buffer;
    globus_result_t                     rc = GLOBUS_SUCCESS;

    GlobusGFSName(hdfs_write_to_storage);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "hdfs_write_to_storage; outstanding %d, optimal %d.\n", hdfs_handle->outstanding, hdfs_handle->optimal_count);

    while (hdfs_handle->outstanding < hdfs_handle->optimal_count)  {

        buffer = globus_malloc(hdfs_handle->block_size);
        if (buffer == NULL) {
            MemoryError(hdfs_handle, "Fail to allocate buffer for HDFS data.", rc);
            goto cleanup;
        }

        rc = globus_gridftp_server_register_read(hdfs_handle->op,
            buffer,
            hdfs_handle->block_size,
            hdfs_write_to_storage_cb,
            hdfs_handle);

        if (rc != GLOBUS_SUCCESS) {
            GenericError(hdfs_handle, "globus_gridftp_server_register_read() fail", rc);
            goto cleanup;
        }
        hdfs_handle->outstanding++;

    }

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
    }
}

