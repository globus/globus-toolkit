
#include "gridftp_hdfs.h"

typedef globus_l_gfs_hdfs_handle_t hdfs_handle_t;

#define ADVANCE_SLASHES (x) {while (x[0] == '/' && x[1] == '/') x++}

char * get_hostname_alloc() {
    char * hostname = globus_malloc(sizeof(char)*256);
    if (!hostname) return hostname;
    memset(hostname, '\0', sizeof(char)*256);
    if (gethostname(hostname, 255) != 0) {
        sprintf(hostname, "UNKNOWN");
    }
}

// Messages should not end with newline
#define MESSAGE_BUFFER_SIZE 1024
globus_result_t ErrorGeneric(const char *msg) {
    char formatted_msg[MESSAGE_BUFFER_SIZE];
    char * user = hdfs_handle ? hdfs_handle->user : NULL;
    char * path = hdfs_handle ? hdfs_handle->pathname : NULL;
    char * host = get_hostname_alloc();
    snprintf(formatted_msg, MESSAGE_BUFFER_SIZE, "%s (host=%s, user=%s, path=%s)", msg, host, user, path);
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "%s\n", formatted_msg);
    return GlobusGFSErrorGeneric(msg);
}

globus_result_t ErrorSystem(hdfs_handle_t hdfs_handle, const char *msg) {
    char formatted_msg[MESSAGE_BUFFER_SIZE];
    char * user = hdfs_handle ? hdfs_handle->user : NULL;
    char * path = hdfs_handle ? hdfs_handle->pathname : NULL;
    char * host = get_hostname_alloc();
    snprintf(formatted_msg, MESSAGE_BUFFER_SIZE, "%s (host=%s, user=%s, path=%s)", msg, host, user, path);
    if (host) free(host);
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "%s\n", formatted_msg);
    return GlobusGFSErrorSystemError(formatted_msg, errno);
}

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

    char map_line = (char *)globus_malloc(sizeof(char) * DEFAULT_LINE_LENGTH);
    if (!map_line) return num_replicas;

    size_t line_length = DEFAULT_LINE_LENGTH;
    char *map_line_index;
    char *filename_index;
    ssize_t bytes_read = 0;
    FILE *replica_map_fd = fopen(replica_map, "r");
    if (replica_map_fd == NULL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Could not open %s for reading.\n", replica_map);
        free(map_line);
        return num_replicas;
    }
    while ( (bytes_read = getline(&map_line, &line_length, replica_map_fd)) > -1) {
        map_line_index = map_line;
        filename_index = hdfs_handle->pathname;
        // Skip comment lines
        if (map_line && map_line[0] == '#') continue

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
    }
    return num_replicas;
}

/*************************************************************************
 * prepare_handle
 * --------------
 * Do all the prep work for preparing an hdfs_handle to be opened
 *************************************************************************/
globus_result_t prepare_handle(hdfs_handle_t *hdfs_handle, const char *path) {

    ADVANCE_SLASHES(path);
    if (strncmp(path, hdfs_handle->mount_point, hdfs_handle->mount_point_len) == 0) {
        path += hdfs_handle->mount_point_len;
    }
    ADVANCE_SLASHES(path);

    hdfs_handle->pathname = strcpy(path);
    if (!hdfs_handle->pathname) return ErrorGeneric(hdfs_handle, "Unable to make a copy of the path name.")
   
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "We are going to open file %s.\n", hdfs_handle->pathname);
    hdfs_handle->outstanding = 0;
    hdfs_handle->done = GLOBUS_FALSE;
    hdfs_handle->done_status = GLOBUS_SUCCESS;
    globus_gridftp_server_get_block_size(op, &hdfs_handle->block_size);


    // HDFS cannot start transfers in the middle of a file.
    globus_gridftp_server_get_write_range(hdfs_handle->op,
                                          &hdfs_handle->offset,
                                          &hdfs_handle->block_length);

    if (hdfs_handle->offset) return ErrorGeneric(hdfs_handle, "Non-zero offsets are not supported.");

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
        rc = MemoryError("Memory allocation error.");
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
        return;
    }
}


/*************************************************************************
 *  recv
 *  ----
 *  This interface function is called when the client requests that a
 *  file be transfered to the server.
 *
 *  To receive a file the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_read();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
void
recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_hdfs_handle_t *        hdfs_handle;
    globus_result_t                     rc = GLOBUS_SUCCESS; 

    GlobusGFSName(globus_l_gfs_hdfs_recv);

    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;
    hdfs_handle->op = op;

    if ((rc = prepare_handle(hdfs_handle)) != GLOBUS_SUCCESS) goto cleanup;

    int num_replicas = determine_replicas(hdfs_handle->pathname);
    if (num_replicas == 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Open file %s.\n", hdfs_handle->pathname);
    } else {
	globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Open file %s with %d replicas.\n", hdfs_handle->pathname, num_replicas);
    }
   
    if (((fileInfo = hdfsGetPathInfo(hdfs_handle->fs, hdfs_handle->pathname)) != NULL) && (fileInfo->mKind == kObjectKindDirectory)){
        rc = ErrorGeneric("Destination path is a directory; cannot overwrite.");
        goto cleanup;
    }

    globus_mutex_lock(&hdfs_handle->mutex);
    hdfs_handle->fd = hdfsOpenFile(hdfs_handle->fs, hdfs_handle->pathname, O_WRONLY, 0, num_replicas, 0);
    if (!hdfs_handle->fd)
    {
        if (errno == EINTERNAL) {
            rc = SystemError(hdfs_handle, "Failed to open file due to an internal HDFS error; could be a misconfiguration or bad installation at the site.")
        } else if (errno == EACCES) {
            rc = SystemError(hdfs_handle, "Permission error in HDFS.")
        } else {
            rc = SystemError(hdfs_handle, "Failed to open file due to unknown error in HDFS.")
        }
        goto cleanup;
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Successfully opened file %s for user %s.\n", hdfs_handle->pathname, hdfs_handle->username);

    globus_gridftp_server_begin_transfer(hdfs_handle->op, 0, hdfs_handle);
    write_to_storage(hdfs_handle);

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        globus_gridftp_server_finished_transfer(op, rc);
    }
    globus_mutex_unlock(&hdfs_handle->mutex);
}

void 
globus_l_gfs_hdfs_write_to_storage_cb(
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
                rc = SystemError(hdfs_handle, "Write into HDFS failed");
                hdfs_handle->done = GLOBUS_TRUE;
            } else {
                hdfs_handle->offset += bytes_written;
                // Try to write out as many buffers as we can to HDFS.
                rc = globus_l_gfs_hdfs_dump_buffers(hdfs_handle);
                if (rc != GLOBUS_SUCCESS) {
                    hdfs_handle->done = GLOBUS_TRUE;
                }
                globus_gridftp_server_update_bytes_written(op, offset, nbytes);
            }
        } else {
            // Try to store the buffer into memory.
            rc = globus_l_gfs_hdfs_store_buffer(hdfs_handle, buffer, offset, nbytes);
            if (rc != GLOBUS_SUCCESS) {
                //printf("Store failed.\n");
                hdfs_handle->done = GLOBUS_TRUE;
            } else {
                // Try to write out as many buffers as we can to HDFS.
                rc = globus_l_gfs_hdfs_dump_buffers(hdfs_handle);
                if (rc != GLOBUS_SUCCESS) {
                    hdfs_handle->done = GLOBUS_TRUE;
                }
                globus_gridftp_server_update_bytes_written(op, offset, nbytes);
            }
        }
        if (nbytes != local_io_block_size)
        {
            if (local_io_block_size != 0)
            {
                snprintf(err_msg, MSG_SIZE, "receive %d blocks of size %d bytes\n",
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
    globus_free(buffer);

cleanup:

    hdfs_handle->outstanding--;
    if (! hdfs_handle->done) {
        // Ask for more transfers!
        globus_l_gfs_hdfs_write_to_storage(hdfs_handle);
    } else if (hdfs_handle->outstanding == 0) {

        // Destroy handle. TODO: factor out
        if (hdfs_handle->using_file_buffer == 0)        
            globus_free(hdfs_handle->buffer);
        else {
            munmap(hdfs_handle->buffer, hdfs_handle->block_size*hdfs_handle->buffer_count*sizeof(globus_byte_t));
            hdfs_handle->using_file_buffer = 0;
            close(hdfs_handle->tmpfilefd);
        }
        globus_free(hdfs_handle->used);
        globus_free(hdfs_handle->nbytes);
        globus_free(hdfs_handle->offsets);

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Trying to close file in HDFS; zero outstanding blocks.\n");
        if ((hdfs_handle->fd != NULL) && (hdfs_handle->fs != NULL) && (hdfsCloseFile(hdfs_handle->fs, hdfs_handle->fd) == -1)) {
             if (rc == GLOBUS_SUCCESS) {
               rc = GenericError(hdfs_handle, "Failed to close file in HDFS.");
             }
             hdfs_handle->fd = NULL;
        }

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "receive %d blocks of size %d bytes\n",
            local_io_count,local_io_block_size);
        local_io_count = 0;
        local_io_block_size = 0;

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
write_to_storage(
    globus_l_gfs_hdfs_handle_t *      hdfs_handle)
{
    globus_byte_t *                     buffer;
    globus_result_t                     rc = GLOBUS_SUCCESS;

    GlobusGFSName(globus_l_gfs_hdfs_write_to_storage);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Globus write_to_storage; outstanding %d, optimal %d.\n", hdfs_handle->outstanding, hdfs_handle->optimal_count);

    while (hdfs_handle->outstanding < hdfs_handle->optimal_count)  {

        buffer = globus_malloc(hdfs_handle->block_size);
        if (buffer == NULL) {
            rc = MemoryError("Fail to allocate buffer for HDFS data.");
            goto cleanup;
        }

        rc = globus_gridftp_server_register_read(hdfs_handle->op,
            buffer,
            hdfs_handle->block_size,
            write_to_storage_cb,
            hdfs_handle);

        if (rc != GLOBUS_SUCCESS) {
            rc = GenericError("globus_gridftp_server_register_read() fail");
            goto cleanup;
        }
        hdfs_handle->outstanding++;

    }

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
    }
}

/**
 *  Decide whether we should use a file buffer based on the current
 *  memory usage.
 *  Returns 1 if we should use a file buffer.
 *  Else, returns 0.
 */
int use_file_buffer(globus_l_gfs_hdfs_handle_t * hdfs_handle) {
        int buffer_count = hdfs_handle->buffer_count;
 
		  if (buffer_count >= hdfs_handle->max_buffer_count-1) {
            return 1;
		  }
        if ((hdfs_handle->using_file_buffer == 1) && (buffer_count > hdfs_handle->max_buffer_count/2))
            return 1;
        return 0;
}

/*************************************************************************
 *  remove_file_buffer
 *  ------------------
 *  This is called when cleaning up a file buffer. The file on disk is removed and
 *  the internal memory for storing the filename is freed.
 ************************************************************************/
void
remove_file_buffer(globus_l_gfs_hdfs_handle_t * hdfs_handle) {
    if (hdfs_handle->tmp_file_pattern) {
	snprintf(err_msg, MSG_SIZE, "Removing file buffer %s.\n", hdfs_handle->tmp_file_pattern);
	globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
        unlink(hdfs_handle->tmp_file_pattern);
        globus_free(hdfs_handle->tmp_file_pattern);
	hdfs_handle->tmp_file_pattern = (char *)NULL;
    }
}

/**
 *  Store the current output to a buffer.
 */
globus_result_t globus_l_gfs_hdfs_store_buffer(globus_l_gfs_hdfs_handle_t * hdfs_handle, globus_byte_t* buffer, globus_off_t offset, globus_size_t nbytes) {
		  GlobusGFSName(globus_l_gfs_hdfs_store_buffer);
		  globus_result_t rc = GLOBUS_SUCCESS;
		  int i, cnt = hdfs_handle->buffer_count;
		  short wrote_something = 0;
		  if (hdfs_handle == NULL) {
					 rc = GlobusGFSErrorGeneric("Storing buffer for un-allocated transfer");
					 return rc;
		  }

        // Determine the type of buffer to use; allocate or transfer buffers as necessary
        int use_buffer = use_file_buffer(hdfs_handle);
        if ((use_buffer == 1) && (hdfs_handle->using_file_buffer == 0)) {
            // Turn on file buffering, copy data from the current memory buffer.
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Switching from memory buffer to file buffer.\n");

            char *tmpdir=getenv("TMPDIR");
            if (tmpdir == NULL) {
                tmpdir = "/tmp";
            }
            hdfs_handle->tmp_file_pattern = globus_malloc(sizeof(char) * (strlen(tmpdir) + 32));
            sprintf(hdfs_handle->tmp_file_pattern, "%s/gridftp-hdfs-buffer-XXXXXX", tmpdir);

            hdfs_handle->tmpfilefd = mkstemp(hdfs_handle->tmp_file_pattern);
            int filedes = hdfs_handle->tmpfilefd;
            if (filedes == -1) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to determine file descriptor of temporary file.\n");
                rc = GlobusGFSErrorGeneric("Failed to determine file descriptor of temporary file.");
                return rc;
            }
            snprintf(err_msg, MSG_SIZE, "Created file buffer %s.\n", hdfs_handle->tmp_file_pattern);
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
            char * tmp_write = globus_calloc(hdfs_handle->block_size, sizeof(globus_byte_t));
            if (tmp_write == NULL) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Could not allocate memory for dumping file buffer.\n");
            }
            /* Write into the file to create its initial size */
            for (i=0; i<cnt; i++) {
                if (write(filedes, tmp_write, sizeof(globus_byte_t)*hdfs_handle->block_size) < 0) {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to initialize backing file.\n");
                    rc = GlobusGFSErrorGeneric("Failed to initialize backing file.");
                    return rc;
                }
            }
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Pre-filled file buffer with empty data.\n");
            globus_free(tmp_write);
            globus_byte_t * file_buffer = mmap(0, hdfs_handle->block_size*hdfs_handle->max_file_buffer_count*sizeof(globus_byte_t), PROT_READ | PROT_WRITE, MAP_SHARED, filedes, 0);
            if (file_buffer == (globus_byte_t *)-1) {
                if (errno == ENOMEM) {
                    snprintf(err_msg, MSG_SIZE, "Error mmapping the file buffer (%ld bytes): errno=ENOMEM\n", hdfs_handle->block_size*hdfs_handle->max_file_buffer_count*sizeof(globus_byte_t));
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
                } else {
                    snprintf(err_msg, MSG_SIZE, "Error mmapping the file buffer: errno=%d\n", errno);
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
                }
                /*
                 * Regardless of the error, remove the file buffer.
                 */
                remove_file_buffer(hdfs_handle);
                /*
                 * Is this the proper way to exit from here?
                 */
                rc = GlobusGFSErrorGeneric("Failed to mmap() the file buffer.");
                return rc;
            }
            memcpy(file_buffer, hdfs_handle->buffer, cnt*hdfs_handle->block_size*sizeof(globus_byte_t));
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Memory buffers copied to disk buffer.\n");
            globus_free(hdfs_handle->buffer);
            hdfs_handle->buffer = file_buffer;
            hdfs_handle->using_file_buffer = 1;
        } else if (use_buffer == 1) {
            // Do nothing.  Continue to use the file buffer for now.
        } else if (hdfs_handle->using_file_buffer == 1 && cnt < hdfs_handle->max_buffer_count) {
            // Turn off file buffering; copy data to a new memory buffer
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Switching from file buffer to memory buffer.\n");
            globus_byte_t * tmp_buffer = globus_malloc(sizeof(globus_byte_t)*hdfs_handle->block_size*cnt);
            if (tmp_buffer == NULL) {
                rc = GlobusGFSErrorGeneric("Memory allocation error.");
                globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error.");
                return rc;
            }
            memcpy(tmp_buffer, hdfs_handle->buffer, cnt*hdfs_handle->block_size*sizeof(globus_byte_t));
            munmap(hdfs_handle->buffer, hdfs_handle->block_size*hdfs_handle->buffer_count*sizeof(globus_byte_t));
            hdfs_handle->using_file_buffer = 0;
            close(hdfs_handle->tmpfilefd);
	    remove_file_buffer(hdfs_handle);
            hdfs_handle->buffer = tmp_buffer;
        } else {
            // Do nothing.  Continue to use the file buffer for now.
        }

        // Search for a free space in our buffer, and then actually make the copy.
		  for (i = 0; i<cnt; i++) {
					 if (hdfs_handle->used[i] == 0) {
								snprintf(err_msg, MSG_SIZE, "Stored some bytes in buffer %d; offset %lu.\n", i, offset);
								globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);
            hdfs_handle->nbytes[i] = nbytes;
            hdfs_handle->offsets[i] = offset;
            hdfs_handle->used[i] = 1;
            wrote_something=1;
            memcpy(hdfs_handle->buffer+i*hdfs_handle->block_size, buffer, nbytes*sizeof(globus_byte_t));
            break;
        }
    }

    // Check to see how many unused buffers we have;
    i = cnt;
    while (i>0) {
        i--;
        if (hdfs_handle->used[i] == 1) {
            break;
        }
    }
    i++;
    snprintf(err_msg, MSG_SIZE, "There are %i extra buffers.\n", cnt-i);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);
    // If there are more than 10 unused buffers, deallocate.
    if (cnt - i > 10) {
        snprintf(err_msg, MSG_SIZE, "About to deallocate %i buffers; %i will be left.\n", cnt-i, i);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
        hdfs_handle->buffer_count = i;
        hdfs_handle->nbytes = globus_realloc(hdfs_handle->nbytes, hdfs_handle->buffer_count*sizeof(globus_size_t));
        hdfs_handle->offsets = globus_realloc(hdfs_handle->offsets, hdfs_handle->buffer_count*sizeof(globus_off_t));
        hdfs_handle->used = globus_realloc(hdfs_handle->used, hdfs_handle->buffer_count*sizeof(short));
        if (hdfs_handle->using_file_buffer == 0)
            hdfs_handle->buffer = globus_realloc(hdfs_handle->buffer, hdfs_handle->buffer_count*hdfs_handle->block_size*sizeof(globus_byte_t));
        else {
            // Truncate the file holding our backing data (note we don't resize the mmap).
            if (ftruncate(hdfs_handle->tmpfilefd, hdfs_handle->buffer_count*hdfs_handle->block_size*sizeof(globus_byte_t))) {
                rc = GlobusGFSErrorGeneric("Unable to truncate our file-backed data.");
                globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to truncate our file-backed data.\n");
            }
            lseek(hdfs_handle->tmpfilefd, 0, SEEK_END);
        }
        if (hdfs_handle->buffer == NULL || hdfs_handle->nbytes==NULL || hdfs_handle->offsets==NULL || hdfs_handle->used==NULL) {
            rc = GlobusGFSErrorGeneric("Memory allocation error.");
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error.");
            globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
            return rc;
        }
    }

    // If wrote_something=0, then we have filled up all our buffers; allocate a new one.
    if (wrote_something == 0) {
        hdfs_handle->buffer_count += 1;
        snprintf(err_msg, MSG_SIZE, "Initializing buffer number %d.\n", hdfs_handle->buffer_count);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
        // Refuse to allocate more than the max.
        if ((hdfs_handle->using_file_buffer == 0) && (hdfs_handle->buffer_count == hdfs_handle->max_buffer_count)) {
            // Out of memory buffers; we really shouldn't hit this code anymore.
            char * hostname = globus_malloc(sizeof(char)*256);
            memset(hostname, '\0', sizeof(char)*256);
            if (gethostname(hostname, 255) != 0) {
                sprintf(hostname, "UNKNOWN");
            }
            snprintf(err_msg, MSG_SIZE, "Allocated all %i memory buffers on server %s; aborting transfer.", hdfs_handle->max_buffer_count, hostname);
            globus_free(hostname);
            rc = GlobusGFSErrorGeneric(err_msg);
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to store data into HDFS buffer.\n");
        } else if ((hdfs_handle->using_file_buffer == 1) && (hdfs_handle->buffer_count == hdfs_handle->max_file_buffer_count)) {
            // Out of file buffers.
            char * hostname = globus_malloc(sizeof(char)*256);
            memset(hostname, '\0', sizeof(char)*256);
            if (gethostname(hostname, 255) != 0) {
                sprintf(hostname, "UNKNOWN");
            }
            snprintf(err_msg, MSG_SIZE, "Allocated all %i file-backed buffers on server %s; aborting transfer.", hdfs_handle->max_file_buffer_count, hostname);
            globus_free(hostname);
            rc = GlobusGFSErrorGeneric(err_msg);
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to store data into HDFS buffer.\n");
        } else {
            // Increase the size of all our buffers which track memory usage
            hdfs_handle->nbytes = globus_realloc(hdfs_handle->nbytes, hdfs_handle->buffer_count*sizeof(globus_size_t));
            hdfs_handle->offsets = globus_realloc(hdfs_handle->offsets, hdfs_handle->buffer_count*sizeof(globus_off_t));
            hdfs_handle->used = globus_realloc(hdfs_handle->used, hdfs_handle->buffer_count*sizeof(short));
            hdfs_handle->used[hdfs_handle->buffer_count-1] = 1;
            // Only reallocate the physical buffer if we're using a memory buffer, otherwise we screw up our mmap
            if (hdfs_handle->using_file_buffer == 0) {
                hdfs_handle->buffer = globus_realloc(hdfs_handle->buffer, hdfs_handle->buffer_count*hdfs_handle->block_size*sizeof(globus_byte_t));
            } else {
                // This not only extends the size of our file, but we extend it with the desired buffer data.
                lseek(hdfs_handle->tmpfilefd, (hdfs_handle->buffer_count-1)*hdfs_handle->block_size, SEEK_SET);
                if (write(hdfs_handle->tmpfilefd, buffer, nbytes*sizeof(globus_byte_t)) < 0) {
                    rc = GlobusGFSErrorGeneric("Unable to extend our file-backed buffers; aborting transfer.");
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to extend our file-backed buffers; aborting transfer.\n");
                }
                // If our buffer was too small, 
                if (nbytes < hdfs_handle->block_size) {
                    int addl_size = hdfs_handle->block_size-nbytes;
                    char * tmp_write = globus_calloc(addl_size, sizeof(globus_byte_t));
                    if (write(hdfs_handle->tmpfilefd, tmp_write, sizeof(globus_byte_t)*addl_size) < 0) {
                        rc = GlobusGFSErrorGeneric("Unable to extend our file-backed buffers; aborting transfer.");
                        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to extend our file-backed buffers; aborting transfer.\n");
                    }
                    globus_free(tmp_write);
                }
                //hdfs_handle->buffer = mmap(hdfs_handle->buffer, hdfs_handle->block_size*hdfs_handle->max_file_buffer_count*sizeof(globus_byte_t), PROT_READ | PROT_WRITE, MAP_PRIVATE, hdfs_handle->tmpfilefd, 0);
            }
            if (hdfs_handle->buffer == NULL || hdfs_handle->nbytes==NULL || hdfs_handle->offsets==NULL || hdfs_handle->used==NULL) {  
                rc = GlobusGFSErrorGeneric("Memory allocation error.");
                globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error.\n");
                globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
            }
            // In the case where we have file buffers, we already wrote the contents of buffer previously.
            if (hdfs_handle->using_file_buffer == 0) {
                memcpy(hdfs_handle->buffer+(hdfs_handle->buffer_count-1)*hdfs_handle->block_size, buffer, nbytes*sizeof(globus_byte_t));
            }
            hdfs_handle->nbytes[hdfs_handle->buffer_count-1] = nbytes;
            hdfs_handle->offsets[hdfs_handle->buffer_count-1] = offset;
        }
    }

    return rc;
}

/**
 * Scan through all the buffers we own, then write out all the consecutive ones to HDFS.
 */
globus_result_t
globus_l_gfs_hdfs_dump_buffers(hdfs_handle_t *hdfs_handle) {

    globus_off_t * offsets = hdfs_handle->offsets;
    globus_size_t * nbytes = hdfs_handle->nbytes;
    globus_size_t bytes_written = 0;
    size_t i, wrote_something;
    size_t cnt = hdfs_handle->buffer_count;
    GlobusGFSName(globus_l_gfs_hdfs_dump_buffers);

    globus_result_t rc = GLOBUS_SUCCESS;

    wrote_something=1;
    // Loop through all our buffers; loop again if we write something.
    while (wrote_something == 1) {
        wrote_something=0;
        // For each of our buffers.
        for (i=0; i<cnt; i++) {
            if (hdfs_handle->used[i] == 1 && offsets[i] == hdfs_handle->offset) {
                //printf("Flushing %d bytes at offset %d from buffer %d.\n", nbytes[i], hdfs_handle->offset, i);
                if (hdfs_handle->syslog_host != NULL) {
                    syslog(LOG_INFO, hdfs_handle->syslog_msg, "WRITE", nbytes[i], hdfs_handle->offset);
                }
                bytes_written = hdfsWrite(hdfs_handle->fs, hdfs_handle->fd, hdfs_handle->buffer+i*hdfs_handle->block_size, nbytes[i]*sizeof(globus_byte_t));
                if (bytes_written > 0) {
                    wrote_something = 1;
                }
                if (bytes_written != nbytes[i]) {
                    rc = SystemError(hdfs_handle, "Write into HDFS failed");
                    hdfs_handle->done = GLOBUS_TRUE;
                    hdfs_handle->done_status = rc;
                    return rc;
                }
                hdfs_handle->used[i] = 0;
                hdfs_handle->offset += bytes_written;
            }
        }
    }
    //if (hdfs_handle->buffer_count > 10) {
    //    printf("Waiting on buffer %d\n", hdfs_handle->offset);
    //}
    return rc;
}

