
#include "gridftp_hdfs.h"
#include <syslog.h>
#include <sys/mman.h>

/*************************************************************************
 *  use_file_buffer
 *  ---------------
 *  Decide whether we should use a file buffer based on the current
 *  memory usage.
 *  Returns 1 if we should use a file buffer.
 *  Else, returns 0.
 ************************************************************************/
static inline int
use_file_buffer(globus_l_gfs_hdfs_handle_t * hdfs_handle) {

    unsigned int buffer_count = hdfs_handle->buffer_count;
 
    if (buffer_count >= hdfs_handle->max_buffer_count-1) {
        return 1;
    }
    if ((hdfs_handle->using_file_buffer == 1) && (buffer_count > hdfs_handle->max_buffer_count/2)) {
        return 1;
    }
    return 0;
}

/*************************************************************************
 *  remove_file_buffer
 *  ------------------
 *  This is called when cleaning up a file buffer. The file on disk is removed and
 *  the internal memory for storing the filename is freed.
 ************************************************************************/

void
remove_file_buffer(hdfs_handle_t * hdfs_handle) {
    if (hdfs_handle->tmp_file_pattern) {
        snprintf(err_msg, MSG_SIZE, "Removing file buffer %s.\n", hdfs_handle->tmp_file_pattern);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
        globus_free(hdfs_handle->tmp_file_pattern);
	hdfs_handle->tmp_file_pattern = (char *)NULL;
    }
}

/**
 *  Initialize backing store
 */
static globus_result_t hdfs_initialize_file(globus_l_gfs_hdfs_handle_t * hdfs_handle) {
    int i, cnt;
    globus_result_t rc = GLOBUS_SUCCESS;
    // Initial file buffer.
    GlobusGFSName(globus_l_gfs_hdfs_initialize_file);
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
            remove_file_buffer(hdfs_handle);
            return rc;
    }
    unlink(hdfs_handle->tmp_file_pattern);
    snprintf(err_msg, MSG_SIZE, "Created file buffer %s.\n", hdfs_handle->tmp_file_pattern);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
    char * tmp_write = globus_calloc(hdfs_handle->block_size, sizeof(globus_byte_t));
    if (tmp_write == NULL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Could not allocate memory for dumping file buffer.\n");
        rc = GlobusGFSErrorGeneric("Could not allocate memory for dumping file buffer.");
        return rc;
    }
    /* Write into the file to create its initial size */
    cnt = hdfs_handle->buffer_count;
    for (i=0; i<cnt; i++) {
        if (write(filedes, tmp_write, sizeof(globus_byte_t)*hdfs_handle->block_size) < 0) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to initialize backing file.\n");
            rc = GlobusGFSErrorGeneric("Failed to initialize backing file.");
            globus_free(tmp_write);
            return rc; 
        }   
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Pre-filled file buffer with empty data.\n");
    globus_free(tmp_write);
    return rc;
}

static globus_result_t hdfs_populate_mmap(globus_l_gfs_hdfs_handle_t* hdfs_handle) {
    GlobusGFSName(hdfs_populate_mmap);
    int filedes = hdfs_handle->tmpfilefd, cnt;
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_byte_t * file_buffer = mmap(0, hdfs_handle->block_size*hdfs_handle->max_file_buffer_count*sizeof(globus_byte_t),
        PROT_READ | PROT_WRITE, MAP_SHARED, filedes, 0);
    if (file_buffer == (globus_byte_t *)-1) {
        if (errno == ENOMEM) {
            snprintf(err_msg, MSG_SIZE, "Error mmapping the file buffer (%ld bytes): errno=ENOMEM\n",
                hdfs_handle->block_size*hdfs_handle->max_file_buffer_count*sizeof(globus_byte_t));
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
        } else {
            snprintf(err_msg, MSG_SIZE, "Error mmapping the file buffer: errno=%d\n", errno);
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
        }
        remove_file_buffer(hdfs_handle);
        rc = GlobusGFSErrorGeneric("Failed to mmap() the file buffer.");
        return rc;
    }
    cnt = hdfs_handle->buffer_count;
    memcpy(file_buffer, hdfs_handle->buffer, cnt*hdfs_handle->block_size*sizeof(globus_byte_t));
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Memory buffers copied to disk buffer.\n");
    globus_free(hdfs_handle->buffer);
    hdfs_handle->buffer = file_buffer;
    hdfs_handle->using_file_buffer = 1;
    return GLOBUS_SUCCESS;
}

/**
 *  Store the current output to a buffer.
 */
globus_result_t hdfs_store_buffer(globus_l_gfs_hdfs_handle_t * hdfs_handle, globus_byte_t* buffer, globus_off_t offset, globus_size_t nbytes) {
    GlobusGFSName(hdfs_store_buffer);
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
        if ((rc = hdfs_initialize_file(hdfs_handle)) != GLOBUS_SUCCESS) {
            return rc;
        }
        if ((rc = hdfs_populate_mmap(hdfs_handle)) != GLOBUS_SUCCESS) {
            return rc;
        }
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
        if (hdfs_handle->buffer_count > hdfs_handle->max_buffer_count/2) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Initializing buffer number %d.\n", hdfs_handle->buffer_count);
        } else {
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Initializing buffer number %d.\n", hdfs_handle->buffer_count);
        }
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
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to store data into HDFS file buffer.\n");
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
hdfs_dump_buffers(hdfs_handle_t *hdfs_handle) {

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
                globus_byte_t *tmp_buffer = hdfs_handle->buffer+i*hdfs_handle->block_size;
                globus_size_t tmp_nbytes = nbytes[i]*sizeof(globus_byte_t);
                if ((rc = hdfs_dump_buffer_immed(hdfs_handle, tmp_buffer, tmp_nbytes)) != GLOBUS_SUCCESS) {
                    return rc;
                }
                if (tmp_nbytes > 0) {
                    wrote_something = 1;
                }
                hdfs_handle->used[i] = 0;
            }
            //if (hdfs_handle->used[i]) {
            //    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Occupied buffer %i with offset %lu.\n", i, offsets[i]);
            //}
        }
    }
    return rc;
}

globus_result_t hdfs_dump_buffer_immed(hdfs_handle_t *hdfs_handle, globus_byte_t *buffer, globus_size_t nbytes) {
    globus_result_t rc = GLOBUS_SUCCESS;

    GlobusGFSName(hdfs_dump_buffer_immed);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Dumping buffer at %lu.\n", hdfs_handle->offset);
    if (hdfs_handle->syslog_host != NULL) {
        syslog(LOG_INFO, hdfs_handle->syslog_msg, "WRITE", nbytes, hdfs_handle->offset);
    }
    globus_size_t bytes_written = hdfsWrite(hdfs_handle->fs, hdfs_handle->fd, buffer, nbytes);
    if (bytes_written != nbytes) {
        SystemError(hdfs_handle, "write into HDFS", rc);
        set_done(hdfs_handle, rc);
        return rc;
    }
    // Checksum after writing to disk.  This way, if a non-transient corruption occurs
    // during writing to Hadoop, we detect it and hopefully fail the file.
    if (hdfs_handle->cksm_types) {
        hdfs_update_checksums(hdfs_handle, buffer, nbytes);
    }
    hdfs_handle->offset += bytes_written;
    return rc;
}

/**
 *  Buffer management functions for the read workflow
 */
globus_result_t
allocate_buffers( 
    hdfs_handle_t * hdfs_handle, 
    globus_size_t          num_buffers)
{   
    GlobusGFSName(allocate_buffers);
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_ssize_t new_size = num_buffers-hdfs_handle->buffer_count;
    if (new_size > 0) {
        // Re-allocate our buffers
        hdfs_handle->buffer = globus_realloc(hdfs_handle->buffer,
            num_buffers*hdfs_handle->block_size*sizeof(globus_byte_t));
        hdfs_handle->used = globus_realloc(hdfs_handle->used,
            num_buffers*sizeof(globus_bool_t));
        hdfs_handle->offsets = globus_realloc(hdfs_handle->offsets,
            num_buffers*sizeof(globus_off_t));
        hdfs_handle->nbytes = globus_realloc(hdfs_handle->nbytes,
            num_buffers*sizeof(globus_size_t));
        memset(hdfs_handle->used+hdfs_handle->buffer_count, 0, sizeof(short)*new_size);
        hdfs_handle->buffer_count = num_buffers;

        if (!hdfs_handle->buffer || !hdfs_handle->offsets
                || !hdfs_handle->used || !hdfs_handle->nbytes) {
            MemoryError(hdfs_handle, "Allocating buffers for read", rc)
            return rc;
        }
    }
    return rc;
}   

globus_ssize_t
find_buffer(
    hdfs_handle_t * hdfs_handle,
    globus_byte_t * buffer)                       
{
    globus_ssize_t result = -1;
    globus_size_t idx;
    for (idx=0; idx<hdfs_handle->buffer_count; idx++) {
        if (hdfs_handle->buffer+idx*hdfs_handle->block_size == buffer) {
            result = idx;
            break;
        } 
    }   
    return result;
}       

globus_ssize_t
find_empty_buffer(
    hdfs_handle_t * hdfs_handle)
{
    globus_ssize_t result = -1;
    globus_size_t idx = 0;
    for (idx=0; idx<hdfs_handle->buffer_count; idx++) {
        if (!hdfs_handle->used[idx]) {
            result = idx;
            break;
        }
    }
    if (result >= 0) {
        hdfs_handle->used[idx] = 1;
    }
    return result;
}

void
disgard_buffer(
    hdfs_handle_t * hdfs_handle,
    globus_ssize_t idx)
{
    if (idx >= 0 && idx < hdfs_handle->buffer_count) {
        hdfs_handle->used[idx] = 0;
    }
}

