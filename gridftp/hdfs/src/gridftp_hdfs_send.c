
#include "gridftp_hdfs.h"
#include <syslog.h>

// Forward declarations of local functions

typedef struct hdfs_read_s {
    hdfs_handle_t *hdfs_handle;
    globus_size_t idx;
} hdfs_read_t;

static void
hdfs_finish_read_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg);

static void
hdfs_perform_read_cb(
    void *  hdfs_read_handle);

static void
hdfs_dispatch_read(
    globus_l_gfs_hdfs_handle_t *      hdfs_handle);

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}

/*************************************************************************
 *  close_and_clean
 *  --------------
 *  Close the HDFS file and clean up the write-related resources in the
 *  handle.
 *************************************************************************/
static globus_result_t
close_and_clean(hdfs_handle_t *hdfs_handle, globus_result_t rc) {

    GlobusGFSName(close_and_clean);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "Trying to close file in HDFS; zero outstanding blocks.\n");
    if (is_close_done(hdfs_handle)) {
        return hdfs_handle->done_status;
    }

    // Only close the file for successful transfers and if the handle is valid.
    // This might cause long-term leaks, but Java has been crash-y when closing
    // invalid handles.
    if ((rc == GLOBUS_SUCCESS) &&
            (hdfs_handle->fd != NULL) && (hdfs_handle->fs != NULL) &&
            (hdfsCloseFile(hdfs_handle->fs, hdfs_handle->fd) == -1)) {
        GenericError(hdfs_handle, "Failed to close file in HDFS.", rc);
        hdfs_handle->fd = NULL;
    }

    if (hdfs_handle->buffer)
        globus_free(hdfs_handle->buffer);
    if (hdfs_handle->used)
        globus_free(hdfs_handle->used);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "receive %d blocks of size %d bytes\n",
        hdfs_handle->io_count, hdfs_handle->io_block_size);

    set_close_done(hdfs_handle, rc);
    return rc;
}

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
hdfs_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_hdfs_handle_t *       hdfs_handle;
    GlobusGFSName(globus_l_gfs_hdfs_send);
    globus_result_t                     rc = GLOBUS_SUCCESS;


    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;
    globus_mutex_lock(hdfs_handle->mutex);
    hdfs_handle->pathname = transfer_info->pathname;

    ADVANCE_SLASHES(hdfs_handle->pathname)
    if (strncmp(hdfs_handle->pathname, hdfs_handle->mount_point, hdfs_handle->mount_point_len)==0) {
        hdfs_handle->pathname += hdfs_handle->mount_point_len;
    }
    ADVANCE_SLASHES(hdfs_handle->pathname)

    hdfs_handle->op = op;
    hdfs_handle->outstanding = 0;
    hdfs_handle->done = 0;
    hdfs_handle->done_status = GLOBUS_SUCCESS;
    hdfs_handle->buffer_count = 0;
    hdfs_handle->buffer = NULL;
    hdfs_handle->offsets = NULL;
    hdfs_handle->nbytes = NULL;
    hdfs_handle->used = NULL;

    globus_gridftp_server_get_block_size(op, &hdfs_handle->block_size);

    globus_gridftp_server_get_read_range(hdfs_handle->op,
                                         &hdfs_handle->offset,
                                         &hdfs_handle->op_length);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
        "Operation starting at %d, length %d\n", hdfs_handle->offset,
        hdfs_handle->op_length);

    globus_gridftp_server_begin_transfer(hdfs_handle->op, 0, hdfs_handle);

    if (hdfsExists(hdfs_handle->fs, hdfs_handle->pathname) == 0) {
        hdfsFileInfo *fileInfo;
        int hasStat = 1;

        if((fileInfo = hdfsGetPathInfo(hdfs_handle->fs, hdfs_handle->pathname)) == NULL)
            hasStat = 0;

        if (hasStat && fileInfo->mKind == kObjectKindDirectory) {
            GenericError(hdfs_handle, "The file you are trying to read is a directory", rc)
            goto cleanup;
        }
        hdfs_handle->file_size = fileInfo->mSize;
    } else {
        errno = ENOENT;
        SystemError(hdfs_handle, "opening file for read", rc);
        goto cleanup;
    }


    hdfs_handle->fd = hdfsOpenFile(hdfs_handle->fs, hdfs_handle->pathname, O_RDONLY, 0, 1, 0);
    if (!hdfs_handle->fd) {
        if (errno == EINTERNAL) {
            SystemError(hdfs_handle,
                "opening file due to an internal HDFS error; "
                "could be a misconfiguration or bad installation at the site.",
                rc);
        } else if (errno == EACCES) {
            SystemError(hdfs_handle, "opening file; permission error in HDFS.", rc);
        } else {
            SystemError(hdfs_handle, "opening file; failed to open file due to unknown error in HDFS.", rc);
        }
        goto cleanup;
    }

    if (hdfsSeek(hdfs_handle->fs, hdfs_handle->fd, hdfs_handle->offset) == -1) {
        GenericError(hdfs_handle, "seek() fail", rc);
    }

    hdfs_dispatch_read(hdfs_handle);

cleanup:

    if (rc != GLOBUS_SUCCESS) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to initialize read setup");
        set_done(hdfs_handle, rc);
        globus_gridftp_server_finished_transfer(op, rc);
    }

    globus_mutex_unlock(hdfs_handle->mutex);

}

// Allow injection of garbage errors, allowing us to test error-handling
//#define FAKE_ERROR
#ifdef FAKE_ERROR
int block_count = 0;
#endif

static void
hdfs_finish_read_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    GlobusGFSName(hdfs_handle_read_cb);
    globus_l_gfs_hdfs_handle_t *      hdfs_handle;
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_ssize_t idx = -1;

    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;
    globus_mutex_lock(hdfs_handle->mutex);

#ifdef FAKE_ERROR 
    block_count ++;
    if (block_count == 30) {
        GenericError(hdfs_handle, "Got bored, threw an error.", rc);
        goto cleanup;
    }   
#endif

    // Various short-circuit routines
    if (is_done(hdfs_handle) && (hdfs_handle->done_status != GLOBUS_SUCCESS)) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Error prior to callback.\n");
        rc = hdfs_handle->done_status;
        goto cleanup;
    }
    if (result != GLOBUS_SUCCESS) {
        rc = result;
        goto cleanup;
    }
    if (nbytes == 0) {
        rc = result;
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Read of size zero.\n");
        goto cleanup;
    }

    // Determine the idx of the buffer.
    idx = find_buffer(hdfs_handle, buffer);
    if (idx < 0) {
        GenericError(hdfs_handle, "Unknown read operation", rc)
        goto cleanup;
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Finishing read op from buffer %d.\n", idx);

    // Do statistics
    if (hdfs_handle->syslog_host != NULL) {
            syslog(LOG_INFO, hdfs_handle->syslog_msg, "READ", nbytes, hdfs_handle->io_count);
    }
    if (nbytes != hdfs_handle->io_block_size) {
        if (0 != hdfs_handle->io_block_size) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "send %d blocks of size %d bytes\n",
                                      hdfs_handle->io_count, hdfs_handle->io_block_size);
        }
        hdfs_handle->io_block_size = nbytes;
        hdfs_handle->io_count=1;
    } else {
        hdfs_handle->io_count++;
    }

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        set_done(hdfs_handle, rc);
    }

    disgard_buffer(hdfs_handle, idx);

    hdfs_handle->outstanding--;
    if (!is_done(hdfs_handle)) {
        hdfs_dispatch_read(hdfs_handle);
    } else if (hdfs_handle->outstanding == 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Transfer has finished!\n");
        rc = close_and_clean(hdfs_handle, rc);
        globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
        
    } else if (rc != GLOBUS_SUCCESS) {
        // Don't close the file because the other transfers will want to finish up.
        // However, do set the failure status.
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
            "We failed to finish the transfer, but there are %i outstanding reads left over.\n",
            hdfs_handle->outstanding);
        globus_gridftp_server_finished_transfer(op, rc);
    } else {
        // Nothing to do if we are done and there was no error, but outstanding transfers exist.
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
            "Transfer finished successfully; %i outstanding reads left over.\n", hdfs_handle->outstanding);
        // Note we do NOT call globus_gridftp_server_finished_transfer yet!
    }
    globus_mutex_unlock(hdfs_handle->mutex);

}

static void
hdfs_perform_read_cb(
    void *                              user_arg)
{
    GlobusGFSName(hdfs_perform_read_cb);
    hdfs_read_t *read_op = (hdfs_read_t*) user_arg;
    hdfs_handle_t *hdfs_handle = read_op->hdfs_handle;
    globus_size_t idx = read_op->idx;
    //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Starting read for buffer %u.\n", idx);
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_size_t read_length, remaining_read;
    globus_off_t offset, cur_offset;
    globus_ssize_t nbytes;

    offset = hdfs_handle->offsets[idx];
    read_length = hdfs_handle->nbytes[idx];
    globus_byte_t *buffer_pos = hdfs_handle->buffer + idx*hdfs_handle->block_size;
    globus_byte_t *cur_buffer_pos = buffer_pos;

    // Check to see if we can short-circuit
    globus_bool_t short_circuit = GLOBUS_FALSE;
    globus_mutex_lock(hdfs_handle->mutex);
    if (is_done(hdfs_handle) && (hdfs_handle->done_status != GLOBUS_SUCCESS)) {
        short_circuit = GLOBUS_TRUE;
    }
    globus_mutex_unlock(hdfs_handle->mutex);
    if (short_circuit) {
        goto cleanup;
    }

    if (hdfs_handle->syslog_host != NULL) {
        syslog(LOG_INFO, hdfs_handle->syslog_msg, "READ", read_length, hdfs_handle->io_count);
    }
    //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
    //    "hdfs_perform_read_cb for %u@%lu.\n", read_length, offset);

    remaining_read = read_length;
    cur_offset = offset;
    while (remaining_read != 0) {
       nbytes = hdfsPread(hdfs_handle->fs, hdfs_handle->fd, cur_offset, cur_buffer_pos, remaining_read);
       if (nbytes == 0) {    /* eof */
           // No error
           globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "hdfs_perform_read_cb EOF.\n");
           globus_mutex_lock(hdfs_handle->mutex);
           set_done(hdfs_handle, GLOBUS_SUCCESS);
           globus_mutex_unlock(hdfs_handle->mutex);
           break;
       } else if (nbytes == -1) {
           SystemError(hdfs_handle, "reading from HDFS", rc)
           goto cleanup;
       }
       //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Read size %d of %d requested\n", nbytes, remaining_read);
       remaining_read -= nbytes;
       cur_buffer_pos += nbytes;
       cur_offset += nbytes;
    }

    //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Read length: %d; remaining: %d\n", read_length, remaining_read);
    if (read_length != remaining_read) {
        // If we read anything at all, write it out to the client.
        // When the write to the network is finished, hdfs_finish_read_cb will be called.
        rc = globus_gridftp_server_register_write(hdfs_handle->op,
            buffer_pos,
            read_length - remaining_read,
            offset,
            -1, // Stripe index
            hdfs_finish_read_cb,
            hdfs_handle);
        if (rc != GLOBUS_SUCCESS) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to create callback\n");
            goto cleanup;
        }
    } else {
        //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Zero-length read; call finish_read_cb directly.\n");
        hdfs_finish_read_cb(hdfs_handle->op, rc, NULL, 0, (void*)hdfs_handle);
    }

cleanup:

    free(read_op);

    if (short_circuit || (rc != GLOBUS_SUCCESS)) {
        globus_mutex_lock(hdfs_handle->mutex);
        set_done(hdfs_handle, rc);
        globus_mutex_unlock(hdfs_handle->mutex);
        //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Short-circuit read.\n");
        // Call finish_read_op directly.
        hdfs_finish_read_cb(hdfs_handle->op, rc, buffer_pos,
            read_length, (void*)hdfs_handle);
    }
}

// Must be called with hdfs_handle->mutex LOCKED!
static void
hdfs_dispatch_read(
    globus_l_gfs_hdfs_handle_t *      hdfs_handle)
{
    globus_size_t read_length, idx;
    globus_result_t rc = GLOBUS_SUCCESS;
    hdfs_read_t *hdfs_read_handle;

    GlobusGFSName(hdfs_dispatch_read);

    globus_gridftp_server_get_optimal_concurrency(hdfs_handle->op,
                                                  &hdfs_handle->optimal_count);

    // Verify we have sufficient buffer space.
    if ((rc = allocate_buffers(hdfs_handle, hdfs_handle->optimal_count)) != GLOBUS_SUCCESS) {
        goto cleanup;
    }

    while ((hdfs_handle->outstanding < hdfs_handle->optimal_count) && !is_done(hdfs_handle)) {
        // Determine the size of this read operation.
        read_length = hdfs_handle->block_size;
        if ((hdfs_handle->op_length != -1)
                && (hdfs_handle->op_length < (globus_ssize_t)hdfs_handle->block_size)) {
            read_length = hdfs_handle->op_length;
        }
        if ((hdfs_handle->offset + read_length) > hdfs_handle->file_size)
        {
            read_length = hdfs_handle->file_size - hdfs_handle->offset;
        }

        // Short-circuit the case where we are done
        if (read_length == 0) {
            set_done(hdfs_handle, GLOBUS_SUCCESS);
            break;
        }

        // Determine a buffer for this read to use.
        if ((idx = find_empty_buffer(hdfs_handle)) < 0) {
            GenericError(hdfs_handle, "Ran out of buffer space", rc)
            break;
        }

        // Record the offset and buffer length
        hdfs_handle->nbytes[idx] = read_length;
        hdfs_handle->offsets[idx] = hdfs_handle->offset;

        if ((hdfs_read_handle = globus_malloc(sizeof(hdfs_read_t))) == NULL) {
            MemoryError(hdfs_handle, "Unable to allocate read handle", rc)
            break;
        }
        hdfs_read_handle->idx = idx;
        hdfs_read_handle->hdfs_handle = hdfs_handle;

        rc = globus_callback_register_oneshot(
            NULL,
            NULL,
            hdfs_perform_read_cb,
            hdfs_read_handle);

        if (rc != GLOBUS_SUCCESS) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to create callback\n");
            break;
        }
        hdfs_handle->outstanding++;
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Issued read from buffer %u (outstanding=%u).\n", idx, hdfs_handle->outstanding);

        hdfs_handle->offset += read_length;
        if (hdfs_handle->op_length != -1) { 
            hdfs_handle->op_length -= read_length;
        }
    }

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        set_done(hdfs_handle, rc);
        globus_gridftp_server_finished_transfer(hdfs_handle->op, rc);
    }

}

