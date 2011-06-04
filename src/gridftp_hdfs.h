
/*
 * Portions of this file Copyright 2008-2011 University of Nebraska-Lincoln
 *
 * This file is licensed under the
 * terms of the Apache Public License, found at
 * http://www.apache.org/licenses/LICENSE-2.0.html.
 */

#include "globus_gridftp_server.h"
#include "gridftp_hdfs_error.h"

#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <hdfs.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

// Note that we hide all symbols from the global scope except the module itself.
#pragma GCC visibility push(hidden)

// Data types and globals
#define default_id 00;

extern const globus_version_t gridftp_hdfs_local_version;

typedef struct globus_l_gfs_hdfs_handle_s
{
    char *                              pathname;
    hdfsFS                              fs;
    hdfsFile                            fd;
    globus_size_t                       block_size;
    globus_off_t                        block_length;
    globus_off_t                        offset;
    globus_bool_t                       done;
    globus_result_t                     done_status; // The status of the finished transfer.
    globus_gfs_operation_t              op;
    globus_byte_t *                     buffer;
    globus_off_t *                      offsets; // The offset of each buffer.
    globus_size_t *                     nbytes; // The number of bytes in each buffer.
    short *                             used;
    int                                 optimal_count;
    int                                 max_buffer_count;
    int                                 max_file_buffer_count;
    int                                 buffer_count; // Number of buffers we currently maintain in memory waiting to be written to HDFS.
    int                                 outstanding;
    globus_mutex_t                      mutex;
    int                                 port;
    char *                              host;
    char *                              mount_point;
    int                                 mount_point_len;
    int                                 replicas;
    char *                              username;
    char *                              tmp_file_pattern;
    int                                 tmpfilefd;
    int                                 using_file_buffer;
    char *                              syslog_host; // The host to send syslog message to.
    char *                              remote_host; // The remote host connecting to us.
    char *                              local_host;  // Our local hostname.
    char                                syslog_msg[256];  // Message printed out to syslog.
    unsigned int                        io_block_size;
    unsigned long long                  io_count;
} globus_l_gfs_hdfs_handle_t;
typedef globus_l_gfs_hdfs_handle_t hdfs_handle_t;

#define MSG_SIZE 1024
extern char err_msg[MSG_SIZE];

// Boilerplate functions for Globus modules
int
globus_l_gfs_hdfs_activate(void);

int
globus_l_gfs_hdfs_deactivate(void);

void
globus_l_gfs_hdfs_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         cmd_info,
    void *                              user_arg);

void
globus_l_gfs_hdfs_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info);

void
globus_l_gfs_hdfs_destroy(
    void *                              user_arg);

void
globus_l_gfs_hdfs_trev(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg);

// Function for sending a file to the client.
void
globus_l_gfs_hdfs_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg);

void
globus_l_gfs_hdfs_read_from_storage( 
    globus_l_gfs_hdfs_handle_t *      hdfs_handle);

void
globus_l_gfs_hdfs_read_from_storage_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg);


// Function for receiving a file from the client.
void
hdfs_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg);

int use_file_buffer(
    globus_l_gfs_hdfs_handle_t * hdfs_handle);

void    
hdfs_write_to_storage(
    globus_l_gfs_hdfs_handle_t *      hdfs_handle);

void    
hdfs_write_to_storage_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg);

globus_result_t
hdfs_store_buffer(
    globus_l_gfs_hdfs_handle_t * hdfs_handle,
    globus_byte_t* buffer,
    globus_off_t offset,
    globus_size_t nbytes);

globus_result_t
hdfs_dump_buffers(
    globus_l_gfs_hdfs_handle_t *      hdfs_handle);

void
remove_file_buffer(
    globus_l_gfs_hdfs_handle_t * hdfs_handle);

// Metadata-related functions
void
globus_l_gfs_hdfs_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg);

void            
globus_l_gfs_file_partition_path(
    const char *                        pathname,
    char *                              basepath,
    char *                              filename);

void
globus_l_gfs_file_destroy_stat(
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count);

void        
globus_l_gfs_file_copy_stat(
    globus_gfs_stat_t *                 stat_object,
    hdfsFileInfo *                      fileInfo,
    const char *                        filename,
    const char *                        symlink_target);

// Some helper functions
void
set_done(
    hdfs_handle_t *    hdfs_handle,
    globus_result_t    rc);

globus_bool_t
is_done(
    hdfs_handle_t *    hdfs_handle);

#pragma GCC visibility pop

