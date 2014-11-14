
/*
 * Portions of this file Copyright 2008-2011 University of Nebraska-Lincoln
 *
 * This file is licensed under the
 * terms of the Apache Public License, found at
 * http://www.apache.org/licenses/LICENSE-2.0.html.
 */


#include <hdfs.h>
#include <stdint.h>
#include <openssl/md5.h>

#include "globus_gridftp_server.h"
#include "gridftp_hdfs_error.h"


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// Note that we hide all symbols from the global scope except the module itself.
#pragma GCC visibility push(hidden)

// Data types and globals
#define default_id 00;

// Note: This really should be const, but the globus module activation code
// doesn't have this as const.
extern globus_version_t gridftp_hdfs_local_version;

#define HDFS_CKSM_TYPE_CKSUM   1
#define HDFS_CKSM_TYPE_CRC32   2
#define HDFS_CKSM_TYPE_ADLER32 4
#define HDFS_CKSM_TYPE_MD5     8

typedef struct globus_l_gfs_hdfs_handle_s
{
    char *                              pathname;
    hdfsFS                              fs;
    hdfsFile                            fd;
    globus_off_t                        file_size; // size of the file for reads
    globus_size_t                       block_size;
    globus_off_t                        op_length; // Length of the requested read/write size
    globus_off_t                        offset;
    unsigned int                        done;
    globus_result_t                     done_status; // The status of the finished transfer.
    globus_bool_t                       sent_finish; // Whether or not we have sent the client an abort.
    globus_gfs_operation_t              op;
    globus_byte_t *                     buffer;
    globus_off_t *                      offsets; // The offset of each buffer.
    globus_size_t *                     nbytes; // The number of bytes in each buffer.
    short *                             used;
    int                                 optimal_count;
    unsigned int                        max_buffer_count;
    unsigned int                        max_file_buffer_count;
    unsigned int                        buffer_count; // Number of buffers we currently maintain in memory waiting to be written to HDFS.
    unsigned int                        outstanding;
    globus_mutex_t *                    mutex;
    int                                 port;
    char *                              host;
    char *                              mount_point;
    unsigned int                        mount_point_len;
    unsigned int                        replicas;
    char *                              username;
    char *                              tmp_file_pattern;
    int                                 tmpfilefd;
    globus_bool_t                       using_file_buffer;
    char *                              syslog_host; // The host to send syslog message to.
    char *                              remote_host; // The remote host connecting to us.
    char *                              local_host;  // Our local hostname.
    char *                              syslog_msg;  // Message printed out to syslog.
    unsigned int                        io_block_size;
    unsigned long long                  io_count;
    globus_bool_t                       eof;

    // Checksumming support
    char *                              expected_cksm;
    const char *                        cksm_root;
    unsigned char                       cksm_types;
    MD5_CTX                             md5;
    char                                md5_output[MD5_DIGEST_LENGTH];
    char                                md5_output_human[MD5_DIGEST_LENGTH*2+1];
    uint32_t                            adler32;
    char                                adler32_human[2*sizeof(uint32_t)+1];
    uint32_t                            crc32;
    uint32_t                            cksum;
} globus_l_gfs_hdfs_handle_t;
typedef globus_l_gfs_hdfs_handle_t hdfs_handle_t;

#define MSG_SIZE 1024
extern char err_msg[MSG_SIZE];

// Function for sending a file to the client.
void
hdfs_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg);


// Function for receiving a file from the client.
void
hdfs_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg);

// Buffer management for writes
globus_result_t
hdfs_store_buffer(
    globus_l_gfs_hdfs_handle_t * hdfs_handle,
    globus_byte_t* buffer,
    globus_off_t offset,
    globus_size_t nbytes);

globus_result_t
hdfs_dump_buffers(
    globus_l_gfs_hdfs_handle_t *      hdfs_handle);

globus_result_t
hdfs_dump_buffer_immed(
    hdfs_handle_t *                   hdfs_handle,
    globus_byte_t *                   buffer,
    globus_size_t                     nbytes);

// Buffer management for reads
inline globus_result_t
allocate_buffers(
    hdfs_handle_t *    hdfs_handle,
    globus_size_t             num_buffers);
    
inline globus_ssize_t
find_buffer(
    hdfs_handle_t *    hdfs_handle,
    globus_byte_t *    buffer); 
            
inline globus_ssize_t
find_empty_buffer(
    hdfs_handle_t *    hdfs_handle);

inline void
disgard_buffer(
    hdfs_handle_t * hdfs_handle,
    globus_ssize_t idx);

void
remove_file_buffer(
    hdfs_handle_t * hdfs_handle);


// Metadata-related functions
void
hdfs_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg);

// Some helper functions
// All must be called with the hdfs_handle mutex held
void
set_done(
    hdfs_handle_t *    hdfs_handle,
    globus_result_t    rc);

void
set_close_done(
    hdfs_handle_t *    hdfs_handle,
    globus_result_t    rc);

globus_bool_t
is_done(
    hdfs_handle_t *    hdfs_handle);

globus_bool_t
is_close_done(
    hdfs_handle_t *    hdfs_handle);

// Checksumming support
void
hdfs_parse_checksum_types(
    hdfs_handle_t *    hdfs_handle,
    const char *       types);

void
hdfs_initialize_checksums(
    hdfs_handle_t *    hdfs_handle);

void
hdfs_update_checksums(
    hdfs_handle_t *    hdfs_handle,
    globus_byte_t *    buffer,
    globus_size_t      nbytes);

void
hdfs_finalize_checksums(
    hdfs_handle_t *    hdfs_handle);

globus_result_t
hdfs_save_checksum(
    hdfs_handle_t *    hdfs_handle);

globus_result_t
hdfs_get_checksum(
    hdfs_handle_t *    hdfs_handle,
    const char *       pathname,
    const char *       requested_cksm, 
    char **            cksm_value);

#pragma GCC visibility pop

