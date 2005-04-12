
/*
 * This file or a portion of this file is licensed under the terms of the
 * Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without modifications,
 * you must include this notice in the file.
 */

#ifndef GLOBUS_I_GFS_LOG_H
#define GLOBUS_I_GFS_LOG_H

void
globus_i_gfs_log_open(void);

void
globus_i_gfs_log_close(void);

#define globus_i_gfs_log_message globus_gfs_log_message
#define globus_i_gfs_log_type_t globus_gfs_log_type_t
#define GLOBUS_I_GFS_LOG_ERR GLOBUS_GFS_LOG_ERR
#define GLOBUS_I_GFS_LOG_WARN GLOBUS_GFS_LOG_WARN
#define GLOBUS_I_GFS_LOG_INFO GLOBUS_GFS_LOG_INFO
#define GLOBUS_I_GFS_LOG_STATUS GLOBUS_GFS_LOG_STATUS
#define GLOBUS_I_GFS_LOG_DUMP GLOBUS_GFS_LOG_DUMP   
#define GLOBUS_I_GFS_LOG_ALL GLOBUS_GFS_LOG_ALL

void
globus_i_gfs_log_result(
    const char *                        lead,
    globus_result_t                     result);

void
globus_i_gfs_log_result_warn(
    const char *                        lead,
    globus_result_t                     result);

void
globus_i_gfs_log_transfer(
    int                                 stripe_count,
    int                                 stream_count, 
    struct timeval *                    start_gtd_time,
    struct timeval *                    end_gtd_time,
    char *                              dest_ip,
    globus_size_t                       blksize,
    globus_size_t                       tcp_bs,
    const char *                        fname,
    globus_off_t                        nbytes,
    int                                 code,
    char *                              volume,
    char *                              type,
    char *                              username);

void
globus_i_gfs_log_usage_stats(
    int                                 stripe_count,
    int                                 stream_count, 
    struct timeval *                    start_gtd_time,
    struct timeval *                    end_gtd_time,
    char *                              dest_ip,
    globus_size_t                       blksize,
    globus_size_t                       tcp_bs,
    const char *                        fname,
    globus_off_t                        nbytes,
    int                                 code,
    char *                              volume,
    char *                              type,
    char *                              username);
    
void
globus_i_gfs_config_display_usage();

#endif
