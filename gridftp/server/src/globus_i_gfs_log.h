/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
