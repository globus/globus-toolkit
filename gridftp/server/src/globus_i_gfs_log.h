#ifndef GLOBUS_I_GFS_LOG_H
#define GLOBUS_I_GFS_LOG_H

typedef enum
{
    GLOBUS_I_GFS_LOG_ERR = 0x01,
    GLOBUS_I_GFS_LOG_WARN = 0x02,
    GLOBUS_I_GFS_LOG_INFO = 0x04,
    GLOBUS_I_GFS_LOG_DUMP = 0x08,
    
    GLOBUS_I_GFS_LOG_ALL = 0xFF
} globus_i_gfs_log_type_t;

void
globus_i_gfs_log_open(void);

void
globus_i_gfs_log_close(void);

void
globus_i_gfs_log_message(
    globus_i_gfs_log_type_t             type,
    const char *                        format,
    ...);

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
    globus_size_t                       nbytes,
    int                                 code,
    char *                              volume,
    char *                              type,
    char *                              username);

void
globus_i_gfs_config_display_usage();

#endif
