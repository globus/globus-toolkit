#ifndef GLOBUS_I_GFS_LOG_H
#define GLOBUS_I_GFS_LOG_H

typedef enum
{
    GLOBUS_I_GFS_LOG_ERR = 0x1,
    GLOBUS_I_GFS_LOG_INFO = 0x2,
    GLOBUS_I_GFS_LOG_CONTROL = 0x4
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
globus_i_gfs_config_display_usage();

#endif
