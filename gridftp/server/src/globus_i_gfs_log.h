#ifndef GLOBUS_I_GFS_LOG_H
#define GLOBUS_I_GFS_LOG_H

typedef enum
{
    GLOBUS_I_GFS_LOG_ERR,
    GLOBUS_I_GFS_LOG_INFO
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
    
#endif
