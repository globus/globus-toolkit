#ifndef GLOBUS_I_GFS_CONFIG_H
#define GLOBUS_I_GFS_CONFIG_H

void
globus_i_gfs_config_init(
    int                                 argc,
    char **                             argv);

globus_bool_t
globus_i_gfs_config_bool(
    const char *                        option_name);

int
globus_i_gfs_config_int(
    const char *                        option_name);

char *
globus_i_gfs_config_string(
    const char *                        option_name);

globus_list_t *
globus_i_gfs_config_list(
    const char *                        option_name);

#endif
