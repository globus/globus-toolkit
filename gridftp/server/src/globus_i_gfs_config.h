/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_I_GFS_CONFIG_H
#define GLOBUS_I_GFS_CONFIG_H

#define globus_i_gfs_config_list    (globus_list_t *) globus_i_gfs_config_get
#define globus_i_gfs_config_string  (char *) globus_i_gfs_config_get
#define globus_i_gfs_config_bool    (globus_bool_t) globus_i_gfs_config_int

void
globus_i_gfs_config_init(
    int                                 argc,
    char **                             argv);

void *
globus_i_gfs_config_get(
    const char *                        option_name);

int
globus_i_gfs_config_int(
    const char *                        option_name);

globus_bool_t
globus_i_gfs_config_is_anonymous(
    const char *                        userid);

const char *
globus_i_gfs_config_get_module_name(
    const char *                        client_supplied_name);

globus_bool_t
globus_i_gfs_config_allow_addr(
    const char *                        remote_addr,
    globus_bool_t                       ipc);
    
#endif
