
#ifndef GLOBUS_I_GSI_SYSTEM_CONFIG_H
#define GLOBUS_I_GSI_SYSTEM_CONFIG_H

#include "globus_common.h"

globus_result_t
globus_i_gsi_get_home_dir(
    char **                             home_dir_p);

int
globus_i_gsi_checkstat(
    const char *                        filename);

globus_result_t
globus_gsi_cred_get_cert_dir(
    char **                             cert_dir_p);

globus_result_t
globus_gsi_cred_get_user_cert_filename(
    char **                             user_cert_p,
    char **                             user_key_p);

globus_result_t
globus_gsi_cred_get_host_cert_filename(
    char **                             host_cert_p,
    char **                             host_key_p);

globus_result_t
globus_gsi_cred_get_proxy_filename(
    char **                             proxy_p,
    int                                 proxy_in);

#endif
