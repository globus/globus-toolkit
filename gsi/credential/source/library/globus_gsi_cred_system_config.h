
#ifndef GLOBUS_I_GSI_SYSTEM_CONFIG_H
#define GLOBUS_I_GSI_SYSTEM_CONFIG_H

#include "globus_common.h"

globus_result_t
globus_i_gsi_get_home_dir(
    char **                             home_dir);

globus_result_t
globus_i_gsi_check_keyfile(
    const char *                        filename);

globus_result_t
globus_i_gsi_check_certfile(
    const char *                        filename);

globus_result_t
globus_gsi_cred_get_cert_dir(
    char **                             cert_dir_name);

globus_result_t
globus_gsi_cred_get_user_cert_filename(
    char **                             user_cert_filename,
    char **                             user_key_filename);

globus_result_t
globus_gsi_cred_get_host_cert_filename(
    char **                             host_cert_filename,
    char **                             host_key_filename);

globus_result_t
globus_gsi_cred_get_service_cert_filename(
    char *                              service_name,
    char **                             service_cert_filename,
    char **                             service_key_filename);

globus_result_t
globus_gsi_cred_get_proxy_filename(
    char **                             proxy_filename,
    int                                 proxy_in);

#endif
