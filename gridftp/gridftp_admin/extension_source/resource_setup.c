#include <globus_wsrf_resource.h>
#include <contact_string.h>
#include <banner.h>
#include <connections_max.h>
#include <open_connections_count.h>
#include <backends_registered.h>
#include <data_connection_max.h>
#include <max_bw.h>
#include <current_bw.h>
#include <file_transfer_count.h>
#include <byte_transfer_count.h>
#include "gridftp_admin.h"
#include "backendInfo.h"


globus_result_t
gridftpA_l_setup_resource(
    globus_resource_t                   resource)
{
    globus_result_t                     result;
    globus_i_gfs_config_option_cb_ent_t * cb_handle;

    globus_gfs_config_add_cb(&cb_handle, "contact_string",
        gridftpA_l_fe_change_cb,
        "contact_string");
    globus_gfs_config_add_cb(&cb_handle, "banner",
        gridftpA_l_fe_change_cb,
        "banner");
    globus_gfs_config_add_cb(&cb_handle, "connections_max",
        gridftpA_l_fe_change_cb,
        "connections_max");
    globus_gfs_config_add_cb(&cb_handle, "open_connections_count",
        gridftpA_l_fe_change_cb,
        "open_connections_count");
    globus_gfs_config_add_cb(&cb_handle, "backends_registered",
        gridftpA_l_fe_change_cb,
        "backends_registered");
    globus_gfs_config_add_cb(&cb_handle, "data_connection_max",
        gridftpA_l_fe_change_cb,
        "data_connection_max");
    globus_gfs_config_add_cb(&cb_handle, "max_bw",
        gridftpA_l_fe_change_cb,
        "max_bw");
    globus_gfs_config_add_cb(&cb_handle, "current_bw",
        gridftpA_l_fe_change_cb,
        "current_bw");
    globus_gfs_config_add_cb(&cb_handle, "file_transfer_count",
        gridftpA_l_fe_change_cb,
        "file_transfer_count");
    globus_gfs_config_add_cb(&cb_handle, "byte_transfer_count",
        gridftpA_l_fe_change_cb,
        "byte_transfer_count");

    result = globus_resource_create_property_callback(
        resource,
        &FrontendStats_qname,
        &FrontendStats_info,
        gridftpA_l_fe_get_cb,
        gridftpA_l_fe_set_cb,
        "FrontendStatsType");
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(&cb_handle, "backend_pool",
        gridftpA_l_backend_change_cb,
        "backend_pool");
    result = globus_resource_create_property_callback(
        resource,
        &BackendPool_qname,
        &BackendPool_info,
        gridftpA_l_backend_get_cb,
        gridftpA_l_backend_set_cb,
        "backend_pool");
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }


    return GLOBUS_SUCCESS;
error:
    return result;
}

