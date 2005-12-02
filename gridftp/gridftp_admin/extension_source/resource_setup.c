#include <ipc_deny_from.h>
#include <allow_from.h>
#include <deny_from.h>
#include <allow_anonymous.h>
#include <anonymous_user.h>
#include <anonymous_group.h>
#include <open_connections_count.h>
#include <connections_max.h>
#include <data_connection_max.h>
#include <blocksize.h>
#include <sync_writes.h>
#include <banner.h>
#include <fqdn.h>
#include <login_msg_file.h>
#include <backends_registered.h>
#include <usage_stats_id.h>
#include <file_transfer_count.h>
#include <byte_transfer_count.h>
#include "gridftp_admin.h"

globus_result_t
gridftpA_l_setup_resource(
    globus_resource_t                   resource)
{
    globus_result_t                     result;
    globus_i_gfs_config_option_cb_ent_t * cb_handle;

    globus_gfs_config_add_cb(
        &cb_handle, "ipc_deny_from",
        gridftpA_l_string_change_cb, "ipc_deny_from");
    result = globus_resource_create_property_callback(
        resource,
        &ipc_deny_from_qname,
        &ipc_deny_from_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "allow_from",
        gridftpA_l_string_change_cb, "allow_from");
    result = globus_resource_create_property_callback(
        resource,
        &allow_from_qname,
        &allow_from_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "deny_from",
        gridftpA_l_string_change_cb, "deny_from");
    result = globus_resource_create_property_callback(
        resource,
        &deny_from_qname,
        &deny_from_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "deny_from",
        gridftpA_l_string_change_cb, "deny_from");
    result = globus_resource_create_property_callback(
        resource,
        &allow_anonymous_qname,
        &allow_anonymous_info,
        gridftpA_l_int_get_cb,
        gridftpA_l_int_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "anonymous_user",
        gridftpA_l_string_change_cb, "anonymous_user");
    result = globus_resource_create_property_callback(
        resource,
        &anonymous_user_qname,
        &anonymous_user_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "anonymous_group",
        gridftpA_l_string_change_cb, "anonymous_group");
    result = globus_resource_create_property_callback(
        resource,
        &anonymous_group_qname,
        &anonymous_group_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(&cb_handle, "data_connection_max",        gridftpA_l_int_change_cb,        "data_connection_max");
    result = globus_resource_create_property_callback(
        resource,
        &data_connection_max_qname,
        &data_connection_max_info,
        gridftpA_l_int_get_cb,
        gridftpA_l_int_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(&cb_handle, "backends_registered",        gridftpA_l_int_change_cb,        "backends_registered");
    result = globus_resource_create_property_callback(
        resource,
        &backends_registered_qname,
        &backends_registered_info,
        gridftpA_l_int_get_cb,
        gridftpA_l_int_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "open_connections_count",
        gridftpA_l_int_change_cb, "open_connections_count");
    result = globus_resource_create_property_callback(
        resource,
        &open_connections_count_qname,
        &open_connections_count_info,
        gridftpA_l_int_get_cb,
        gridftpA_l_int_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "connections_max",
        gridftpA_l_int_change_cb, "connections_max");
    result = globus_resource_create_property_callback(
        resource,
        &connections_max_qname,
        &connections_max_info,
        gridftpA_l_int_get_cb,
        gridftpA_l_int_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "file_transfer_count",
        gridftpA_l_int_change_cb, "file_transfer_count");
    result = globus_resource_create_property_callback(
        resource,
        &file_transfer_count_qname,
        &file_transfer_count_info,
        gridftpA_l_int_get_cb,
        gridftpA_l_int_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "byte_transfer_count",
        gridftpA_l_string_change_cb, "byte_transfer_count");
    result = globus_resource_create_property_callback(
        resource,
        &byte_transfer_count_qname,
        &byte_transfer_count_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "blocksize",
        gridftpA_l_int_change_cb, "blocksize");
    result = globus_resource_create_property_callback(
        resource,
        &blocksize_qname,
        &blocksize_info,
        gridftpA_l_int_get_cb,
        gridftpA_l_int_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "sync_writes",
        gridftpA_l_int_change_cb, "sync_writes");
    result = globus_resource_create_property_callback(
        resource,
        &sync_writes_qname,
        &sync_writes_info,
        gridftpA_l_int_get_cb,
        gridftpA_l_int_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "banner",
        gridftpA_l_string_change_cb, "banner");
    result = globus_resource_create_property_callback(
        resource,
        &banner_qname,
        &banner_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(
        &cb_handle, "login_msg_file",
        gridftpA_l_string_change_cb, "login_msg_file");
    result = globus_resource_create_property_callback(
        resource,
        &login_msg_file_qname,
        &login_msg_file_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        cb_handle);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_resource_create_property_callback(
        resource,
        &fqdn_qname,
        &fqdn_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        "fqdn");
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_resource_create_property_callback(
        resource,
        &usage_stats_id_qname,
        &usage_stats_id_info,
        gridftpA_l_string_get_cb,
        gridftpA_l_string_set_cb,
        "usage_stats_id");
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return GLOBUS_SUCCESS;
error:
    return result;
}
