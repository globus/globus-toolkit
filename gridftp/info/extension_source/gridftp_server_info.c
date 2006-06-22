#include "gridftp_server_info.h"

#define GFTP_INFO_ARG_DEL  '#'

extern globus_module_descriptor_t       GridFTPServerInfoService_module;

void
gridftpA_l_init();

static
int
gridftp_admin_l_activate();

static
globus_result_t
gridftp_admin_l_write_epr(
    wsa_EndpointReferenceType *         epr,
    const char *                        epr_filename);

globus_result_t
gridftpA_l_setup_resource(
    globus_resource_t                   resource);


globus_result_t
gridftpA_l_setup_resource(
    globus_resource_t                   resource)
{
    globus_result_t                     result;
    globus_i_gfs_config_option_cb_ent_t * cb_handle;

    globus_gfs_config_add_cb(&cb_handle, "contact_string",
        gridftpA_l_fe_change_cb,
        "contactString");
    globus_gfs_config_add_cb(&cb_handle, "banner",
        gridftpA_l_fe_change_cb,
        "banner");
    globus_gfs_config_add_cb(&cb_handle, "connections_max",
        gridftpA_l_fe_change_cb,
        "maxConnections");
    globus_gfs_config_add_cb(&cb_handle, "open_connections_count",
        gridftpA_l_fe_change_cb,
        "openConnections");
    globus_gfs_config_add_cb(&cb_handle, "backends_registered",
        gridftpA_l_fe_change_cb,
        "backendsAvailable");
    globus_gfs_config_add_cb(&cb_handle, "max_bw",
        gridftpA_l_fe_change_cb,
        "maxBW");
    globus_gfs_config_add_cb(&cb_handle, "current_bw",
        gridftpA_l_fe_change_cb,
        "filesTransfered");
    globus_gfs_config_add_cb(&cb_handle, "file_transfer_count",
        gridftpA_l_fe_change_cb,
        "filesTransfered");
    globus_gfs_config_add_cb(&cb_handle, "byte_transfer_count",
        gridftpA_l_fe_change_cb,
        "megaBytesTransfered");

    result = globus_resource_create_property_callback(
        resource,
        &frontendInfo_qname,
        &frontendInfoType_info,
        gridftpA_l_fe_get_cb,
        gridftpA_l_fe_set_cb,
        "frontendInfoType");
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_gfs_config_add_cb(&cb_handle, "backend_pool",
        gridftpA_l_backend_change_cb,
        "backendPool");
    result = globus_resource_create_property_callback(
        resource,
        &backendPool_qname,
        &backendPoolType_info,
        gridftpA_l_backend_get_cb,
        gridftpA_l_backend_set_cb,
        "backendPool");
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }


    return GLOBUS_SUCCESS;
error:
    return result;
}

static
int
gridftp_admin_l_deactivate();

GlobusExtensionDefineModule(gridftp_admin) =
{
    "gridftp_admin",
    gridftp_admin_l_activate,
    gridftp_admin_l_deactivate,
    NULL,
    NULL,
    NULL
};

static
backendPoolType *
gridftpA_l_make_backend_array()
{
    backendPoolType *                   bP;
    backendInfoType_array *             backend_array = NULL;
    globus_list_t *                     list;
    backendInfoType *                   wsrf_b_info;
    globus_i_gfs_brain_node_t *         backend_info;
    int                                 i = 0;
    globus_abstime_t                    tm_now;

    backendPoolType_init(&bP);
    backend_array = &bP->backendInfo;

    list = (globus_list_t *)globus_gfs_config_get("backend_pool");

    while(!globus_list_empty(list))
    {
        backend_info = (globus_i_gfs_brain_node_t *) globus_list_first(list);

        wsrf_b_info = backendInfoType_array_push(backend_array);

        xsd_string_copy_contents_cstr(
            &wsrf_b_info->indentifier, strdup(backend_info->host_id));
        wsrf_b_info->openConnections = (xsd_int)
            backend_info->current_connection;
        list = globus_list_rest(list);

        globus_gfs_log_message(
            GLOBUS_GFS_LOG_ERR, "HOST: %s\n", wsrf_b_info->indentifier);

        i++;
    }

    GlobusTimeAbstimeGetCurrent(tm_now);
    globus_libc_gmtime_r(&tm_now.tv_sec, &bP->changedAt);

    return bP;
}

static
frontendInfoType *
gridftpA_l_make_fe_struct()
{
    frontendInfoType *                  fe;
    char *                              tmp_s;
    int                                 tmp_i;
    int64_t                             tmp_l;

    frontendInfoType_init(&fe);

    tmp_s = globus_gfs_config_get_string("contact_string");
    xsd_string_init_contents_cstr(&fe->contactString, strdup(tmp_s));
    tmp_s = globus_gfs_config_get_string("banner");
    xsd_string_init_contents_cstr(&fe->banner, strdup(tmp_s));

    tmp_i = globus_gfs_config_get_int("connections_max");
    fe->maxConnections = (xsd_int) tmp_i;
    tmp_i = globus_gfs_config_get_int("open_connections_count");
    fe->openConnections = (xsd_int) tmp_i;

    tmp_i = globus_gfs_config_get_int("backends_registered");
    xsd_int_copy(&fe->backendsAvailable, &tmp_i);
    tmp_l = (int64_t)globus_gfs_config_get_int("file_transfer_count");
    xsd_long_copy(&fe->filesTransfered, &tmp_l);

    return fe;
}


void
gridftpA_l_backend_change_cb(
    const char *                        opt_name,
    const char *                        val,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_resource_t                   resource;

    result = globus_resource_find(RESOURCE_NAME, &resource);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_resource_property_changed(
        resource, &backendPool_qname);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_set;
    }

    globus_resource_finish(resource);

    return;
error_set:
    globus_resource_finish(resource);
error:
    return;
}

void
gridftpA_l_fe_change_cb(
    const char *                        opt_name,
    const char *                        val,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_resource_t                   resource;

    result = globus_resource_find(RESOURCE_NAME, &resource);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_resource_property_changed(
        resource, &frontendInfo_qname);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_set;
    }

    globus_resource_finish(resource);

    return;
error_set:
    globus_resource_finish(resource);
error:
    return;
}

void
gridftpA_l_fe_get_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void **                             property)
{
    frontendInfoType *                  fe;

    fe = gridftpA_l_make_fe_struct();

    *property = fe;
}

/* maynot externally set this */
globus_bool_t
gridftpA_l_fe_set_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void *                              property)
{
    return GLOBUS_FALSE;
}


void
gridftpA_l_backend_get_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void **                             property)
{
    backendPoolType *                   bP;

    bP = gridftpA_l_make_backend_array();

    *property = bP;
}

/* maynot externally set this */
globus_bool_t
gridftpA_l_backend_set_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void *                              property)
{
    return GLOBUS_FALSE;
}

static
void
gridftp_admin_l_engine_stop_callback(
    globus_result_t                     result,
    globus_service_engine_t             engine,
    void *                              args)
{
}

static
globus_result_t
gridftp_admin_l_create_resource(
    globus_service_engine_t             engine,
    char *                              epr_filename)
{
    wsa_EndpointReferenceType           epr;
    globus_result_t                     result;
    xsd_any *                           reference_properties;
    char *                              name = RESOURCE_NAME;
    globus_resource_t                   resource = NULL;
    GlobusGFSName(gridftp_admin_l_create_resource);

    result = globus_resource_create(
        name,
        &resource);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = xsd_any_init(&reference_properties);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_resource_destroy;
    }
    reference_properties->any_info = &xsd_string_info;
    result = xsd_QName_init(&reference_properties->element);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_refprop_destroy;
    }
    reference_properties->element->Namespace = globus_libc_strdup(
        GRIDFTP_INFO_SERVICE_NAMESPACE);
    reference_properties->element->local = globus_libc_strdup(name);

    result = xsd_string_init_cstr(
        (xsd_string **) &reference_properties->value, name);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_qname_destroy;
    }

    result = globus_wsrf_core_create_endpoint_reference(
        engine,
        GRIDFTPSERVERINFOSERVICE_BASE_PATH,
        &reference_properties,
        &epr);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_qname_destroy;
    }

    result = gridftpA_l_setup_resource(resource);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_qname_destroy;
    }

    globus_resource_finish(resource);
    GridFTPServerInfoServiceInitResource(&epr);
    if(epr_filename == NULL)
    {
        epr_filename = "/tmp/gridftp_admin_epr";
    }
    gridftp_admin_l_write_epr(&epr, epr_filename);

    return GLOBUS_SUCCESS;

error_qname_destroy:
    xsd_QName_destroy(reference_properties->element);
error_refprop_destroy:
    xsd_any_destroy(reference_properties);
error_resource_destroy:
    globus_resource_destroy(resource);
error:
    return result;

}

static
globus_result_t
gridftp_admin_l_write_epr(
    wsa_EndpointReferenceType *         epr,
    const char *                        epr_filename)
{
    globus_result_t                     result;
    globus_soap_message_handle_t        soap_handle;
    xsd_QName                           element_name;

    element_name.Namespace = ELEMENT_NAME;
    element_name.local = ELEMENT_NAME;

    result = globus_soap_message_handle_init_to_file(
        &soap_handle,
        epr_filename,
        GLOBUS_XIO_FILE_CREAT | GLOBUS_XIO_FILE_TRUNC);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = wsa_EndpointReferenceType_serialize(
        &element_name,
        epr,
        soap_handle,
        0);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_handle;
    }

    globus_soap_message_handle_destroy(soap_handle);

    return GLOBUS_SUCCESS;

error_handle:
    globus_soap_message_handle_destroy(soap_handle);
error:
    printf("error writting\n");
    return result;
}

static
globus_result_t
gridftp_admin_l_init()
{
    int                                 key_len;
    char *                              key;
    char *                              next_arg;
    char *                              tmp_s;
    char *                              current_arg;
    char *                              args = NULL;
    int                                 rc;
    char *                              prepend_name;
    globus_service_engine_t             engine;
    globus_result_t                     result;
    char *                              epr_filename = NULL;
    char *                              pc = NULL;
    char *                              real_pc;
    globus_bool_t                       secure = GLOBUS_TRUE;
    GlobusGFSName(gridftp_admin_l_init);

    result = globus_module_activate(GLOBUS_SERVICE_ENGINE_MODULE);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    tmp_s = globus_gfs_config_get_string("extension_args");
    if(tmp_s != NULL)
    {
        args = strdup(tmp_s);

        current_arg = args;
        while(current_arg != NULL && *current_arg != '\0')
        {
            tmp_s = strchr(current_arg, GFTP_INFO_ARG_DEL);
            if(tmp_s != NULL)
            {
                *tmp_s = '\0';
                next_arg = tmp_s + 1;
            }
            else
            {
                next_arg = NULL;
            }
            /* check for parametes we car about */
            key = "contact=";
            key_len = strlen(key);
            if(strncmp(key, current_arg, key_len) == 0)
            {
                pc = current_arg + key_len;
            }

            key = "epr_file=";
            key_len = strlen(key);
            if(strncmp(key, current_arg, key_len) == 0)
            {
                epr_filename = current_arg + key_len;
            }

            key = "secure=";
            key_len = strlen(key);
            if(strncmp(key, current_arg, key_len) == 0)
            {
                tmp_s = current_arg + key_len;
                if(*tmp_s == 'N')
                {
                    secure = GLOBUS_FALSE;
                }
            }

            current_arg = next_arg;
        }

    }

    result = globus_service_engine_init(
        &engine,
        NULL,
        pc,
        NULL,
        secure);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_deactivate;
    }
    result = globus_service_engine_get_contact(engine, &real_pc);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_engine_destroy;
    }
    if(pc == NULL)
    {
        globus_gfs_config_set_ptr(
            "extension_args", (void *)strdup(real_pc));
    }
    /* print out real */
    globus_gfs_log_message(
        GLOBUS_GFS_LOG_STATUS, "GridFTP Server Info WSRF: %s\n", real_pc);

    result = globus_service_engine_register_start(
        engine,
        gridftp_admin_l_engine_stop_callback,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_pc_free;
    }

    /* we have now used all the args and can free them */
    if(args != NULL)
    {
        free(args);
    }
    prepend_name = globus_common_create_string(
        "globus_service_modules/%s", GRIDFTPSERVERINFOSERVICE_BASE_PATH);
/*
    rc = globus_extension_register_builtin(
        prepend_name, &GridFTPServerInfoService_module);
    globus_assert(rc == 0);
*/
    result = globus_extension_activate(prepend_name);
    globus_free(prepend_name);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_pc_free;
    }
    result = gridftp_admin_l_create_resource(engine, epr_filename);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_pc_free;
    }

    return GLOBUS_SUCCESS;

error_pc_free:
    free(real_pc);
error_engine_destroy:
    globus_service_engine_destroy(engine);
error_deactivate:
    globus_module_deactivate(GLOBUS_SERVICE_ENGINE_MODULE);
error:
    if(args != NULL)
    {
        free(args);
    }
    globus_gfs_log_message(
        GLOBUS_GFS_LOG_WARN, "Error starting WSRF service");

    return result;
}

static
int
gridftp_admin_l_activate()
{
    GlobusGFSName(gridftp_admin_l_activate);
/*
    rc = globus_extension_registry_add(
        &brain_i_registry,
        BRAIN_SYMBOL_NAME,
        GlobusExtensionMyModule(gridftp_registry),
        &gridftp_registry_l_brain_funcs);
    if(rc != 0 )
    {
        goto error;
    }
*/

    gridftp_admin_l_init();
    return 0;
}

static
int
gridftp_admin_l_deactivate()
{
/*
    globus_extension_registry_remove(
        &brain_i_registry, BRAIN_SYMBOL_NAME);
*/
    return 0;
}

