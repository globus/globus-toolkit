#include "globus_wsrf_resource.h"
#include "gridftp_admin.h"
#include "globus_gridftp_server.h"
#include "GridFTPAdminService_skeleton.h"
#include "wssg_MembershipContentRuleType.h"
#include "wssg_MembershipContentRule.h"
#include "wssg_EntryType_array.h"
#include "wssg_EntryType.h"

#include "gridftp_admin.h"

extern globus_module_descriptor_t       GridFTPAdminService_module;

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


void
gridftpA_l_string_get_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void **                             property)
{
    char *                              opt;
    char *                              val;

    opt = (char *) arg;

    val = strdup(globus_gfs_config_get_string(qname->local));
    xsd_string_init_cstr((xsd_string **) property, val);
}

void
gridftpA_l_int_get_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void **                             property)
{
    char *                              opt;
    int                                 val;
    xsd_int *                           i_ptr;

    opt = (char *) qname->local;

    val = globus_gfs_config_get_int(opt);
    xsd_int_init(&i_ptr);
    *i_ptr = val;
    *property = i_ptr;
}

globus_bool_t
gridftpA_l_int_set_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void *                              property)
{
    int                                 val;
    xsd_int *                           i_ptr;
    char *                              opt;
    globus_i_gfs_config_option_cb_ent_t * cb_ent;

    cb_ent = (globus_i_gfs_config_option_cb_ent_t *) arg;
    opt = (char *) qname->local;

    val = globus_gfs_config_get_int(qname->local);
    i_ptr = (xsd_int *) property;
    if(val == *i_ptr)
    {
        return GLOBUS_TRUE;
    }
    globus_gfs_config_enable_cb(cb_ent, GLOBUS_FALSE);
    globus_gfs_config_set_int(opt, *i_ptr);
    globus_gfs_config_enable_cb(cb_ent, GLOBUS_TRUE);

    return GLOBUS_TRUE;
}

globus_bool_t
gridftpA_l_string_set_cb(
    void *                              arg,
    const xsd_QName *                   qname,
    void *                              property)
{
    char *                              val;
    xsd_string *                        i_ptr;
    char *                              opt;
    globus_i_gfs_config_option_cb_ent_t * cb_ent;

    cb_ent = (globus_i_gfs_config_option_cb_ent_t *) arg;

    opt = (char *) qname->local;

    val = globus_gfs_config_get_string(opt);
    i_ptr = (xsd_string *) property;
    if(strcmp(*i_ptr, val) == 0)
    {
        return GLOBUS_TRUE;
    }
    globus_gfs_config_enable_cb(cb_ent, GLOBUS_FALSE);
    globus_gfs_config_set_ptr(opt, strdup(*i_ptr));
    globus_gfs_config_enable_cb(cb_ent, GLOBUS_TRUE);

    return GLOBUS_TRUE;
}

void
gridftpA_l_int_change_cb(
    const char *                        opt_name,
    int                                 val,
    void *                              user_arg)
{
    xsd_int *                           i_ptr;
    globus_result_t                     result;
    globus_resource_t                   resource;
    xsd_QName                           qname =
        {
            GRIDFTP_ADMIN_SERVICE_NAMESPACE,
            NULL
        };

    qname.local = (char *)opt_name;
    result = globus_resource_find(RESOURCE_NAME, &resource);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    xsd_int_init(&i_ptr);
    *i_ptr = val;
    result = globus_resource_set_property(resource, &qname, (void *)i_ptr);
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
gridftpA_l_string_change_cb(
    const char *                        opt_name,
    const char *                        val,
    void *                              user_arg)
{
    xsd_string *                        i_ptr;
    globus_result_t                     result;
    globus_resource_t                   resource;
    xsd_QName                           qname =
        {
            GRIDFTP_ADMIN_SERVICE_NAMESPACE,
            NULL
        };

    qname.local = (char *)opt_name;
    result = globus_resource_find(RESOURCE_NAME, &resource);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    xsd_string_init_cstr(&i_ptr, strdup(val));
    result = globus_resource_set_property(resource, &qname, (void *)i_ptr);
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
    globus_service_engine_t             engine)
{
    wsa_EndpointReferenceType           epr;
    globus_result_t                     result;
    xsd_any *                           reference_properties;
    char *                              name = RESOURCE_NAME;
    globus_resource_t                   resource = NULL;
    char *                              epr_filename = NULL;
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
        GRIDFTP_ADMIN_SERVICE_NAMESPACE);
    reference_properties->element->local = globus_libc_strdup(name);

    result = xsd_string_init_cstr(
        (xsd_string **) &reference_properties->value, name);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_qname_destroy;
    }

    result = globus_wsrf_core_create_endpoint_reference(
        engine,
        GRIDFTPADMINSERVICE_BASE_PATH,
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
    GridFTPAdminServiceInitResource(&epr);
    epr_filename = globus_gfs_config_get_string("epr_outfile");
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
    int                                 rc;
    char *                              prepend_name;
    globus_service_engine_t             engine;
    globus_result_t                     result;
    char *                              pc;
    char *                              real_pc;
    GlobusGFSName(gridftp_admin_l_init);

    result = globus_module_activate(GLOBUS_SERVICE_ENGINE_MODULE);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    engine = (globus_service_engine_t)
        globus_gfs_config_get("service_engine");
    if(engine == NULL)
    {
        pc = globus_gfs_config_get_string("service_port");
        result = globus_service_engine_init(
            &engine,
            NULL,
            pc,
            NULL,
            GLOBUS_FALSE);
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
                "service_port", (void *)strdup(real_pc));
            /* print out real */
            globus_gfs_log_message(
                GLOBUS_GFS_LOG_STATUS, "WSRF Admin: %s\n", real_pc);
        }

        globus_gfs_config_set_ptr("service_engine", engine);

       result = globus_service_engine_register_start(
            engine,
            gridftp_admin_l_engine_stop_callback,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_pc_free;
        }
    }

    prepend_name = globus_common_create_string(
        "globus_service_modules/%s", GRIDFTPADMINSERVICE_BASE_PATH);

    rc = globus_extension_register_builtin(
        prepend_name, &GridFTPAdminService_module);
    globus_assert(rc == 0);

    result = globus_extension_activate(prepend_name);
    globus_free(prepend_name);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_pc_free;
    }
    result = gridftp_admin_l_create_resource(engine);
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

    printf("loaded gridftp admin extension\n");
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

