#include "globus_url_copy.h"

#include <stdio.h>
#include <string.h>

static int l_time_plugin_activate(void);
static int l_time_plugin_deactivate(void);

#define L_TIME_PLUGIN_NAME "client_netlogger_plugin"

typedef struct l_time_plugin_s
{
    int x;
} l_time_plugin_t;

globus_result_t
l_time_plugin_init(
    globus_ftp_client_plugin_t *        plugin,
    char *                              in_args);

static
globus_result_t
l_time_setup_plugin(
    globus_ftp_client_plugin_t *		plugin,
    l_time_plugin_t *                   d);


static globus_guc_client_plugin_funcs_t  l_my_guc_plugin =
{
    l_time_plugin_init
};

static l_time_plugin_t                  l_pg;
static globus_ftp_client_plugin_t *     l_dummy;

static
void
l_time_response(
    globus_ftp_client_plugin_t *		plugin,
    void *					plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				url,
    globus_object_t *				error,
    const globus_ftp_control_response_t *	ftp_response)
{
    l_time_plugin_t *                   d;
    d = (l_time_plugin_t *) plugin_specific;

    if(!error)
    {
        switch(ftp_response->code)
        {
            case 226:
printf("##########-> %s\n", ftp_response->response_buffer);
                break;

            default:
                break;
        }
    }
}


globus_result_t
l_time_plugin_init(
    globus_ftp_client_plugin_t *		plugin,
    char *                              in_args)
{
    char *                              fname = NULL;
    char *                              text = NULL;
    l_time_plugin_t *                   d;
    GlobusFuncName(l_time_plugin_init);

    d = globus_libc_malloc(sizeof(l_time_plugin_t));

    if(fname == NULL)
    {
        fname = "-";
    }
    if(text == NULL)
    {
        text = "";
    }

    return l_time_setup_plugin(plugin, d);
}

static
globus_ftp_client_plugin_t *
l_time_copy(
    globus_ftp_client_plugin_t *        plugin_template,
    void *                              plugin_specific)
{
    globus_ftp_client_plugin_t *        newguy;
    l_time_plugin_t *                   s;
    l_time_plugin_t *                   d;
    globus_result_t                     result;

    s = (l_time_plugin_t *) plugin_specific;

    newguy = globus_libc_malloc(sizeof(globus_ftp_client_plugin_t));
    if(newguy == GLOBUS_NULL)
    {
        goto error_exit;
    }
    d = globus_calloc(sizeof(l_time_plugin_t), 1);

    result = l_time_setup_plugin(newguy, d);
    if(result != GLOBUS_SUCCESS)
    {
        goto free_exit;
    }
    return newguy;

free_exit:
    globus_libc_free(newguy);
error_exit:
    return NULL;
}

static
void
l_time_destroy(
    globus_ftp_client_plugin_t *        plugin,
    void *                              plugin_specific)
{
    l_time_plugin_t *                   s;

    s = (l_time_plugin_t *) plugin_specific;

    globus_free(s);
    globus_ftp_client_plugin_destroy(plugin);
}

static
void
l_time_command(
    globus_ftp_client_plugin_t *        plugin,
    void *                  plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                url,
    const char *                command_name)
{
}

static
void
l_time_connect(
    globus_ftp_client_plugin_t *        plugin,
    void *                              plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                        url)
{
}

static
void
l_time_authenticate(
    globus_ftp_client_plugin_t *        plugin,
    void *                              plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                        url,
    const globus_ftp_control_auth_info_t *  auth_info)
{
}

static
void
l_time_get(
    globus_ftp_client_plugin_t *        plugin,
    void *                  plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                url,
    const globus_ftp_client_operationattr_t *   attr,
    globus_bool_t               restart)
{
}

static
void
l_time_put(
    globus_ftp_client_plugin_t *        plugin,
    void *                  plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                url,
    const globus_ftp_client_operationattr_t *   attr,
    globus_bool_t               restart)
{
}

static
void
l_time_third_party_transfer(
    globus_ftp_client_plugin_t *        plugin,
    void *                  plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                source_url,
    const globus_ftp_client_operationattr_t *   source_attr,
    const char *                dest_url,
    const globus_ftp_client_operationattr_t *   dest_attr,
    globus_bool_t               restart)
{   
}

static
void
l_time_fault(
    globus_ftp_client_plugin_t *        plugin,
    void *                  plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                url,
    globus_object_t *               error)
{
}

static
void
l_time_complete(
    globus_ftp_client_plugin_t *        plugin,
    void *                  plugin_specific,
    globus_ftp_client_handle_t *        handle)
{
}

static
globus_result_t
l_time_setup_plugin(
    globus_ftp_client_plugin_t *		plugin,
    l_time_plugin_t *                   d)
{
    globus_ftp_client_plugin_init(plugin,
		L_TIME_PLUGIN_NAME,
		GLOBUS_FTP_CLIENT_CMD_MASK_ALL,
        d);

    globus_ftp_client_plugin_set_copy_func(plugin, l_time_copy);
    globus_ftp_client_plugin_set_destroy_func(plugin, l_time_destroy);
    globus_ftp_client_plugin_set_response_func(plugin, l_time_response);
    globus_ftp_client_plugin_set_command_func(plugin, l_time_command);

    globus_ftp_client_plugin_set_connect_func(plugin, l_time_connect);
    globus_ftp_client_plugin_set_get_func(plugin, l_time_get);
    globus_ftp_client_plugin_set_put_func(plugin, l_time_put);
    globus_ftp_client_plugin_set_third_party_transfer_func(
        plugin, l_time_third_party_transfer);
    globus_ftp_client_plugin_set_authenticate_func(plugin, l_time_authenticate);
    globus_ftp_client_plugin_set_fault_func(plugin, l_time_fault);
    globus_ftp_client_plugin_set_complete_func(plugin, l_time_complete);



    return GLOBUS_SUCCESS;
}

GlobusExtensionDefineModule(guc_time) =
{
    "guc_time",
    l_time_plugin_activate,
    l_time_plugin_deactivate,
    NULL,
    NULL,
    NULL
};

static
int
l_time_plugin_activate(void)
{
    int                                 rc;

    rc = globus_extension_registry_add(
        &globus_guc_client_plugin_registry,
        L_TIME_PLUGIN_NAME "_funcs",
        GlobusExtensionMyModule(guc_time),
        &l_my_guc_plugin);

    return rc;
}

static
int
l_time_plugin_deactivate(void)
{
    return 0;
}

