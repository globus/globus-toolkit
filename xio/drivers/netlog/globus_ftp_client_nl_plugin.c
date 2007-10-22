#include "globus_url_copy.h"

#include "nl.h"
#include "nlsumm.h"
#include "nltransfer.h"
#include <stdio.h>
#include <string.h>

static int l_time_plugin_activate(void);
static int l_time_plugin_deactivate(void);

#define L_TIME_PLUGIN_NAME "client_netlogger_plugin"
#define NL_COOKIE   "NL: uuid="

typedef struct globus_l_nl_uuid_ent_s
{
    int                                 count;
    int                                 return_count;
    char *                              uuid;
    char *                              msgs[2];
} globus_l_nl_uuid_ent_t;

typedef struct l_time_plugin_s
{
    int x;
} l_time_plugin_t;

static globus_mutex_t                   globus_l_nl_mutex;
static globus_hashtable_t               globus_l_nl_uuid_table;

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

static
void
nl_print_bottleneck(
    NL_transfer_btl_t *                 bottleneck)
{
    printf("Bottleneck is ");
    switch (bottleneck->result) {
    case NL_BTL_KNOWN:
        printf("known: ");
        switch (bottleneck->location) {
        case NL_BTL_DISK_READ:
            printf("disk read\n");
            break;
        case NL_BTL_DISK_WRITE:
            printf("disk write\n");
            break;
        case NL_BTL_DISK:
            printf("either disk read or write\n");
            break;
        case NL_BTL_NET:
            printf("the friggin' network!\n");
            break;
        default:
            printf("unkown bottleneck code (?)\n");
        }
        break;
    default:
        printf("not known\n");
    }
}

static
void
guc_l_nl_replace_str(
    char *                              nl_str, 
    const char *                        n)
{
    char *                              tmp_ptr;
    char *                              tmp_ptr2;
    char *                              end_ptr;
    int                                 sz;
    int                                 len;
    int                                 off = 0;

    end_ptr = nl_str + strlen(nl_str);
    sz = strlen(n) - 1;
    tmp_ptr = strstr(nl_str, n);
    while(tmp_ptr != NULL)
    {
        *tmp_ptr = '\n';
        tmp_ptr++;

        tmp_ptr2 = tmp_ptr + sz;

        len = end_ptr - tmp_ptr2;
        memmove(tmp_ptr, tmp_ptr2, len); 
        tmp_ptr = strstr(nl_str, n);
        off += sz;
    }
    end_ptr -= off;
    *end_ptr = '\0';
}


static
void
nl_l_final_received(
    const char *                        response_buffer)
{
    int                                 rc;
    char *                              tmp_ptr;
    char *                              nl_str;
    char *                              uuid;
    NL_transfer_btl_t                   bottleneck;
    globus_l_nl_uuid_ent_t *            ent;

    tmp_ptr = strstr(response_buffer, NL_COOKIE);
    if(tmp_ptr == NULL)
    {
        goto error_response;
    }
    tmp_ptr += sizeof(NL_COOKIE);
    uuid = strdup(tmp_ptr);
    tmp_ptr = strchr(uuid, ';');
    if(tmp_ptr == NULL)
    {
        goto error_uuid;
    }
    *tmp_ptr = '\0';
    tmp_ptr++;

    nl_str = strdup(tmp_ptr);
    /* remove trailing 226 final line if it exists */
    tmp_ptr = strstr(nl_str, "226 ");
    if(tmp_ptr != NULL)
    {
        *tmp_ptr = '\0';
    }

    /* have to remove all of the \r\n226 messages*/
    guc_l_nl_replace_str(nl_str, "\r\n226-");

    ent = (globus_l_nl_uuid_ent_t *)
        globus_hashtable_lookup(&globus_l_nl_uuid_table, uuid);
    if(ent == NULL)
    {
        goto error_ent;
    }

    ent->msgs[ent->return_count] = nl_str;
    ent->return_count++;
    if(2 == ent->return_count)
    {
        rc = NL_transfer_get_bottleneck(ent->msgs[0], ent->msgs[1],
            &bottleneck);
        if(rc != 0)
        {
        }
        nl_print_bottleneck(&bottleneck);   

        globus_hashtable_remove(&globus_l_nl_uuid_table, uuid);
        /* clean up the entry */
        free(ent->msgs[0]);
        free(ent->msgs[1]);
        free(ent->uuid);
        free(ent);
    }

    return;

error_ent:
    free(nl_str);
error_uuid:
    free(uuid);
error_response:

    return;
}


static
void
l_time_response(
    globus_ftp_client_plugin_t *		plugin,
    void *					            plugin_specific,
    globus_ftp_client_handle_t *		handle,
    const char *				        url,
    globus_object_t *				    error,
    const globus_ftp_control_response_t *	ftp_response)
{
    l_time_plugin_t *                   d;

    d = (l_time_plugin_t *) plugin_specific;

    globus_mutex_lock(&globus_l_nl_mutex);
    {
        if(!error)
        {
            switch(ftp_response->code)
            {
                case 226:
                    nl_l_final_received(
                        (const char *)ftp_response->response_buffer);
                    break;

                default:
                    break;
            }
        }
    }
    globus_mutex_unlock(&globus_l_nl_mutex);

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
    void *                              plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                        url,
    const char *                        command_name)
{
    char *                              tmp_ptr;
    char *                              uuid;
    globus_l_nl_uuid_ent_t *            ent;

    tmp_ptr = strstr(command_name, "SETNETSTACK");
    if(tmp_ptr == NULL)
    {
        return;
    }
    tmp_ptr = strstr(command_name, "netlogger");
    if(tmp_ptr == NULL)
    {
        return;
    }
    tmp_ptr = strstr(command_name, "uuid=");
    if(tmp_ptr == NULL)
    {
        return;
    }

    tmp_ptr += sizeof("uuid=");
    uuid = strdup(tmp_ptr);

    tmp_ptr = strchr(uuid, ';');
    if(tmp_ptr != NULL)
    {
        *tmp_ptr = '\0';
    }

    
    globus_mutex_lock(&globus_l_nl_mutex);
    {
        ent = (globus_l_nl_uuid_ent_t *)
            globus_hashtable_lookup(&globus_l_nl_uuid_table, uuid);

        if(ent == NULL)
        {
            ent = (globus_l_nl_uuid_ent_t *) globus_calloc(
                1, sizeof(globus_l_nl_uuid_ent_t));
            ent->uuid = uuid;
            ent->count = 1;

            globus_hashtable_insert(&globus_l_nl_uuid_table, ent->uuid, ent);
        }
        else
        {
            ent->count++;
        }

        if(ent->count > 2)
        {
            /* log a message */
            ent->count = 2;
        }
    }
    globus_mutex_unlock(&globus_l_nl_mutex);
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
void
l_time_chmod(
    globus_ftp_client_plugin_t *        plugin,
    void *                  plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                url,
    int                                         mode,
    const globus_ftp_client_operationattr_t *   attr,
    globus_bool_t               restart)
{
}

static
void
l_time_feat(
    globus_ftp_client_plugin_t *        plugin,
    void *                  plugin_specific,
    globus_ftp_client_handle_t *        handle,
    const char *                url,
    const globus_ftp_client_operationattr_t *   attr,
    globus_bool_t               restart)
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
    globus_ftp_client_plugin_set_chmod_func(plugin, l_time_chmod);
    globus_ftp_client_plugin_set_feat_func(plugin, l_time_feat);


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

    globus_mutex_init(&globus_l_nl_mutex, NULL);
    globus_hashtable_init(
        &globus_l_nl_uuid_table,
        128,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    return rc;
}

static
int
l_time_plugin_deactivate(void)
{
    return 0;
}

