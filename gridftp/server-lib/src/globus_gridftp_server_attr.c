#include "globus_i_gridftp_server.h"
#include "globus_gridftp_server_pmod_959.h"

globus_result_t
globus_gridftp_server_attr_init(
    globus_gridftp_server_attr_t *          in_attr)
{
    globus_i_gs_attr_t *                    attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_attr_init);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    attr = (globus_i_gs_attr_t *) globus_malloc(
                sizeof(globus_i_gs_attr_t));

    if(attr == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("attr");
        goto err;
    }

    memset(attr, '\0', sizeof(globus_i_gs_attr_t));

    globus_hashtable_init(
        &attr->send_func_table,
        GLOBUS_GRIDFTP_SERVER_HASHTABLE_SIZE,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    globus_hashtable_init(
        &attr->recv_func_table,
        GLOBUS_GRIDFTP_SERVER_HASHTABLE_SIZE,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    globus_hashtable_init(
        &attr->command_func_table,
        GLOBUS_GRIDFTP_SERVER_HASHTABLE_SIZE,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    attr->resource_func = NULL;
    attr->version_ctl = GLOBUS_GRIDFTP_VERSION_CTL;
    attr->pmod = &globus_i_gsp_959_proto_mod;
    attr->start_state = GLOBUS_L_GS_STATE_AUTH;

    globus_i_gs_cmd_add_builtins(attr);

    *in_attr = attr;

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_attr_destroy(
    globus_gridftp_server_attr_t            in_attr)
{
    globus_i_gs_attr_t *                    attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_attr_destroy);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    attr = in_attr;

    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    globus_hashtable_destroy(&attr->send_func_table);
    globus_hashtable_destroy(&attr->recv_func_table);
    globus_hashtable_destroy(&attr->command_func_table);

    globus_free(attr);

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_attr_copy(
    globus_gridftp_server_attr_t *          dst,
    globus_gridftp_server_attr_t            src)
{
    globus_result_t                         res;
    globus_i_gs_attr_t *                    attr;
    GlobusGridFTPServerName(globus_gridftp_server_attr_copy);

    if(dst == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("dst");
        goto err;
    }
    if(src == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("src");
        goto err;
    }
    if(src->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    attr = (globus_i_gs_attr_t *) globus_malloc(
                sizeof(globus_i_gs_attr_t));
    if(attr == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("attr");
        goto err;
    }
    attr->version_ctl = src->version_ctl;
    attr->resource_func = src->resource_func;
    globus_hashtable_copy(
	&src->send_func_table, &src->send_func_table, NULL);
    globus_hashtable_copy(&src->recv_func_table, &src->recv_func_table, NULL);
    globus_hashtable_copy(
        &src->command_func_table, &src->command_func_table, NULL);

    *dst = attr;

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_attr_add_recv(
    globus_gridftp_server_attr_t            in_attr,
    const char *                            module_name,
    globus_gridftp_server_data_func_t       recv_func)
{
    globus_i_gs_attr_t *                    attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_attr_add_recv);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    attr = in_attr;

    if(recv_func == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("recv_func");
        goto err;
    }

    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    globus_hashtable_insert(
        &attr->recv_func_table,
        (void *)module_name,
        recv_func);

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_attr_add_send(
    globus_gridftp_server_attr_t            in_attr,
    const char *                            module_name,
    globus_gridftp_server_data_func_t       send_func)
{
    globus_i_gs_attr_t *                    attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_attr_add_send);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    attr = in_attr;

    if(send_func == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("send_func");
        goto err;
    }

    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    globus_hashtable_insert(
        &attr->send_func_table,
        (void *)module_name,
        send_func);

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_attr_set_resource(
    globus_gridftp_server_attr_t            in_attr,
    globus_gridftp_server_resource_func_t   resource_query_func)
{
    globus_i_gs_attr_t *                    attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_attr_resource_query);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    if(resource_query_func == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("resource_query_func");
        goto err;
    }
    attr = in_attr;

    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    attr->resource_func = resource_query_func;

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_attr_command_add(
    globus_gridftp_server_attr_t            server_attr,
    const char *                            command_name,
    globus_gridftp_server_cmd_func_t        func,
    void *                                  user_arg,
    globus_gridftp_server_command_desc_t    cmd_desc)
{
    globus_i_gs_attr_t *                    attr;
    globus_result_t                         res;
    globus_i_gs_cmd_ent_t *                 cmd_ent;
    globus_list_t *                         list;
    GlobusGridFTPServerName(globus_gridftp_server_attr_command_add);

    if(server_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server_attr");
        goto err;
    }
    if(command_name == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("command_name");
        goto err;
    }

    attr = (globus_i_gs_attr_t *) server_attr;
    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("server_attr");
        goto err;
    }

    cmd_ent = (globus_i_gs_cmd_ent_t *) globus_malloc(
        sizeof(globus_i_gs_cmd_ent_t));
    if(cmd_ent == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("cmd_ent");
        goto err;
    }
    cmd_ent->name = globus_libc_strdup(command_name);
    cmd_ent->desc = cmd_desc;
    cmd_ent->user_arg = user_arg;
    cmd_ent->func = func;

    list = (globus_list_t *)globus_hashtable_lookup(
                &server_attr->command_func_table, (char *)command_name);
    globus_list_insert(&list, cmd_ent);
    globus_hashtable_insert(
        &server_attr->command_func_table, (char *) command_name, list);
                                                                                
    return GLOBUS_SUCCESS;

  err:

    return res;
}

globus_result_t
globus_gridftp_server_attr_set_done(
    globus_gridftp_server_attr_t            server_attr,
    globus_gridftp_server_callback_t        done_cb)
{
    globus_i_gs_attr_t *                    attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_attr_set_done);

    if(server_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server_attr");
        goto err;
    }
    attr = (globus_i_gs_attr_t *) server_attr;

    attr->done_func = done_cb;

    return GLOBUS_SUCCESS;

  err:

    return res;
}
