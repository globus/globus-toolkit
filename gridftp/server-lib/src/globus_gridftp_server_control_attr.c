#include "globus_i_gridftp_server_control.h"

globus_result_t
globus_gridftp_server_control_attr_init(
    globus_gridftp_server_control_attr_t *  in_attr)
{
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_init);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    attr = (globus_i_gsc_attr_t *) globus_malloc(
                sizeof(globus_i_gsc_attr_t));

    if(attr == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("attr");
        goto err;
    }

    memset(attr, '\0', sizeof(globus_i_gsc_attr_t));

    globus_hashtable_init(
        &attr->send_cb_table,
        GLOBUS_GRIDFTP_SERVER_HASHTABLE_SIZE,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    globus_hashtable_init(
        &attr->recv_cb_table,
        GLOBUS_GRIDFTP_SERVER_HASHTABLE_SIZE,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    attr->resource_cb = NULL;
    attr->version_ctl = GLOBUS_GRIDFTP_VERSION_CTL;
    attr->modes = globus_libc_strdup("ES");
    attr->types = globus_libc_strdup("AI");
    attr->base_dir = globus_libc_strdup("/");

    *in_attr = attr;

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_destroy(
    globus_gridftp_server_control_attr_t    in_attr)
{
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_destroy);

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

    globus_hashtable_destroy(&attr->send_cb_table);
    globus_hashtable_destroy(&attr->recv_cb_table);

    globus_free(attr->modes);
    globus_free(attr->types);
    globus_free(attr);

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_copy(
    globus_gridftp_server_control_attr_t *  dst,
    globus_gridftp_server_control_attr_t    src)
{
    globus_result_t                         res;
    globus_i_gsc_attr_t *                   attr;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_copy);

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

    attr = (globus_i_gsc_attr_t *) globus_malloc(
                sizeof(globus_i_gsc_attr_t));
    if(attr == NULL)
    {
        res = GlobusGridFTPServerErrorMemory("attr");
        goto err;
    }
    attr->version_ctl = src->version_ctl;
    attr->resource_cb = src->resource_cb;
    globus_hashtable_copy(
	    &attr->send_cb_table, &src->send_cb_table, NULL);
    globus_hashtable_copy(&attr->recv_cb_table, &src->recv_cb_table, NULL);
    attr->modes = globus_libc_strdup(src->modes);
    attr->types = globus_libc_strdup(src->types);

    *dst = attr;

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_add_type(
    globus_gridftp_server_control_attr_t    in_attr,
    char                                    type)
{
    char                                    ch;
    char *                                  tmp_str;
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_add_type);

    GlobusGridFTPServerDebugEnter();
    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    attr = in_attr;

    ch = toupper(type);
    tmp_str = globus_common_create_string("%s%c", attr->types, ch);
    globus_free(attr->types);
    attr->types = tmp_str;

    GlobusGridFTPServerDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_add_mode(
    globus_gridftp_server_control_attr_t    in_attr,
    char                                    mode)
{
    char                                    ch;
    char *                                  tmp_str;
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_add_mode);

    GlobusGridFTPServerDebugEnter();
    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    attr = in_attr;

    ch = toupper(mode);
    tmp_str = globus_common_create_string("%s%c", attr->modes, ch);
    globus_free(attr->modes);
    attr->modes = tmp_str;

    GlobusGridFTPServerDebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_add_recv(
    globus_gridftp_server_control_attr_t    in_attr,
    const char *                            module_name,
    globus_gridftp_server_control_transfer_cb_t recv_cb)
{
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_add_recv);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    attr = in_attr;

    if(recv_cb == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("recv_cb");
        goto err;
    }

    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    if(module_name == NULL)
    {
        attr->default_recv_cb = recv_cb;
    }
    else
    {
        globus_hashtable_insert(
            &attr->recv_cb_table,
            (void *)module_name,
            recv_cb);
    }
    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_add_send(
    globus_gridftp_server_control_attr_t    in_attr,
    const char *                            module_name,
    globus_gridftp_server_control_transfer_cb_t send_cb)
{
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_add_send);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    attr = in_attr;

    if(send_cb == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("send_cb");
        goto err;
    }

    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    if(module_name == NULL)
    {
        attr->default_send_cb = send_cb;
    }
    else
    {
        globus_hashtable_insert(
            &attr->send_cb_table,
            (void *)module_name,
            send_cb);
    }
    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_set_auth(
    globus_gridftp_server_control_attr_t    in_attr,
    globus_gridftp_server_control_auth_cb_t auth_cb)
{
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_set_auth);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    if(auth_cb == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("auth_cb");
        goto err;
    }
    attr = in_attr;

    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    attr->auth_cb = auth_cb;

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_set_resource(
    globus_gridftp_server_control_attr_t    in_attr,
    globus_gridftp_server_control_resource_cb_t resource_query_cb)
{
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_resource_query);

    GlobusGridFTPServerDebugEnter();

    if(in_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }
    if(resource_query_cb == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("resource_query_cb");
        goto err;
    }
    attr = in_attr;

    if(attr->version_ctl != GLOBUS_GRIDFTP_VERSION_CTL)
    {
        res = GlobusGridFTPServerErrorParameter("in_attr");
        goto err;
    }

    attr->resource_cb = resource_query_cb;

    GlobusGridFTPServerDebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusGridFTPServerDebugExitWithError();

    return res;
}

globus_result_t
globus_gridftp_server_control_attr_data_functions(
    globus_gridftp_server_control_attr_t            server_attr,
    globus_gridftp_server_control_active_connect_cb_t  active_cb,
    globus_gridftp_server_control_passive_connect_cb_t passive_cb,
    globus_gridftp_server_control_data_destroy_cb_t    destroy_cb)
{
    globus_i_gsc_attr_t *                   attr;
    globus_result_t                         res;
    GlobusGridFTPServerName(globus_gridftp_server_control_attr_set_passive);

    if(server_attr == NULL)
    {
        res = GlobusGridFTPServerErrorParameter("server_attr");
        goto err;
    }
    attr = (globus_i_gsc_attr_t *) server_attr;

    attr->passive_cb = passive_cb;
    attr->active_cb = active_cb;
    attr->data_destroy_cb = destroy_cb;

    return GLOBUS_SUCCESS;

  err:

    return res;
}
