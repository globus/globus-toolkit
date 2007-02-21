/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_gridftp_server.h"
#include "globus_i_gfs_ipc.h"

#define GFS_BRAIN_FIXED_SIZE    256
#define GFS_DB_REPO_SIZE        16
#define GFS_DB_REPO_NAME        "default"
#define STATIC_TIMEOUT          10

#define COOKIE_LEN              16

typedef enum gfs_l_db_node_type_e
{
    GFS_DB_NODE_TYPE_STATIC = 1,
    GFS_DB_NODE_TYPE_DYNAMIC
} gfs_l_db_node_type_t;

typedef struct gfs_l_db_node_s
{
    /* over load globus_i_gfs_brain_node_t */
    char *                              host_id;
    char *                              repo_name;
    void *                              brain_arg;
    int                                 max_connection;
    int                                 current_connection;
    int                                 total_max_connections;
    int                                 total_connections;
    float                               load;
    /* end over load */
    gfs_l_db_node_type_t                type;
    globus_bool_t                       error;
    char *                              cookie_id;
    struct gfs_l_db_repo_s *            repo;
} gfs_l_db_node_t;

typedef struct gfs_l_db_repo_s
{
    char *                              name;
    globus_hashtable_t                  node_table;
    globus_priority_q_t                 node_q;
} gfs_l_db_repo_t;

static globus_mutex_t                   globus_l_brain_mutex;
static globus_xio_server_t              globus_l_brain_server_handle;
static globus_hashtable_t               gfs_l_db_repo_table;
static gfs_l_db_repo_t *                gfs_l_db_default_repo = NULL;

static
void
globus_l_gfs_backend_changed();

static
int
gfs_l_db_node_cmp(
    void *                              priority_1,
    void *                              priority_2)
{
    gfs_l_db_node_t *                   n1;
    gfs_l_db_node_t *                   n2;

    n1 = (gfs_l_db_node_t *) priority_1;
    n2 = (gfs_l_db_node_t *) priority_2;

    /* if the node is saturated always put it at the back of the queue */
    if(n1->current_connection >= n1->max_connection && n1->max_connection != 0)
    {
        return 1;
    }
    /* if the total number of connections is capped and we have exceded
        the cap send it to the back */
    if(n1->total_max_connections > 0 
        && n1->total_connections >= n1->total_max_connections)
    {
        return 1;
    }
    if(n2->current_connection >= n2->max_connection && n2->max_connection != 0)
    {
        return -1;
    }
    if(n1->current_connection < n2->current_connection)
    {
        return -1;
    }
    else if(n1->current_connection == n2->current_connection)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

static
globus_list_t *
gfs_l_db_parse_string_list(
    const char *                        str_list)
{
    char *                              last_str;
    char *                              tmp_str;
    globus_list_t *                     list = NULL;
    char *                              p;

    if(str_list == NULL || *str_list == '\0')
    {
        return NULL;
    }
    
    tmp_str = globus_libc_strdup(str_list);
    last_str = tmp_str;
    while((p = strchr(last_str, ',')) != NULL)
    {
        *p = '\0';
        globus_list_insert(&list, strdup(last_str));
        last_str = p + 1;
    }
    globus_list_insert(&list, strdup(last_str));
    
    globus_free(tmp_str);

    return list;
}


static
void
globus_l_brain_log_socket(
    globus_xio_handle_t                 handle,
    char *                              msg)
{
    globus_result_t                     res;
    char *                              peer_contact;

    res = globus_xio_handle_cntl(
        handle,
        globus_i_gfs_tcp_driver,
        GLOBUS_XIO_TCP_GET_REMOTE_NUMERIC_CONTACT,
        &peer_contact);
    if(res != GLOBUS_SUCCESS)
    {
        peer_contact = strdup("could get peer addr");
    }
    
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_WARN,
        "[%s]  %s", peer_contact, msg);
    globus_free(peer_contact);
}

static
void
globus_l_brain_read_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    int                                 con_diff;
    gfs_l_db_node_t *                   node = NULL;
    gfs_l_db_repo_t *                   repo = NULL;
    int                                 i;
    int                                 con_max;
    int                                 total_max;
    char *                              start_str;
    char *                              repo_name = NULL;
    char *                              cs = NULL;
    char                                cookie[COOKIE_LEN];
    char *                              cookie_id;
    GlobusGFSName(globus_l_brain_read_cb);

    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_WARN,
        "[%s] enter", "globus_l_brain_read_cb");
    globus_mutex_lock(&globus_l_brain_mutex);
    {
        if(result != GLOBUS_SUCCESS)
        {
            globus_l_brain_log_socket(handle, "read_cb");
            globus_i_gfs_log_result_warn(
                "read_cb: A connection request to brain failed",
                result);
            goto error;
        }

        /* verify message */
        con_max = (int) buffer[0];
        total_max = (int) buffer[1];
        if(total_max == 0)
        {
            total_max = -1;
        }
        memcpy(cookie, &buffer[2], COOKIE_LEN);
        start_str = &buffer[2+COOKIE_LEN];
        for(i = 2+COOKIE_LEN; i < len && cs == NULL; i++)
        {
            if(buffer[i] == '\0')
            {
                if(repo_name == NULL)
                {
                    repo_name = start_str;
                    start_str = &buffer[i+1];
                }
                else if(cs == NULL)
                {
                    cs = strdup(start_str);
                }
            }
            else if(!isalnum(buffer[i]) && buffer[i] != '.'
                && buffer[i] != ':')
            {
                /* log an error */
                globus_l_brain_log_socket(handle, "bad_ip");
                globus_i_gfs_log_message(
                    GLOBUS_I_GFS_LOG_WARN,
                    "bad ip registered %s",
                    start_str);
                goto error;
            }
        }
        if(cs != NULL && *cs == '\0')
        {
            globus_free(cs);
            goto error_cs;
        }

        cookie_id = globus_common_create_string("%s::%s", cookie, cs);

        if(*repo_name == '\0')
        {
            repo_name = GFS_DB_REPO_NAME;
        }

        repo = (gfs_l_db_repo_t *) globus_hashtable_lookup(
            &gfs_l_db_repo_table, repo_name);
        if(repo == NULL)
        {
            /* create a new repo */
            repo = (gfs_l_db_repo_t *) calloc(1, sizeof(gfs_l_db_repo_t));
            globus_priority_q_init(&repo->node_q, gfs_l_db_node_cmp);
            globus_hashtable_init(
                &repo->node_table, 
                32,
                globus_hashtable_string_hash,
                globus_hashtable_string_keyeq);

            repo->name = strdup(repo_name);
            globus_hashtable_insert(&gfs_l_db_repo_table, repo->name, repo);
        }
        else
        {
            node = (gfs_l_db_node_t *)
                globus_hashtable_lookup(&repo->node_table, cookie_id);
        }

        if(node == NULL)
        { 
            node = (gfs_l_db_node_t*)globus_calloc(1, sizeof(gfs_l_db_node_t));
            node->host_id = strdup(cs);
            node->cookie_id = cookie_id;
            node->repo_name = strdup(repo_name);
            node->repo = repo;
            globus_priority_q_enqueue(&repo->node_q, node, node);
            globus_hashtable_insert(&repo->node_table, node->cookie_id, node);
            /* the next line is here so that if it was static it will
                remain static */
            node->type = GFS_DB_NODE_TYPE_DYNAMIC;
            con_diff = con_max;
            node->current_connection = 0;
            node->max_connection = con_max;
            node->total_max_connections = total_max;
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_WARN,
                "A new backend registered, contact string: [%s] %s\n"
                "  max=[%d]\n  total=[%d]\n id=[%s]\n",
                node->repo_name,
                node->host_id,
                node->max_connection,
                node->total_max_connections,
                node->cookie_id);
            globus_gfs_config_inc_int("backends_registered", 1);
        }
        else
        {
            /* XXX ? do i need to dequeue and requeue ? */
            node->total_max_connections = total_max;
            con_diff = con_max - node->max_connection;
            node->max_connection = con_max;
            free(cookie_id);
        }
        /* it already set to unlimited dont change it */
        if(globus_gfs_config_get_int("data_connection_max") >= 0)
        {
            /* if the new one is unlimited set the cout to reflect that */
            if(con_max == 0)
            {
                globus_gfs_config_set_int("data_connection_max", -1);
            }
            else
            {
                globus_gfs_config_inc_int("data_connection_max", con_diff);
            }
            globus_i_gfs_log_message(
                GLOBUS_I_GFS_LOG_WARN,
                "Backend [%s] %s has refreshed its contact information.\n",
                node->repo_name,
                node->host_id);
        }
error_cs:
error:
        globus_xio_register_close(
            handle,
            NULL,
            NULL,
            NULL);
	    globus_free(buffer);

        globus_l_gfs_backend_changed();
    }
    globus_mutex_unlock(&globus_l_brain_mutex);

}


static
void
globus_l_brain_open_server_cb(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_byte_t *                     buffer;
    globus_bool_t                       accept;

    if(result != GLOBUS_SUCCESS)
    {
        goto error_accept;
    }
    /* XXX todo verify we are ok with the sender */
    accept = GLOBUS_TRUE;

    buffer = globus_calloc(1, GFS_BRAIN_FIXED_SIZE);
    if(!accept)
    {
        goto error_read;
    }
    result = globus_xio_register_read(
        handle,
        buffer,
        GFS_BRAIN_FIXED_SIZE,
        GFS_BRAIN_FIXED_SIZE,
        NULL,
        globus_l_brain_read_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_read;
    }
    globus_l_brain_log_socket(handle, "posting a read off the open socket\n");

    return;

error_read:
    globus_free(buffer);
error_accept:
    globus_i_gfs_log_result_warn(
        "open_server_cb: A connection request to brain failed",
        result);
    globus_xio_register_close(
        handle,
        NULL,
        NULL,
        NULL);
    return;
}

static
void
globus_l_brain_add_server_accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result_warn(
            "accept_cb failed: A connection request to brain failed",
            result);
        goto error;
    }
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_WARN,
        "The brain received a connection\n");

   result = globus_xio_register_open(
        handle,
        NULL,
        NULL,
        globus_l_brain_open_server_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result_warn(
            "register_open failed: A connection request to brain failed",
            result);
    }

error:
    result = globus_xio_server_register_accept(
        globus_l_brain_server_handle,
        globus_l_brain_add_server_accept_cb,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        globus_i_gfs_log_result_warn(
            "registering the next accept failed.  "
            "this will prevent future registration",
            result);
    }
}

static
globus_result_t
globus_l_brain_listen()
{
    char *                              contact_string;
    globus_result_t                     res;
    globus_xio_attr_t                   attr;
    int                                 port = 0;
    GlobusGFSName(globus_l_brain_listen);

    GlobusGFSDebugEnter();

    res = globus_xio_attr_init(&attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_attr_init;
    }

    port =  globus_i_gfs_config_int("ipc_port");

    res = globus_xio_attr_cntl(
        attr,
        globus_i_gfs_tcp_driver,
        GLOBUS_XIO_TCP_SET_PORT,
        port);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    res = globus_xio_server_create(
        &globus_l_brain_server_handle, attr, globus_i_gfs_ipc_xio_stack);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    res = globus_xio_server_get_contact_string(
        globus_l_brain_server_handle,
        &contact_string);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_server;
    }
    globus_i_gfs_log_message(
        GLOBUS_I_GFS_LOG_INFO,
        "Braing listening on %s\n", contact_string);
    globus_free(contact_string);

    res = globus_xio_server_register_accept(
        globus_l_brain_server_handle,
        globus_l_brain_add_server_accept_cb,
        NULL);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_accept;
    }

    GlobusGFSDebugExit();

    return GLOBUS_SUCCESS;

error_accept:
    globus_free(contact_string);
error_server:
error_attr:
    globus_xio_attr_destroy(attr);
error_attr_init:

    return res;
}

static
void
globus_l_gfs_backend_changed()
{
    globus_list_t *                     repo_list;
    globus_list_t *                     node_list;
    gfs_l_db_repo_t *                   repo;
    gfs_l_db_node_t *                   node;

    globus_hashtable_to_list(&gfs_l_db_repo_table, &repo_list);

    while(!globus_list_empty(repo_list))
    {
        repo = (gfs_l_db_repo_t *) globus_list_remove(&repo_list, repo_list);

        /* for mem saftey should walk this list and copy nodes */
        node_list = globus_gfs_config_get("backend_pool");
        while(!globus_list_empty(node_list))
        {
            node = (gfs_l_db_node_t *)
                globus_list_remove(&node_list, node_list);
        }
        globus_hashtable_to_list(&repo->node_table, &node_list); 
        globus_gfs_config_set_ptr("backend_pool", node_list);
        /*
        while(!globus_list_empty(node_list))
        {
            node = (gfs_l_db_node_t *)
                globus_list_remove(&node_list, node_list);
        }
        */
    }
}

static
globus_result_t
globus_l_gfs_default_brain_init()
{
    gfs_l_db_repo_t *                   default_repo;
    char *                              remote_list;
    globus_list_t *                     list;
    globus_result_t                     res;
    gfs_l_db_node_t *                   node;

    globus_mutex_init(&globus_l_brain_mutex, NULL);

    globus_mutex_lock(&globus_l_brain_mutex);
    {
        globus_hashtable_init(
            &gfs_l_db_repo_table,
            GFS_DB_REPO_SIZE,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
            
        remote_list = globus_i_gfs_config_string("remote_nodes");
        list = gfs_l_db_parse_string_list(remote_list);

        default_repo = (gfs_l_db_repo_t *) globus_calloc(
            1, sizeof(gfs_l_db_repo_t));
        default_repo->name = strdup(GFS_DB_REPO_NAME);
        gfs_l_db_default_repo = default_repo;
        globus_priority_q_init(&default_repo->node_q, gfs_l_db_node_cmp);

        globus_hashtable_init(
            &gfs_l_db_default_repo->node_table, 
            32,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
        while(!globus_list_empty(list))
        {
            node =(gfs_l_db_node_t *)globus_calloc(1, sizeof(gfs_l_db_node_t));

            node->host_id = (char *) globus_list_first(list);
            node->repo_name = strdup(default_repo->name);
            node->max_connection = 0;
            node->total_max_connections = -1; /* -1 is infinite */
            node->current_connection = 0;
            node->load = 0.0;
            node->error = GLOBUS_FALSE;
            node->type = GFS_DB_NODE_TYPE_STATIC;
            node->repo = default_repo;
            node->cookie_id = globus_common_create_string("STATIC::%s",
                node->host_id);

            globus_hashtable_insert(
                &gfs_l_db_default_repo->node_table, node->cookie_id, node);
            globus_priority_q_enqueue(&default_repo->node_q, node, node);
            list = globus_list_rest(list);
        }
        globus_list_free(list);
        if(globus_i_gfs_config_int("brain_listen"))
        {
            res = globus_l_brain_listen();
            if(res != GLOBUS_SUCCESS)
            {
                goto error;
            }
        }
        globus_hashtable_insert(
            &gfs_l_db_repo_table, default_repo->name, default_repo);

        globus_gfs_config_set_int("data_connection_max", -1);
    }
    globus_mutex_unlock(&globus_l_brain_mutex);

    return GLOBUS_SUCCESS;

error:
    globus_mutex_unlock(&globus_l_brain_mutex);

    return res;
}

static
void
globus_l_gfs_default_brain_stop()
{
    globus_mutex_destroy(&globus_l_brain_mutex);
}

static
globus_result_t
globus_l_gfs_default_brain_available(
    const char *                        user_id,
    const char *                        repo_name,
    int *                               count)
{
    int                                 size;
    int                                 max;
    
    max = globus_i_gfs_config_int("repo_count");
    size = globus_priority_q_size(&gfs_l_db_default_repo->node_q);
    if(max > 0)
    {
        *count = (max > size) ? size : max;
    }
    else
    {
        *count = size;
    }
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_gfs_default_brain_select_nodes(
    globus_i_gfs_brain_node_t ***       out_node_array,
    int *                               out_array_length,
    const char *                        r_name,
    globus_off_t                        filesize,
    int                                 min_count,
    int                                 max_count)
{
    globus_bool_t                       done = GLOBUS_FALSE;
    int                                 best_count;
    int                                 count;
    int                                 e_count;
    int                                 i;
    globus_i_gfs_brain_node_t **        node_array;
    gfs_l_db_node_t *                   node;
    globus_result_t                     result;
    gfs_l_db_repo_t *                   repo = NULL;
    char *                              repo_name;
    GlobusGFSName(globus_gfs_brain_select_nodes);

    repo_name = (char *) r_name;
    if(repo_name == NULL || *repo_name =='\0')
    {
        repo_name = GFS_DB_REPO_NAME;
    }
    globus_mutex_lock(&globus_l_brain_mutex);
    {
        repo = (gfs_l_db_repo_t *) globus_hashtable_lookup(
            &gfs_l_db_repo_table, repo_name);
        if(repo == NULL)
        {
            result = globus_error_put(GlobusGFSErrorObjParameter("repo_name"));
            goto error;
        }

        best_count = globus_i_gfs_config_int("repo_count");
        if(best_count > max_count || best_count <= 0)
        {
            best_count = max_count;
        }

        node_array = (globus_i_gfs_brain_node_t **)
            globus_calloc(max_count, sizeof(globus_i_gfs_brain_node_t *));
        if(node_array == NULL)
        {
            result = globus_error_put(GlobusGFSErrorObjMemory("nodes"));
            goto error;
        }
        count = 0;
        e_count = count;
        while(!done && count < best_count)
        {
            node = (gfs_l_db_node_t *)globus_priority_q_dequeue(&repo->node_q);
            if(node == NULL)
            {
                done = GLOBUS_TRUE;
            }
            /* if we have exceed the current connection count for a node,
                or we have exceeded the total connection count for the
                node, we do not use it */
            else if(
                (node->current_connection >= node->max_connection &&
                 node->max_connection < 0) ||
                (node->total_max_connections > 0 && 
                    node->total_connections >= node->total_max_connections))
            {
                /* need to up everything for sake of nice clean up*/
                node->current_connection++;
                node_array[count] = (globus_i_gfs_brain_node_t *)node;
                e_count = count + 1;
                done = GLOBUS_TRUE;
            }
            else
            {
                node->current_connection++;
                node_array[count] = (globus_i_gfs_brain_node_t *)node;
                count++;
                e_count = count;
            }
        }
        if(count < min_count)
        {
            result = globus_error_put(GlobusGFSErrorObjParameter("not enough nodes"));
            goto error_short;
        }
        /* if we are here we were successful and must re-enque nodes with
            new order */
        for(i = 0; i < count; i++)
        {
            node = (gfs_l_db_node_t *) node_array[i];
            node->total_connections++;
            globus_priority_q_enqueue(
                &repo->node_q, node_array[i], node_array[i]);
        }

        *out_node_array = node_array;
        *out_array_length = count;

        globus_l_gfs_backend_changed();
    }
    globus_mutex_unlock(&globus_l_brain_mutex);

    return GLOBUS_SUCCESS;

error_short:
    /* remove the connectiopn reference */
    for(i = 0; i < e_count; i++)
    {
        node = (gfs_l_db_node_t *) node_array[i];
        node->current_connection--;
        globus_priority_q_enqueue(&repo->node_q, node, node);
        globus_i_gfs_log_message(
            GLOBUS_I_GFS_LOG_WARN,
            "Not enough nodes available: [%s] %s: %d, %d, %d\n",
            node->repo_name,
            node->host_id,
            node->current_connection,
            node->max_connection,
            node->total_max_connections);
    }
    globus_free(node_array);
error:
    globus_mutex_unlock(&globus_l_brain_mutex);
    return result;
}

static
void
gfs_l_db_static_error_timeout(
    void *                              arg)
{
    gfs_l_db_repo_t *                   repo;
    gfs_l_db_node_t *                   node;

    node = (gfs_l_db_node_t *) arg;
    repo = node->repo;
    globus_mutex_lock(&globus_l_brain_mutex);
    {
        /* clear the error and let it try again */
        node->error = GLOBUS_FALSE;
        globus_priority_q_enqueue(&repo->node_q, node, node);
        globus_hashtable_insert(&repo->node_table, node->cookie_id, node);
    }
    globus_mutex_unlock(&globus_l_brain_mutex);
}

static
globus_result_t
globus_l_gfs_default_brain_release_node(
    globus_i_gfs_brain_node_t *         b_node,
    globus_gfs_brain_reason_t           reason)
{
    int                                 dn_count = 0;
    globus_list_t *                     list;
    void *                              tmp_ptr;
    gfs_l_db_repo_t *                   repo;
    globus_bool_t                       first_error = GLOBUS_FALSE;
    globus_bool_t                       done;
    globus_result_t                     result;
    gfs_l_db_node_t *                   node;
    gfs_l_db_node_t *                   tmp_node;
    void *                              tmp_nptr;
    GlobusGFSName(globus_l_gfs_default_brain_release_node);

    node = (gfs_l_db_node_t *) b_node;

    globus_mutex_lock(&globus_l_brain_mutex);
    {
        repo = node->repo;
        node->current_connection--;
        tmp_ptr  = globus_priority_q_remove(&repo->node_q, node);
        if(tmp_ptr == NULL && !node->error)
        {
            result = GlobusGFSErrorGeneric("not a valid node");
            goto error;
        }
        switch(reason)
        {
            case GLOBUS_GFS_BRAIN_REASON_ERROR:
                globus_i_gfs_log_message(
                    GLOBUS_I_GFS_LOG_WARN,
                    "Node released with error: [%s] %s\n",
                    node->repo_name,
                    node->host_id);
                first_error = !node->error;
                node->error = GLOBUS_TRUE;
                break;

            case GLOBUS_GFS_BRAIN_REASON_COMPLETE:
                first_error = GLOBUS_FALSE;
                break;

            default:
                globus_assert(0);
                break;
        }
        if(node->error)
        {
            tmp_nptr = globus_hashtable_remove(
                &repo->node_table, node->cookie_id);
            assert(tmp_nptr == node || tmp_nptr == NULL);
            if(node->type == GFS_DB_NODE_TYPE_DYNAMIC)
            {
                if(first_error)
                {
                    globus_gfs_config_inc_int("backends_registered", -1);
                }
                if(node->current_connection == 0)
                {
                    globus_free(node->repo_name);
                    globus_free(node->host_id);
                    globus_free(node);
                }
            }
            else if(first_error)
            {
                globus_reltime_t        delay;
                GlobusTimeReltimeSet(delay, STATIC_TIMEOUT, 0);
                globus_callback_register_oneshot(
                    NULL,
                    &delay,
                    gfs_l_db_static_error_timeout,
                    node);
            }
            /* re-count everything and set it again in config,
                we need to recount because a single unlimited sets the
                value to unlimited.  if we are removing an unlimited it
                may no longer be unlimited, but it may still be */
            globus_hashtable_to_list(&repo->node_table, &list);
            done = GLOBUS_FALSE;
            while(!globus_list_empty(list) && !done)
            {
                tmp_node = (gfs_l_db_node_t *) globus_list_first(list);
                dn_count += tmp_node->max_connection;
                if(tmp_node->max_connection < 0)
                {
                    done = GLOBUS_TRUE;
                    dn_count = -1;
                }
                list = globus_list_rest(list);
            }
            globus_gfs_config_set_int("data_connection_max", dn_count);
        }
        else
        {
            /* if the node is not all used up */
            if(node->total_max_connections < 0
                || node->total_connections < node->total_max_connections)
            {
                globus_priority_q_enqueue(&repo->node_q, node, node);
            }
            else
            {
                tmp_nptr = globus_hashtable_remove(
                    &repo->node_table, node->cookie_id);
                assert(tmp_nptr == node || tmp_nptr == NULL);
                globus_assert(node->current_connection == 0);
                globus_free(node->cookie_id);
                globus_free(node->repo_name);
                globus_free(node->host_id);
                globus_free(node);
            }
        }
        globus_l_gfs_backend_changed();
    }
    globus_mutex_unlock(&globus_l_brain_mutex);
    /* depending on reason we may remove from list or whatever */

    return GLOBUS_SUCCESS;
error:
    return result;
}

globus_i_gfs_brain_module_t globus_i_gfs_default_brain =
{
    globus_l_gfs_default_brain_init,
    globus_l_gfs_default_brain_stop,
    globus_l_gfs_default_brain_select_nodes,
    globus_l_gfs_default_brain_release_node,
    globus_l_gfs_default_brain_available
};
