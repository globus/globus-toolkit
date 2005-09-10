/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_i_gridftp_server.h"
#include "globus_i_gfs_ipc.h"

extern globus_i_gfs_community_t *       globus_l_gfs_ipc_community_default;

static globus_list_t *                  globus_l_brain_repo_list;
static globus_mutex_t                   globus_l_brain_mutex;

globus_result_t
globus_i_gfs_brain_init()
{
    globus_mutex_init(&globus_l_brain_mutex, NULL);
    globus_l_brain_repo_list = globus_i_gfs_config_list("community");

    return GLOBUS_SUCCESS;
}

void
globus_i_gfs_brain_stop()
{
    globus_mutex_destroy(&globus_l_brain_mutex);
}

globus_result_t
globus_gfs_brain_select_nodes(
    char ***                            out_contact_strings,
    int *                               out_array_length,
    const char *                        repo_name,
    globus_off_t                        filesize,
    int                                 min_count,
    int                                 max_count)
{
    int                                 best_count;
    int                                 count;
    char **                             cs;
    globus_result_t                     result;
    globus_list_t *                     list;
    globus_i_gfs_community_t *          repo = NULL;
    globus_i_gfs_community_t *          tmp_repo = NULL;
    GlobusGFSName(globus_gfs_brain_select_nodes);

    globus_mutex_lock(&globus_l_brain_mutex);
    {
        if(repo_name == NULL || 
            strcmp(repo_name, globus_l_gfs_ipc_community_default->name) == 0)
        {
            repo = globus_l_gfs_ipc_community_default;
        }
        else
        {
            list = globus_l_brain_repo_list;
            while(!globus_list_empty(list) && repo == NULL)
            {
                tmp_repo = globus_list_first(list);
                if(strcmp(tmp_repo->name, repo_name) == 0)
                {
                    repo = tmp_repo;
                }
                list = globus_list_rest(list);
            }
        }

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

        /* this is the tester brain dead approach */
        cs = globus_calloc(max_count, sizeof(char *));
        if(cs == NULL)
        {
            result = globus_error_put(GlobusGFSErrorObjMemory("cs"));
            goto error;
        }
        count = 0;
        while(count < best_count)
        {
            cs[count] = strdup(repo->cs[repo->next_ndx]);
            count++;
            repo->next_ndx++;
            if(repo->next_ndx >= repo->cs_count)
            {
                repo->next_ndx = 0;
            }
        }

        *out_contact_strings = cs;
        *out_array_length = count;
    }
    globus_mutex_unlock(&globus_l_brain_mutex);

    return GLOBUS_SUCCESS;

error:
    globus_mutex_unlock(&globus_l_brain_mutex);
    return result;
}

globus_result_t
globus_gfs_brain_release_node(
    char *                              contact_string,
    const char *                        repo_name,
    globus_gfs_brain_reason_t           reason)
{
    /* depending on reason we may remove from list or whatever */

    return GLOBUS_SUCCESS;
}
