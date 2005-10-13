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

#define GFS_BRAIN_FIXED_SIZE 256


static globus_i_gfs_brain_module_t *    brain_l_module = NULL;
static globus_extension_handle_t        brain_l_ext_handle = NULL;

globus_extension_registry_t             brain_i_registry;


globus_result_t
globus_i_gfs_brain_init()
{
    globus_result_t                     result;
    int                                 rc;
    char *                              brain_name;
    GlobusGFSName(globus_i_gfs_brain_init);

    brain_name = globus_gfs_config_get_string("brain");
    if(brain_name == NULL)
    {
        brain_l_module = &globus_i_gfs_default_brain;
    }
    else
    {
        rc = globus_extension_activate(brain_name);
        if(rc != GLOBUS_SUCCESS)
        {
            result = GlobusGFSErrorGeneric("Unable to load brain");
            goto error;
        }
        brain_l_module = (globus_i_gfs_brain_module_t *)
            globus_extension_lookup(
                &brain_l_ext_handle, &brain_i_registry, BRAIN_SYMBOL_NAME);
        if(brain_l_module == NULL)
        {
            result = GlobusGFSErrorGeneric("Couldn't find brain symbol");
            goto error;
        }
    }

    if(brain_l_module->init_func != NULL)
    {
        result = brain_l_module->init_func();
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }

    return GLOBUS_SUCCESS;

error:
    return result;
}

globus_result_t
globus_gfs_brain_get_available(
    const char *                        user_id,
    const char *                        repo_name,
    int *                               count)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    GlobusGFSName(globus_i_gfs_brain_stop);
    if(brain_l_module != NULL && brain_l_module->available_func != NULL)
    {
        result = brain_l_module->available_func(user_id, repo_name, count);
    }
    return result;
}

void
globus_i_gfs_brain_stop()
{
    GlobusGFSName(globus_i_gfs_brain_stop);
    if(brain_l_module != NULL && brain_l_module->stop_func != NULL)
    {
        brain_l_module->stop_func();
        globus_extension_release(brain_l_ext_handle);
    }
}

globus_result_t
globus_gfs_brain_select_nodes(
    globus_i_gfs_brain_node_t ***       out_nodes,
    int *                               out_array_length,
    const char *                        repo_name,
    globus_off_t                        filesize,
    int                                 min_count,
    int                                 max_count)
{
    globus_result_t                     result;
    GlobusGFSName(globus_gfs_brain_select_nodes);

    if(brain_l_module != NULL && brain_l_module->select_func != NULL)
    {
        result = brain_l_module->select_func(
            out_nodes,
            out_array_length,
            repo_name,
            filesize,
            min_count,
            max_count);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }

    return GLOBUS_SUCCESS;

error:
    return result;
}

globus_result_t
globus_gfs_brain_release_node(
    globus_i_gfs_brain_node_t *         nodes,
    globus_gfs_brain_reason_t           reason)
{
    globus_result_t                     result;
    GlobusGFSName(globus_gfs_brain_release_node);

    if(brain_l_module != NULL && brain_l_module->select_func != NULL)
    {
        result = brain_l_module->release_func(
            nodes,
            reason);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }

    return GLOBUS_SUCCESS;

error:
    return result;
}
