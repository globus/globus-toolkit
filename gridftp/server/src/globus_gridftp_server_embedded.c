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

#include "globus_gridftp_server_embed.h"

static globus_cond_t                    globus_l_gfs_cond;
static globus_mutex_t                   globus_l_gfs_mutex;
static globus_bool_t                    globus_l_gfs_sigint_caught = GLOBUS_FALSE;
static globus_bool_t                    globus_l_gfs_server_active = GLOBUS_FALSE;
static globus_bool_t                    globus_l_gfs_terminated = GLOBUS_FALSE;
static globus_gfs_embed_handle_t        globus_l_gfs_server_handle = NULL;


static
void 
globus_l_gfs_sigint(
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_sigint);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        if(globus_l_gfs_sigint_caught)
        {
            globus_l_gfs_server_active = 0;
        }

        globus_l_gfs_sigint_caught = GLOBUS_TRUE;
        globus_l_gfs_terminated = GLOBUS_TRUE;

        if(!globus_l_gfs_server_active)
        {
            globus_cond_signal(&globus_l_gfs_cond);
        }
        else
        {
            globus_libc_printf("Embedded server stopping.\n");
            globus_gridftp_server_embed_stop(globus_l_gfs_server_handle);
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    GlobusGFSDebugExit();
}


static
void
globus_l_gfs_signal_init()
{
    GlobusGFSName(globus_l_gfs_signal_init);
    GlobusGFSDebugEnter();
    
#   ifdef SIGINT
    globus_callback_register_signal_handler(
        SIGINT,
        GLOBUS_TRUE,
        globus_l_gfs_sigint,
        NULL);
#   endif

    GlobusGFSDebugExit();
}

static
globus_bool_t
globus_l_gfs_event_cb(
    globus_gfs_embed_handle_t           handle,
    globus_result_t                     result,
    globus_gfs_embed_event_t            event,
    void *                              user_arg)
{
    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        switch(event)
        {
            case GLOBUS_GFS_EMBED_EVENT_STOPPED:
                globus_libc_printf("Embedded server stopped.\n");
                globus_l_gfs_server_active = GLOBUS_FALSE;
                globus_cond_signal(&globus_l_gfs_cond);
            
                globus_gridftp_server_embed_destroy(handle);
                break;
                
            case GLOBUS_GFS_EMBED_EVENT_CONNECTION_CLOSED:
                globus_libc_printf("Connection closed.\n");
                break;
                
            case GLOBUS_GFS_EMBED_EVENT_CONNECTION_OPENED:
                globus_libc_printf("Connection established.\n");
                break;
                
            default:
                break;
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);
    
    return GLOBUS_TRUE;
}

int
main(
    int                                 argc,
    char **                             argv)
{
    int                                 rc = 0;
    globus_result_t                     result;
    char *                              cs;
    globus_xio_contact_t                parsed_contact;
    char *                              new_banner;
    char *                              old_banner;
    GlobusGFSName(main);

    /* activte globus stuff */    
    if((rc = globus_module_activate(GLOBUS_COMMON_MODULE)) != GLOBUS_SUCCESS ||
        (rc = globus_module_activate(
            GLOBUS_GRIDFTP_SERVER_MODULE)) != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
            "Error: Failed to initialize:\n%s",
            globus_error_print_friendly(globus_error_peek(rc)));
        goto error_activate;
    }
        
    /* initialize global variables */
    globus_mutex_init(&globus_l_gfs_mutex, GLOBUS_NULL);
    globus_cond_init(&globus_l_gfs_cond, GLOBUS_NULL);
    globus_l_gfs_signal_init();

    globus_libc_printf("Embedded server starting.\n");

    globus_mutex_lock(&globus_l_gfs_mutex);
    {
        result = globus_gridftp_server_embed_init(
            &globus_l_gfs_server_handle,
            argv);
        if(result != GLOBUS_SUCCESS)
        {
            rc = 1;
            goto error_lock;
        }
        
        globus_gridftp_server_embed_config_set_int(
            globus_l_gfs_server_handle, 
            "connections_max", 
            10);

        old_banner = globus_gridftp_server_embed_config_get_string(
            globus_l_gfs_server_handle, "banner");
        new_banner = globus_common_create_string(
            "%s\nEMBEDDED", old_banner);
        globus_gridftp_server_embed_config_set_ptr(
            globus_l_gfs_server_handle, 
            "banner", 
            new_banner);
        globus_free(old_banner);
        
        result = globus_gridftp_server_embed_start(
            globus_l_gfs_server_handle,
            globus_l_gfs_event_cb,
            NULL);
        if(result != GLOBUS_SUCCESS)
        {
            rc = 1;
            goto error_lock;
        }
        globus_l_gfs_server_active = GLOBUS_TRUE;
        
        cs = globus_gridftp_server_embed_config_get_string(
            globus_l_gfs_server_handle, "contact_string");
            
        globus_xio_contact_parse(&parsed_contact, cs);
        
        globus_libc_printf(
            "Server listening on port %s.\n", parsed_contact.port);
        globus_xio_contact_destroy(&parsed_contact);
        
        /* run until we are done */ 
        while(!globus_l_gfs_terminated || globus_l_gfs_server_active)
        {
            globus_cond_wait(&globus_l_gfs_cond, &globus_l_gfs_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_gfs_mutex);

    globus_module_deactivate_all();

    GlobusGFSDebugExit();
    return 0;

error_lock:
    globus_mutex_unlock(&globus_l_gfs_mutex);

error_activate:
    globus_module_deactivate_all();


    GlobusGFSDebugExitWithError();
    return rc;
}

