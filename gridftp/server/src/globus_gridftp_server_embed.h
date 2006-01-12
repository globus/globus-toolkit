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


#if !defined(GLOBUS_GRIDFTP_SERVER_EMBED_H)
#define GLOBUS_GRIDFTP_SERVER_EMBED_H 1

#include "globus_gridftp_server.h"

typedef struct globus_l_gfs_embed_handle_s * globus_gfs_embed_handle_t;


/* events.
 * XXX should possibly add some generic way to get useful info for
 * for an event.
 */
typedef enum
{
    GLOBUS_GFS_EMBED_EVENT_CONNECTION_CLOSED = 1,
    GLOBUS_GFS_EMBED_EVENT_CONNECTION_OPENED,
    GLOBUS_GFS_EMBED_EVENT_STOPPED
} globus_gfs_embed_event_t;

typedef globus_bool_t
(*globus_gfs_embed_event_cb_t)(
    globus_gfs_embed_handle_t           handle,
    globus_result_t                     result,
    globus_gfs_embed_event_t            event,
    void *                              user_arg);


/*
 * init the handle.  args[] is a NULL terminated argv-type array filled with 
 * command line parameters, may be NULL.  Start at args[1]. 
 * eg: args = {"not used", "-p", "5000", NULL}
 */
globus_result_t
globus_gridftp_server_embed_init(
    globus_gfs_embed_handle_t *         handle,
    char *                              args[]);


/*
 * destroy the handle.  if server has been started, should only be called 
 * after the STOPPED event has been triggered.
 */
void
globus_gridftp_server_embed_destroy(
    globus_gfs_embed_handle_t           handle);


/*
 * set a config parameter.  use _int or _ptr as appropriate for
 * the parameter.
 */
void
globus_gridftp_server_embed_config_set_int(
    globus_gfs_embed_handle_t           handle,
    char *                              option_name,
    int                                 int_value);

void
globus_gridftp_server_embed_config_set_ptr(
    globus_gfs_embed_handle_t           handle,
    char *                              option_name,
    void *                              ptr_value);
    

/*
 *   config query functions.
 */

#define globus_gridftp_server_embed_config_get_list    \
    (globus_list_t *) globus_gridftp_server_embed_config_get_ptr
#define globus_gridftp_server_embed_config_get_string  \
    (char *) globus_gridftp_server_embed_config_get_ptr
#define globus_gridftp_server_embed_config_get_bool    \
    (globus_bool_t) globus_gridftp_server_embed_config_get_int

void *
globus_gridftp_server_embed_config_get_ptr(
    globus_gfs_embed_handle_t           handle,
    const char *                        option_name);

int
globus_gridftp_server_embed_config_get_int(
    globus_gfs_embed_handle_t           handle,
    const char *                        option_name);


/*
 *   start up an embedded gridftp server
 *
 */
globus_result_t
globus_gridftp_server_embed_start(
    globus_gfs_embed_handle_t           handle,
    globus_gfs_embed_event_cb_t         event_cb,
    void *                              user_arg);

/*
 *  stop the running embedded server.  calling this function will start
 *  the processes of shutting down the embedded server.  When it is
 *  completely shut down the event callback will be called with
 *  the GLOBUS_GRIDFTP_SERVER_EMEB_EVENT_STOPPED event.
 */
void
globus_gridftp_server_embed_stop(
    globus_gfs_embed_handle_t           handle);


#endif
