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


/*
 * This file or a portion of this file is licensed under the terms of the
 * Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without modifications,
 * you must include this notice in the file.
 */

#ifndef GLOBUS_I_GFS_DATA_H
#define GLOBUS_I_GFS_DATA_H

#include "globus_i_gridftp_server.h"

typedef globus_gfs_finished_info_t      globus_gfs_data_reply_t;
typedef globus_gfs_event_info_t         globus_gfs_data_event_reply_t;

typedef void
(*globus_i_gfs_data_callback_t)(
    globus_gfs_data_reply_t *           reply,
    void *                              user_arg);

typedef void
(*globus_i_gfs_data_event_callback_t)(
    globus_gfs_data_event_reply_t *     reply,
    void *                              user_arg);

void
globus_i_gfs_data_init();

void
globus_i_gfs_data_request_stat(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_stat_info_t *            stat_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

void
globus_i_gfs_data_request_recv(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_transfer_info_t *        recv_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg);

void
globus_i_gfs_data_request_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_transfer_info_t *        send_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg);

void
globus_i_gfs_data_request_list(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_transfer_info_t *        list_info,
    globus_i_gfs_data_callback_t        cb,
    globus_i_gfs_data_event_callback_t  event_cb,
    void *                              user_arg);

void
globus_i_gfs_data_request_command(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_command_info_t *         command_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

void
globus_i_gfs_data_request_passive(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_data_info_t *            data_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

void
globus_i_gfs_data_request_active(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    int                                 id,
    globus_gfs_data_info_t *            data_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

void
globus_i_gfs_data_request_handle_destroy(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    void *                              data_arg);

void
globus_i_gfs_data_request_transfer_event(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    globus_gfs_event_info_t *           event_info);

void
globus_i_gfs_data_request_set_cred(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    gss_cred_id_t                       del_cred);

void
globus_i_gfs_data_request_buffer_send(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg,
    globus_byte_t *                     buffer,
    int                                 buffer_type,
    globus_size_t                       buffer_len);
    
void
globus_i_gfs_data_session_start(
    globus_gfs_ipc_handle_t             ipc_handle,
    const gss_ctx_id_t                  context,
    globus_gfs_session_info_t *         session_info,
    globus_i_gfs_data_callback_t        cb,
    void *                              user_arg);

void
globus_i_gfs_data_session_stop(
    globus_gfs_ipc_handle_t             ipc_handle,
    void *                              session_arg);

#endif
