#include "globus_i_gridftp_server_control.h"

typedef struct globus_l_gsc_restart_ent_s
{
    globus_off_t                        offset;
    globus_off_t                        length;
} globus_l_gsc_restart_ent_t;

static void
globus_l_gsc_send_perf_marker_cb(
    void *                              user_arg);
                                                                                
static void
globus_l_gsc_send_perf_marker(
    globus_i_gsc_op_t *                 op);
                                                                                
static void
globus_l_gsc_unreg_perf_marker(
    void *                              user_arg);

void
globus_i_gsc_event_start(
    globus_i_gsc_op_t *                 op,
    int                                 event_mask)
{
    globus_result_t                     res;
    globus_reltime_t                    delay;
    globus_i_gsc_event_data_t *             event;

    event = &op->event;

    if(op->type != GLOBUS_L_GSC_OP_TYPE_RECV)
    {
        return;
    }

    /* performance markers */
    if(op->server_handle->opts.perf_frequency >= 0 &&
        event_mask & GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF)
    {
        event->stripe_count = op->server_handle->stripe_count;
        event->stripe_total_bytes = (globus_off_t *)
            globus_calloc(sizeof(globus_off_t) * event->stripe_count, 1);

        /* send out the first one */
        globus_l_gsc_send_perf_marker(op);

        /* register periodic for events */
        GlobusTimeReltimeSet(delay, op->server_handle->opts.perf_frequency, 0);
        op->ref++;  /* up the op ref for all oustanding callbacks */
        event->perf_running = GLOBUS_TRUE;
        res = globus_callback_register_periodic(
            &event->periodic_handle,
            &delay,
            &delay,
            globus_l_gsc_send_perf_marker_cb,
            op);
        if(res != GLOBUS_SUCCESS)
        {
            globus_panic(&globus_i_gsc_module, res, "one shot failed.");
        }
    }

    /* restart markers */
    if(op->server_handle->opts.restart_frequency >= 0 &&
        event_mask & GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_RESTART)
    {
        GlobusTimeReltimeSet(delay, event->restart_frequency, 0);
    }
}

void
globus_i_gsc_event_end(
    globus_i_gsc_op_t *                 op)
{
    globus_i_gsc_event_data_t *             event;

    event = &op->event;

    if(event->perf_running)
    {
        globus_l_gsc_send_perf_marker(op);
        /* cancel callback send last one */
        event->perf_running = GLOBUS_FALSE;
        globus_callback_unregister(
            op->event.periodic_handle,
            globus_l_gsc_unreg_perf_marker,
            op,
            NULL);

    }
}

int
globus_l_gsc_restart_q_cmp(
    void *                                  p1,
    void *                                  p2)
{
    globus_l_gsc_restart_ent_t *            ent1;
    globus_l_gsc_restart_ent_t *            ent2;

    ent1 = (globus_l_gsc_restart_ent_t *) p1;
    ent2 = (globus_l_gsc_restart_ent_t *) p2;

    if(ent1->offset == ent2->offset)
    {
        return 0;
    }
    else if(ent1->offset < ent2->offset)
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

globus_i_gsc_restart_t *
globus_i_gsc_restart_create()
{
    globus_i_gsc_restart_t *                restart;

    restart = (globus_i_gsc_restart_t *)
        globus_calloc(sizeof(globus_i_gsc_restart_t), 1);
    if(restart == NULL)
    {
        return NULL;
    }
    globus_priority_q_init(&restart->q, globus_l_gsc_restart_q_cmp);

    return restart;
}

void
globus_i_gsc_restart_add(
    globus_i_gsc_restart_t *                restart,
    globus_off_t                            start_off,
    globus_off_t                            end_off)
{
    globus_l_gsc_restart_ent_t *            ent;

    ent = (globus_l_gsc_restart_ent_t *)
        globus_malloc(sizeof(globus_l_gsc_restart_ent_t));
    ent->offset = start_off;
    ent->length = end_off - start_off;

    globus_priority_q_enqueue(&restart->q, ent, ent);
}

int
globus_gridftp_server_control_restart_get(
    globus_i_gsc_restart_t *                restart,
    globus_off_t *                          offset,
    globus_off_t *                          length)
{
    int                                     size;
    int                                     ndx;
    globus_l_gsc_restart_ent_t *            ent;

    if(restart->offset_a == NULL)
    {
        size = globus_priority_q_size(&restart->q) + 1;
        restart->offset_a = (globus_off_t *) 
            globus_malloc(sizeof(globus_off_t) * size);
        restart->length_a = (globus_off_t *) 
            globus_malloc(sizeof(globus_off_t) * size);

        if(size == 1)
        {
            restart->offset_a[0] = 0;
            restart->length_a[0] = -1;
            ndx++;
        }
        else
        {
            ndx = 0;
            ent = (globus_l_gsc_restart_ent_t *)
                globus_priority_q_first(&restart->q);
            if(ent->offset != 0)
            {
                restart->offset_a[ndx] = 0;
                restart->length_a[ndx] = ent->offset;
                ndx++;
            }
            while(globus_priority_q_size(&restart->q) != 1)
            {
                ent = (globus_l_gsc_restart_ent_t *)
                    globus_priority_q_dequeue(&restart->q);
                restart->offset_a[ndx] = ent->offset + ent->length;
                globus_free(ent);

                ent = (globus_l_gsc_restart_ent_t *)
                    globus_priority_q_first(&restart->q);
                restart->length_a[ndx] = ent->offset - restart->offset_a[ndx];
                ndx++;
            }
            ent = (globus_l_gsc_restart_ent_t *)
                    globus_priority_q_dequeue(&restart->q);

            restart->offset_a[ndx] = ent->offset + ent->length;
            restart->length_a[ndx] = -1;
            ndx++;

            globus_free(ent);

        }
        restart->size = ndx;
    }

    if(restart->ndx >= restart->size)
    {
        return -1;
    }
    if(offset != NULL)
    {
        *offset = restart->offset_a[restart->ndx];
    }
    if(length != NULL)
    {
        *length = restart->length_a[restart->ndx];
    }
    restart->ndx++;

    return 0;
}

void
globus_i_gsc_restart_destroy(
    globus_i_gsc_restart_t *                restart)
{
    if(restart)
    {
        if(restart->offset_a != NULL)
        {
            globus_free(restart->offset_a);
        }
        if(restart->length_a != NULL)
        {
            globus_free(restart->length_a);
        }
        globus_priority_q_destroy(&restart->q);
        globus_free(restart);
    }
}

void
globus_l_gsc_send_restart_marker()
{
}

static void
globus_l_gsc_unreg_perf_marker(
    void *                                  user_arg)
{
    globus_i_gsc_op_t *                     op;
    globus_i_gsc_event_data_t *             event;

    op = (globus_i_gsc_op_t *) user_arg;
    event = &op->event;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(event->stripe_total_bytes != NULL)
        {
            globus_free(event->stripe_total_bytes);
        }
        globus_i_gsc_op_destroy(op);
    }
    globus_mutex_unlock(&op->server_handle->mutex);
}

static void
globus_l_gsc_send_perf_marker_cb(
    void *                                  user_arg)
{
    globus_i_gsc_op_t *                     op;
    globus_i_gsc_event_data_t *             event;

    op = (globus_i_gsc_op_t *) user_arg;
    event = &op->event;

    globus_mutex_lock(&op->server_handle->mutex);
    {
        if(event->perf_running)
        {
            globus_l_gsc_send_perf_marker(op);
        }
    }
    globus_mutex_unlock(&op->server_handle->mutex);
}

static void
globus_l_gsc_send_perf_marker(
    globus_i_gsc_op_t *                     op)
{
    char *                                  msg;
    int                                     ctr;
    struct timeval                          now;
    globus_i_gsc_event_data_t *             event;

    event = &op->event;
    gettimeofday(&now, NULL);
    for(ctr = 0; ctr < event->stripe_count; ctr++)
    {
        msg = globus_common_create_string(
                "112-Perf Marker.\r\n"
                " Timestamp:  %ld.%01ld\r\n"
                " Stripe Index: %d\r\n"
                " Stripe Bytes Transferred: %"GLOBUS_OFF_T_FORMAT"\r\n"
                " Total Stripe Count: %d\r\n"
                "112 End.\r\n",
                    now.tv_sec, now.tv_usec / 100000, 
                    ctr,
                    event->stripe_total_bytes[ctr], 
                    event->stripe_count);
        globus_i_gsc_intermediate_reply(op, msg); 
        globus_free(msg);
    }

}

globus_result_t
globus_gridftp_server_control_update_bytes(
    globus_gridftp_server_control_op_t      op,
    int                                     stripe_ndx,
    globus_off_t                            offset,
    globus_off_t                            length)
{
    GlobusGridFTPServerName(globus_gridftp_server_control_update_bytes);

    if(op == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }

    if(op->event.stripe_total_bytes == NULL)
    {
        return GlobusGridFTPServerErrorParameter("op");
    }
    if(stripe_ndx > op->event.stripe_count || stripe_ndx < 0)
    {
        return GlobusGridFTPServerErrorParameter("stripe_ndx");
    }

    op->event.stripe_total_bytes[stripe_ndx] += length;

    return GLOBUS_SUCCESS;
}
