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

#include "globus_i_xio_udt.h"

static
void
globus_l_xio_udt_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

static
void
globus_i_xio_udt_pass_close(
    void*                               user_arg);

static
void
globus_l_xio_udt_handle_destroy(
    globus_l_handle_t *                handle);

/*
 *  close a udt connection
 */

static
void
globus_l_xio_udt_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_handle_t*                  handle;
    GlobusXIOName(globus_l_xio_udt_close_cb);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) user_arg;
    globus_xio_driver_finished_close(op, result);
    globus_l_xio_udt_handle_destroy(handle);

    GlobusXIOUdtDebugExit();
    return;
}


static
void
globus_i_xio_udt_pass_close(
    void*                               user_arg)
{
    globus_l_handle_t*                  handle;
    GlobusXIOName(globus_i_xio_udt_pass_close);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*) user_arg;
    globus_xio_driver_pass_close(handle->close_op, globus_l_xio_udt_close_cb,
        handle);

    GlobusXIOUdtDebugExit();
}


globus_result_t
globus_l_xio_udt_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_l_handle_t*                  handle;
    GlobusXIOName(globus_l_xio_udt_close);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t *) driver_specific_handle;
    globus_mutex_lock(&handle->state_mutex);
    if (handle->state == GLOBUS_L_XIO_UDT_CONNECTED)
    {
        handle->state = GLOBUS_L_XIO_UDT_FIN_WAIT1;
        globus_l_xio_udt_write_fin(handle);
    }
    else if (handle->state == GLOBUS_L_XIO_UDT_CLOSE_WAIT)
    {
        globus_reltime_t timeout;
        handle->state = GLOBUS_L_XIO_UDT_LAST_ACK;
        globus_l_xio_udt_write_fin(handle);
        GlobusTimeReltimeSet(timeout, 0,
            2 * GLOBUS_L_XIO_UDT_CLOSE_TIMEOUT);
        globus_callback_register_oneshot(&handle->fin_close_handle,
            &timeout, globus_l_xio_udt_fin_close, handle);
    }
    else if (handle->state == GLOBUS_L_XIO_UDT_PEER_DEAD)
    {
        globus_l_xio_udt_pass_close(handle);
    }
    handle->close_op = op;
    globus_mutex_unlock(&handle->state_mutex);
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
}

void
globus_l_xio_udt_pass_close(
    void*                       user_arg)
{
    globus_l_handle_t*          handle;
    globus_result_t             result;
    GlobusXIOName(globus_l_xio_udt_pass_close);

    GlobusXIOUdtDebugEnter();

    handle = (globus_l_handle_t*)user_arg;
    GlobusXIOUdtDebugPrintf(GLOBUS_L_XIO_UDT_DEBUG_INTERNAL_TRACE,
        ("handle state is %d\n", handle->state));
    handle->state = GLOBUS_L_XIO_UDT_CLOSED;
    globus_xio_driver_operation_cancel(handle->driver_handle,
        handle->driver_write_op);
    globus_xio_driver_operation_cancel(handle->driver_handle,
        handle->driver_read_op);
/*    globus_callback_unregister(handle->exp_handle, NULL, NULL, NULL);
    globus_callback_unregister(handle->nak_handle, NULL, NULL, NULL);
    globus_callback_unregister(handle->ack_handle, NULL, NULL, NULL);
    globus_callback_unregister(handle->fin_handle, NULL, NULL, NULL);   */
    result = globus_callback_unregister(handle->write_handle,
        globus_i_xio_udt_pass_close, handle, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        globus_xio_driver_pass_close(handle->close_op,
            globus_l_xio_udt_close_cb, handle);
    }
    GlobusXIOUdtDebugExit();
}


      /*
       *  Functionality:
       *     destroy driver handle
       *  Parameters:
       *     1) [in] handle: udt driver handle
       *  Returned value:
       *     None.
       */

static
void
globus_l_xio_udt_handle_destroy(
    globus_l_handle_t *                handle)
{
    GlobusXIOName(globus_l_xio_udt_handle_destroy);

    GlobusXIOUdtDebugEnter();

    globus_mutex_destroy(&handle->state_mutex);
    globus_mutex_destroy(&handle->write_mutex);
    globus_mutex_destroy(&handle->write_cntl->mutex);
    globus_mutex_destroy(&handle->read_cntl->mutex);
    globus_mutex_destroy(&handle->read_buf->mutex);
    globus_mutex_destroy(&handle->writer_loss_info->mutex);
    globus_mutex_destroy(&handle->write_buf->mutex);

    globus_free(handle->read_buf);
    globus_free(handle->reader_loss_info);
    globus_free(handle->read_history);
    globus_free(handle->irregular_pkt_info);
    globus_free(handle->read_cntl);
    globus_free(handle->write_buf);
    globus_free(handle->writer_loss_info);
    globus_free(handle->write_cntl);
    globus_free(handle->payload);
    globus_fifo_destroy(&handle->cntl_write_q);
    /* all the above variables were allocated in handle_init */
    globus_free(handle->cntl_write_iovec);
    globus_free(handle->attr);          /* allocated in open */
    globus_free(handle->handshake);             /* allocated in open */
    globus_free(handle);

    GlobusXIOUdtDebugExit();
}
