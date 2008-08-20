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

#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_queue.h"

static int
globus_l_xio_queue_activate();

static int
globus_l_xio_queue_deactivate();

#include "version.h"

GlobusXIODefineModule(queue) =
{
    "globus_xio_queue",
    globus_l_xio_queue_activate,
    globus_l_xio_queue_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef struct globus_xio_driver_queue_entry_s
{
    globus_xio_iovec_t *                iovec;
    int                                 iovec_count;
    globus_xio_operation_t              op;
    globus_size_t                       wait_for;
    struct globus_xio_driver_queue_handle_s * handle;
    globus_result_t                     res;
} globus_xio_driver_queue_entry_t;

typedef struct globus_xio_driver_queue_handle_s
{
    int                                 write_at_once;
    int                                 outstanding_write;
    globus_fifo_t                       write_q;
    globus_mutex_t                      mutex;
} globus_xio_driver_queue_handle_t;


static globus_xio_driver_queue_handle_t *
globus_l_xio_q_handle_create()
{
    globus_xio_driver_queue_handle_t *  handle;

    handle = (globus_xio_driver_queue_handle_t *) globus_malloc(
        sizeof(globus_xio_driver_queue_handle_t));
    if(handle == NULL)
    {
        return NULL;
    }
    globus_fifo_init(&handle->write_q);
    globus_mutex_init(&handle->mutex, NULL);

    handle->outstanding_write = 0;
    handle->write_at_once = 1;

    return handle;
}

static void
globus_l_xio_q_handle_destroy(
    globus_xio_driver_queue_handle_t *  handle)
{
    globus_fifo_destroy(&handle->write_q);
    globus_mutex_destroy(&handle->mutex);
    globus_free(handle);
}

/*
 *  open
 */
void
globus_l_xio_queue_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_queue_handle_t *  handle;

    handle = (globus_xio_driver_queue_handle_t *) user_arg;

    globus_xio_driver_finished_open(handle, op, result);
    if(result != GLOBUS_SUCCESS)
    {
        globus_l_xio_q_handle_destroy(handle);
        handle = NULL;
    }
}   

static
globus_result_t
globus_l_xio_queue_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_xio_driver_queue_handle_t *  handle;

    handle = globus_l_xio_q_handle_create();
    if(handle == NULL)
    {
    }

    res = globus_xio_driver_pass_open(op, contact_info,
        globus_l_xio_queue_open_cb, handle);

    return res;
}

static
globus_result_t
globus_l_xio_queue_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_xio_driver_queue_handle_t *  handle;

    handle = (globus_xio_driver_queue_handle_t *) driver_specific_handle;

    globus_l_xio_q_handle_destroy(handle);

    res = globus_xio_driver_pass_close(op, NULL, NULL);

    return res;
}

/*
 *  read
 */
void
globus_l_xio_queue_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_read(op, result, nbytes);
}

static globus_result_t
globus_l_xio_queue_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_size_t                       wait_for;
    globus_result_t                     res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_l_xio_queue_read);

    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_read(
        op, 
        (globus_xio_iovec_t *)iovec, 
        iovec_count, 
        wait_for,
        globus_l_xio_queue_read_cb, 
        NULL);

    return res;
}

/*
 *  write
 */
void
globus_l_xio_queue_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_queue_handle_t *  handle;
    globus_bool_t                       done = GLOBUS_FALSE;
    globus_xio_driver_queue_entry_t *   in_entry;
    globus_xio_driver_queue_entry_t *   entry;
    globus_result_t                     res;
    globus_fifo_t                       q;
    globus_bool_t                       use_q = GLOBUS_FALSE;

    in_entry = (globus_xio_driver_queue_entry_t *) user_arg;
    handle = in_entry->handle;

    globus_mutex_lock(&handle->mutex);
    {
        handle->outstanding_write--;

        while(handle->outstanding_write < handle->write_at_once && !done)
        {
            if(globus_fifo_empty(&handle->write_q))
            {
                done = GLOBUS_TRUE;
            }
            else
            {
                entry = (globus_xio_driver_queue_entry_t *)
                    globus_fifo_dequeue(&handle->write_q);
                globus_assert(entry != NULL);

                res = globus_xio_driver_pass_write(
                    entry->op, 
                    entry->iovec, 
                    entry->iovec_count, 
                    entry->wait_for,
                    globus_l_xio_queue_write_cb, 
                    entry);
                if(res != GLOBUS_SUCCESS)
                {
                    if(!use_q)
                    {
                        globus_fifo_init(&q);
                    }
                    use_q = GLOBUS_TRUE;
                    entry->res = res;
                    globus_fifo_enqueue(&q, entry);
                }
                else
                {
                    handle->outstanding_write++;
                }
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);

    globus_xio_driver_finished_write(in_entry->op, result, nbytes);
    globus_free(in_entry);

    if(use_q)
    {
        while(!globus_fifo_empty(&q))
        {
            entry = (globus_xio_driver_queue_entry_t *) globus_fifo_dequeue(&q);

            globus_xio_driver_finished_write(entry->op, entry->res, 0);
            globus_free(entry);
        }
        globus_fifo_destroy(&q);
    }
}

static globus_result_t
globus_l_xio_queue_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_xio_driver_queue_entry_t *   entry;
    globus_size_t                       wait_for;
    globus_xio_driver_queue_handle_t *  handle;
    GlobusXIOName(globus_l_xio_queue_write);

    handle = (globus_xio_driver_queue_handle_t *) driver_specific_handle;
    wait_for = globus_xio_operation_get_wait_for(op);

    entry = globus_malloc(sizeof(globus_xio_driver_queue_entry_t));
    if(entry == NULL)
    {
        res = GlobusXIOErrorMemory("entry");
        return res;
    }
    entry->wait_for = wait_for;
    entry->iovec = (globus_xio_iovec_t *)iovec;
    entry->iovec_count = iovec_count;
    entry->op = op;
    entry->handle = handle;
    entry->res = GLOBUS_SUCCESS;

    globus_mutex_lock(&handle->mutex);
    {
        if(handle->outstanding_write < handle->write_at_once)
        {
            res = globus_xio_driver_pass_write(
                op, 
                (globus_xio_iovec_t *)iovec, 
                iovec_count, 
                wait_for,
                globus_l_xio_queue_write_cb,
                entry);
            if(res == GLOBUS_SUCCESS)
            {
                handle->outstanding_write++;
            }
        }
        else
        {
            res = GLOBUS_SUCCESS;
            globus_fifo_enqueue(&handle->write_q, entry);
        }
    }
    globus_mutex_unlock(&handle->mutex);

    return res;
}

static globus_result_t
globus_l_xio_queue_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "queue", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_queue_open,
        globus_l_xio_queue_close,
        globus_l_xio_queue_read,
        globus_l_xio_queue_write,
        NULL,
	NULL);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_queue_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    queue,
    globus_l_xio_queue_init,
    globus_l_xio_queue_destroy);

static
int
globus_l_xio_queue_activate(void)
{
    int                                 rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(queue);
    }
    return rc;
}

static
int
globus_l_xio_queue_deactivate(void)
{
    GlobusXIOUnRegisterDriver(queue);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
