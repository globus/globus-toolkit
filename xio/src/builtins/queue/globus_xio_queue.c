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
} globus_xio_driver_queue_entry_t;

typedef struct globus_xio_driver_queue_handle_s
{
    int                                 read_at_once;
    int                                 write_at_once;
    int                                 outstanding_read;
    int                                 outstanding_write;
    globus_fifo_t                       read_q;
    globus_fifo_t                       write_q;
    globus_mutex_t                      mutex;
} globus_xio_driver_queue_handle_t;


static globus_xio_driver_queue_handle_t *
globus_l_xio_q_handle_create()
{
    globus_xio_driver_queue_handle_t *  handle;

    handle = (globus_xio_driver_queue_handle_t *) globus_malloc(
        sizeof(globus_xio_driver_queue_handle_t));
    globus_fifo_init(&handle->read_q);
    globus_fifo_init(&handle->write_q);
    globus_mutex_init(&handle->mutex, NULL);

    handle->outstanding_read = 0;
    handle->outstanding_write = 0;
    handle->read_at_once = 1;
    handle->write_at_once = 1;

    return handle;
}

static void
globus_l_xio_q_handle_destroy(
    globus_xio_driver_queue_handle_t *  handle)
{
    globus_fifo_destroy(&handle->read_q);
    globus_fifo_destroy(&handle->write_q);
    globus_mutex_destroy(&handle->mutex);
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
    globus_xio_driver_queue_handle_t *  handle;
    globus_bool_t                       done = GLOBUS_FALSE;
    globus_xio_driver_queue_entry_t *   entry;
    globus_result_t                     res;
    
    handle = (globus_xio_driver_queue_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        res = result;
        while(!done)
        {
            if(globus_fifo_empty(&handle->read_q))
            {
                handle->outstanding_read--;
                done = GLOBUS_TRUE;
                /* must be after the wempty check */
                globus_xio_driver_finished_read(op, res, nbytes);
            }
            else
            {
                entry = (globus_xio_driver_queue_entry_t *)
                    globus_fifo_dequeue(&handle->read_q);
                globus_assert(entry != NULL);

                /* must be after the dequeue */
                globus_xio_driver_finished_read(op, res, nbytes);

                globus_xio_driver_pass_read(
                    entry->op, 
                    entry->iovec,
                    entry->iovec_count, 
                    entry->wait_for,
                    globus_l_xio_queue_read_cb, 
                    handle);
                if(res == GLOBUS_SUCCESS)
                {
                    done = GLOBUS_TRUE;
                }
                else
                {
                    nbytes = 0;
                    op = entry->op;
                    globus_free(entry);
                }
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);
}

static globus_result_t
globus_l_xio_queue_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_xio_driver_queue_entry_t *   entry;
    globus_size_t                       wait_for;
    globus_xio_driver_queue_handle_t *  handle;
    GlobusXIOName(globus_l_xio_queue_read);

    handle = (globus_xio_driver_queue_handle_t *) driver_specific_handle;

    wait_for = globus_xio_operation_get_wait_for(op);

    globus_mutex_lock(&handle->mutex);
    {
        if(handle->outstanding_read < handle->read_at_once)
        {
            res = globus_xio_driver_pass_read(
                op, 
                (globus_xio_iovec_t *)iovec, 
                iovec_count, 
                wait_for,
                globus_l_xio_queue_read_cb, 
                handle);
            if(res == GLOBUS_SUCCESS)
            {
                handle->outstanding_read++;
            }
        }
        else
        {
            entry = globus_malloc(sizeof(globus_xio_driver_queue_entry_t));
            if(entry == NULL)
            {
                res = GlobusXIOErrorMemory("entry");
            }
            else
            {
                entry->wait_for = wait_for;
                entry->iovec = (globus_xio_iovec_t *)iovec;
                entry->iovec_count = iovec_count;
                entry->op = op;
                globus_fifo_enqueue(&handle->read_q, entry);
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);

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
    globus_xio_driver_queue_entry_t *   entry;
    globus_result_t                     res;
    
    handle = (globus_xio_driver_queue_handle_t *) user_arg;

    globus_mutex_lock(&handle->mutex);
    {
        /* loop for error cases, if the pass fails go through them all */
        res = result;
        while(!done)
        {
            if(globus_fifo_empty(&handle->write_q))
            {
                handle->outstanding_write--;
                done = GLOBUS_TRUE;
                globus_xio_driver_finished_write(op, res, nbytes);
            }
            else
            {
                entry = (globus_xio_driver_queue_entry_t *)
                    globus_fifo_dequeue(&handle->write_q);
                globus_assert(entry != NULL);

                /* finish the current one and pass the next */
                globus_xio_driver_finished_write(op, res, nbytes);
                res = globus_xio_driver_pass_write(
                    entry->op, 
                    entry->iovec, 
                    entry->iovec_count, 
                    entry->wait_for,
                    globus_l_xio_queue_write_cb, 
                    handle);
                if(res == GLOBUS_SUCCESS)
                {
                    done = GLOBUS_TRUE;
                }
                else
                {
                    nbytes = 0;
                    op = entry->op;
                    globus_free(entry);
                }
            }
        }
    }
    globus_mutex_unlock(&handle->mutex);
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
                handle);
            if(res == GLOBUS_SUCCESS)
            {
                handle->outstanding_write++;
            }
        }
        else
        {
            entry = globus_malloc(sizeof(globus_xio_driver_queue_entry_t));
            if(entry == NULL)
            {
                res = GlobusXIOErrorMemory("entry");
            }
            else
            {
                entry->wait_for = wait_for;
                entry->iovec = (globus_xio_iovec_t *)iovec;
                entry->iovec_count = iovec_count;
                entry->op = op;
                globus_fifo_enqueue(&handle->write_q, entry);
            }
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
