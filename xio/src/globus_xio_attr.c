#include "globus_common.h"
#include "globus_i_xio.h"

/*******************************************************************
 *                     internal functions
 ******************************************************************/

/*******************************************************************
 *                         api functions
 *                         -------------
 *
 *  In these we just check parameters, allocate memory and call the
 *  internal functions.
 ******************************************************************/
/*
 *
 */
globus_result_t
globus_xio_attr_init(
    globus_xio_attr_t *                     attr)
{
    globus_result_t                         res;
    globus_i_xio_attr_t *                   xio_attr;
    GlobusXIOName(globus_xio_attr_init);

    GlobusXIODebugEnter();
    
    if(attr == NULL)
    {
        res = GlobusXIOErrorParameter("attr");
        goto err;
    }
   
    /* allocate the attr */ 
    xio_attr = (globus_i_xio_attr_t *)
                globus_malloc(sizeof(globus_i_xio_attr_t));
    if(xio_attr == NULL)
    {
        res = GlobusXIOErrorMemory("attr");
        goto err;
    }
    memset(xio_attr, '\0', sizeof(globus_i_xio_attr_t));

    xio_attr->entry = (globus_i_xio_attr_ent_t *)
        globus_malloc(sizeof(globus_i_xio_attr_ent_t) *
            GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);

    if(xio_attr->entry == NULL)
    {
        globus_free(xio_attr);
        res = GlobusXIOErrorMemory("attr->entry");
        goto err;
    }

    /* zero it out */
    memset((xio_attr->entry), '\0', sizeof(globus_i_xio_attr_ent_t) *
        GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);
    xio_attr->max = GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE;
    xio_attr->space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    
    *attr = xio_attr;

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:
    *attr = GLOBUS_NULL;

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *
 */
globus_result_t
globus_xio_attr_cntl(
    globus_xio_attr_t                       user_attr,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...)
{
    va_list                                 ap;
    globus_result_t                         res;
    void *                                  ds;
    globus_i_xio_attr_t *                   attr;
    globus_xio_attr_cmd_t                   general_cmd;
    globus_xio_timeout_server_callback_t    server_timeout_cb;
    globus_xio_timeout_callback_t           timeout_cb;
    globus_reltime_t *                      delay_time;
    GlobusXIOName(globus_xio_attr_cntl);

    GlobusXIODebugEnter();
    
    if(user_attr == NULL)
    {
        res = GlobusXIOErrorParameter("user_attr");
        goto err;
    }

    attr = user_attr;

#   ifdef HAVE_STDARG_H
    {
        va_start(ap, cmd);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    if(driver != NULL)
    {
        GlobusIXIOAttrGetDS(ds, attr, driver);
        if(ds == NULL)
        {
            res = driver->attr_init_func(&ds);
            if(res != GLOBUS_SUCCESS)
            {
                goto err;
            }
            if(attr->ndx >= attr->max)
            {
                attr->max *= 2;
                attr->entry = (globus_i_xio_attr_ent_t *)
                    globus_realloc(attr->entry, attr->max *
                            sizeof(globus_i_xio_attr_ent_t));
            }
            attr->entry[attr->ndx].driver = driver;
            attr->entry[attr->ndx].driver_data = ds;
            attr->ndx++;
        }
        res = driver->attr_cntl_func(ds, cmd, ap);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    else
    {
        general_cmd = cmd;

        switch(general_cmd)
        {
            case GLOBUS_XIO_ATTR_SET_TIMEOUT_ALL:
                timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                delay_time = va_arg(ap, globus_reltime_t *);

                attr->open_timeout_cb = timeout_cb;
                attr->close_timeout_cb = timeout_cb;
                attr->read_timeout_cb = timeout_cb;
                attr->write_timeout_cb = timeout_cb;

                GlobusTimeReltimeCopy(attr->open_timeout_period, *delay_time);
                GlobusTimeReltimeCopy(attr->close_timeout_period, *delay_time);
                GlobusTimeReltimeCopy(attr->read_timeout_period, *delay_time);
                GlobusTimeReltimeCopy(attr->write_timeout_period, *delay_time);

                break;

            case GLOBUS_XIO_ATTR_SET_TIMEOUT_OPEN:
                timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                delay_time = va_arg(ap, globus_reltime_t *);

                attr->open_timeout_cb = timeout_cb;
                GlobusTimeReltimeCopy(attr->open_timeout_period, *delay_time);
                break;

            case GLOBUS_XIO_ATTR_SET_TIMEOUT_CLOSE:
                timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                delay_time = va_arg(ap, globus_reltime_t *);

                attr->close_timeout_cb = timeout_cb;
                GlobusTimeReltimeCopy(attr->close_timeout_period, *delay_time);
                break;

            case GLOBUS_XIO_ATTR_SET_TIMEOUT_READ:
                timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                delay_time = va_arg(ap, globus_reltime_t *);

                attr->read_timeout_cb = timeout_cb;
                GlobusTimeReltimeCopy(attr->read_timeout_period, *delay_time);
                break;

            case GLOBUS_XIO_ATTR_SET_TIMEOUT_WRITE:
                timeout_cb = va_arg(ap, globus_xio_timeout_callback_t);
                delay_time = va_arg(ap, globus_reltime_t *);

                attr->write_timeout_cb = timeout_cb;
                GlobusTimeReltimeCopy(attr->write_timeout_period, *delay_time);
                break;

            case GLOBUS_XIO_ATTR_SET_TIMEOUT_ACCEPT:
                server_timeout_cb = 
                    va_arg(ap, globus_xio_timeout_server_callback_t);
                delay_time = va_arg(ap, globus_reltime_t *);

                attr->accept_timeout_cb = server_timeout_cb;
                GlobusTimeReltimeCopy(attr->accept_timeout_period, *delay_time);
                break;
        } 

        res = GLOBUS_SUCCESS;
    }

    va_end(ap);

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    va_end(ap);

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *
 */
globus_result_t
globus_xio_attr_destroy(
    globus_xio_attr_t                       attr)
{
    int                                     ctr;
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_result_t                         tmp_res;
    GlobusXIOName(globus_xio_attr_destroy);

    GlobusXIODebugEnter();
    
    if(attr == NULL)
    {
        res = GlobusXIOErrorParameter("attr");
        goto err;
    }
    
    for(ctr = 0; ctr < attr->ndx; ctr++)
    {
        /* report the last seen error but be sure to attempt to clean 
            them all */
        tmp_res = attr->entry[ctr].driver->attr_destroy_func(
                attr->entry[ctr].driver_data);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            res = tmp_res;
        }
    }

    globus_free(attr->entry);
    globus_free(attr);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_attr_copy(
    globus_xio_attr_t *                     dst,
    globus_xio_attr_t                       src)
{
    globus_i_xio_attr_t *                   xio_attr_src;
    globus_i_xio_attr_t *                   xio_attr_dst;
    globus_result_t                         res;
    int                                     ctr;
    int                                     ctr2;
    GlobusXIOName(globus_xio_attr_copy);

    GlobusXIODebugEnter();
    
    if(dst == NULL)
    {
        res = GlobusXIOErrorParameter("dst");
        goto err;
    }

    if(src == NULL)
    {
        res = GlobusXIOErrorParameter("src");
        goto err;
    }

    xio_attr_src = src;

    xio_attr_dst = (globus_i_xio_attr_t *)
            globus_malloc(sizeof(globus_i_xio_attr_t));

    /* check for memory alloc failure */
    if(xio_attr_dst == NULL)
    {
        res = GlobusXIOErrorMemory("xio_attr_dst");
        goto err;
    }
    
    memset(xio_attr_dst, 0, sizeof(globus_i_xio_attr_t));
    xio_attr_dst->entry = (globus_i_xio_attr_ent_t *)
        globus_malloc(sizeof(globus_i_xio_attr_ent_t) *
            GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);
    if(xio_attr_dst->entry == NULL)
    {
        globus_free(xio_attr_dst);
        res = GlobusXIOErrorMemory("xio_attr_dst->entry");
        goto err;
    }

    memset(xio_attr_dst->entry, 0, 
        sizeof(globus_i_xio_attr_ent_t) * GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);

    /* copy all general attrs */
    xio_attr_dst->max = xio_attr_src->max;
    xio_attr_dst->ndx = xio_attr_src->ndx;
 
    for(ctr = 0; ctr < xio_attr_dst->ndx; ctr++)
    {
        xio_attr_dst->entry[ctr].driver = xio_attr_src->entry[ctr].driver;

        res = xio_attr_dst->entry[ctr].driver->attr_copy_func(
                &xio_attr_dst->entry[ctr].driver_data,
                xio_attr_src->entry[ctr].driver_data);
        if(res != GLOBUS_SUCCESS)
        {
            for(ctr2 = 0; ctr2 < ctr; ctr2++)
            {
                /* ignore result here */
                xio_attr_dst->entry[ctr].driver->attr_destroy_func(
                    xio_attr_dst->entry[ctr].driver_data);
            }
            globus_free(xio_attr_dst->entry);
            globus_free(xio_attr_dst);

            goto err;
        }
    }

    *dst = xio_attr_dst;

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}
/*******************************************************************
 *                       data descriptor stuff
 ******************************************************************/
/* 
 *  the main difference between a dd and an attr is that the DD
 *  has the driver specific data in order of the drivers in the handle 
 *
 *  the same internal data structures are used.  the only difference
 *  in accessing these data structures is the assumptoin of order.
 */

/*
 *
 */
globus_result_t
globus_xio_data_descriptor_init( 
    globus_xio_data_descriptor_t *          data_desc,
    globus_xio_handle_t                     handle)
{
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                     op;
    globus_i_xio_context_t *                context;
    GlobusXIOName(globus_xio_data_descriptor_init);

    GlobusXIODebugEnter();
    
    if(data_desc == NULL)
    {
        res = GlobusXIOErrorParameter("data_desc");
        goto err;
    }
    if(handle == NULL)
    {
        res = GlobusXIOErrorParameter("handle");
        goto err;
    }

    context = handle->context;
    globus_mutex_lock(&handle->mutex);
    {
        GlobusXIOOperationCreate(op, context);
        if(op != NULL)
        {
            op->type = GLOBUS_XIO_OPERATION_TYPE_DD;
            handle->ref++;
        }
        else
        {
            res = GlobusXIOErrorMemory("xio_dd");
        }
    }
    globus_mutex_unlock(&handle->mutex);

    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    *data_desc = op;

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    *data_desc = NULL;
    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_data_descriptor_destroy(
    globus_xio_data_descriptor_t            data_desc)
{
    int                                     ctr;
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_result_t                         tmp_res;
    globus_i_xio_op_t *                     op;
    globus_i_xio_handle_t *                 handle;
    globus_bool_t                           destroy_handle;
    GlobusXIOName(globus_xio_data_descriptor_destroy);

    GlobusXIODebugEnter();
    
    if(data_desc == NULL)
    {
        res = GlobusXIOErrorParameter("data_desc");
        goto err;
    }

    op = (globus_i_xio_op_t *) data_desc;
    if(op->type != GLOBUS_XIO_OPERATION_TYPE_DD)
    {
        res = GlobusXIOErrorInvalidState(op->type);
        goto err;
    }
    handle = op->_op_handle;

    for(ctr = 0; ctr < op->stack_size; ctr++)
    {
        if(op->entry[ctr].dd != NULL)
        {
            tmp_res = op->_op_context->entry[ctr].driver->attr_destroy_func(
                        op->entry[ctr].dd);
            if(tmp_res != GLOBUS_SUCCESS)
            {
                res = tmp_res;
            }
        }
    }

    globus_mutex_lock(&handle->mutex);
    {
        GlobusXIOOperationDestroy(op);
        GlobusIXIOHandleDec(destroy_handle, handle);
    }
    globus_mutex_unlock(&handle->mutex);

    if(destroy_handle)
    {
        GlobusXIOHandleDestroy(handle);
    }
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_data_descriptor_cntl(
    globus_xio_data_descriptor_t            data_desc,
    globus_xio_driver_t                     driver,
    int                                     cmd,
    ...)
{
    globus_result_t                         res;
    int                                     ndx;
    int                                     ctr;
    globus_i_xio_op_t *                     op;
    va_list                                 ap;
    GlobusXIOName(globus_xio_data_descriptor_cntl);

    GlobusXIODebugEnter();
    
    if(data_desc == NULL)
    {
        res = GlobusXIOErrorParameter("data_desc");
        goto err;
    }

    op = (globus_i_xio_op_t *) data_desc;

    if(driver != NULL)
    {
        ndx = -1;
        for(ctr = 0; ctr < op->stack_size && ndx == -1; ctr++)
        {
            if(driver == op->_op_context->entry[ctr].driver)
            {
                if(op->entry[ctr].dd == NULL)
                {
                    res = op->_op_context->entry[ctr].driver->attr_init_func(
                            &op->entry[ctr].dd);
                    if(res != GLOBUS_SUCCESS)
                    {
                        goto err;
                    }
                }
                ndx = ctr;
            }
        }
        if(ndx == -1)
        {
            /* throw error */
            res = GlobusXIOErrorInvalidDriver("not found");
            goto err;
        }
#       ifdef HAVE_STDARG_H
        {
            va_start(ap, cmd);
        }
#       else
        {
            va_start(ap);
        }
#       endif

        res = op->_op_context->entry[ndx].driver->attr_cntl_func(
                op->entry[ndx].dd,
                cmd,
                ap);
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
        va_end(ap);
    }
    else
    {
        /* TODO: add code for general dd attributes */
    }

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_data_descriptor_copy(
    globus_xio_data_descriptor_t *          dst,
    globus_xio_data_descriptor_t            src)
{
    globus_i_xio_op_t *                     op_src;
    globus_i_xio_op_t *                     op_dst;
    globus_result_t                         res;
    int                                     ctr;
    int                                     ctr2;
    GlobusXIOName(globus_xio_data_descriptor_copy);

    GlobusXIODebugEnter();
    
    if(dst == NULL)
    {
        res = GlobusXIOErrorParameter("dst");
        goto err;
    }

    if(src == NULL)
    {
        res = GlobusXIOErrorParameter("src");
        goto err;
    }

    op_src = src;

    res = globus_xio_data_descriptor_init(&op_dst, op_src->_op_handle);
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }

    for(ctr = 0; ctr < op_src->stack_size; ctr++)
    {
        res = op_dst->_op_context->entry[ctr].driver->attr_copy_func(
                &op_dst->entry[ctr].dd,
                op_src->entry[ctr].dd);
        if(res != GLOBUS_SUCCESS)
        {
            for(ctr2 = 0; ctr2 < ctr; ctr2++)
            {
                /* ignore result here */
                op_dst->_op_context->entry[ctr].driver->attr_destroy_func(
                    op_dst->entry[ctr].dd);
            }
            globus_memory_push_node(&op_dst->_op_context->op_memory, op_dst);

            goto err;
        }
    }

    *dst = op_dst;

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

/************************************************************************
 *                  stack functions
 ***********************************************************************/
globus_result_t
globus_xio_stack_init(
    globus_xio_stack_t *                    stack,
    globus_xio_attr_t                       stack_attr)
{
    globus_i_xio_stack_t *                  xio_stack;
    GlobusXIOName(globus_xio_stack_init);

    GlobusXIODebugEnter();
    
    if(stack == NULL)
    {
        GlobusXIODebugExitWithError();
        return GlobusXIOErrorParameter("stack");
    }

    xio_stack = globus_malloc(sizeof(globus_i_xio_stack_t));
    memset(xio_stack, '\0', sizeof(globus_i_xio_stack_t));
    globus_mutex_init(&xio_stack->mutex, NULL);

    *stack = xio_stack;

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_stack_push_driver(
    globus_xio_stack_t                      stack,
    globus_xio_driver_t                     driver)
{
    globus_i_xio_stack_t *                  xio_stack;
    globus_result_t                         res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_stack_push_driver);

    GlobusXIODebugEnter();
    
    if(stack == NULL)
    {
        res = GlobusXIOErrorParameter("stack");
        goto err;
    }
    if(driver == NULL)
    {
        res = GlobusXIOErrorParameter("driver");
        goto err;
    }

    xio_stack = (globus_i_xio_stack_t *) stack;

    globus_mutex_lock(&xio_stack->mutex);
    {
        if(xio_stack->size == 0)
        {
            if(driver->transport_open_func == NULL)
            {
                res = GlobusXIOErrorInvalidDriver(
                    "open function not defined");
            }
            else
            {
                xio_stack->transport_driver = driver;
            }
        }
        else if(driver->transport_open_func != NULL)
        {
                res = GlobusXIOErrorInvalidDriver(
                    "transport can only be at bottom of stack");
        }
       
        if(res == GLOBUS_SUCCESS)
        {
            xio_stack->size++;
            globus_list_insert(&xio_stack->driver_stack, driver);
        } 
    }
    globus_mutex_unlock(&xio_stack->mutex);

    /* this is weird, but for debug messages */
    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_stack_destroy(
    globus_xio_stack_t                      stack)
{
    globus_result_t                         res;
    GlobusXIOName(globus_xio_stack_destroy);

    GlobusXIODebugEnter();
    
    if(stack == NULL)
    {
        res = GlobusXIOErrorParameter("stack");
        goto err;
    }

    globus_mutex_destroy(&stack->mutex);
    globus_list_free(stack->driver_stack);
    globus_free(stack);

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}
