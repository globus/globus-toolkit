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
    globus_xio_attr_t *                         attr)
{
    globus_i_xio_attr_t *                       xio_attr;
    GlobusXIOName(globus_xio_attr_init);

    if(attr == NULL)
    {
        return GlobusXIOErrorParameter("attr");
    }
   
    /* allocate the attr */ 
    xio_attr = (globus_i_xio_attr_t *)
                globus_malloc(sizeof(globus_i_xio_attr_t));
    if(xio_attr == NULL)
    {
        return GlobusXIOErrorMemory("attr");
    }
    memset(xio_attr, '\0', sizeof(globus_i_xio_attr_t));

    xio_attr->entry = (globus_i_xio_attr_ent_t *)
        globus_malloc(sizeof(globus_i_xio_attr_ent_t) *
            GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);

    if(xio_attr->entry == NULL)
    {
        globus_free(xio_attr);
        return GlobusXIOErrorMemory("attr->entry");
    }

    /* zero it out */
    memset((xio_attr->entry), '\0', sizeof(globus_i_xio_attr_ent_t) *
        GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);
    xio_attr->max = GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE;
    xio_attr->space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    
    *attr = xio_attr;

    return GLOBUS_SUCCESS;
}

/*
 *
 */
globus_result_t
globus_xio_attr_cntl(
    globus_xio_attr_t                           user_attr,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    ...)
{
    va_list                                     ap;
    globus_result_t                             res;
    void *                                      ds;
    globus_i_xio_attr_t *                       attr;
    globus_xio_attr_cmd_t                       general_cmd;
    globus_xio_timeout_server_callback_t        server_timeout_cb;
    globus_xio_timeout_callback_t               timeout_cb;
    globus_reltime_t *                          delay_time;
    GlobusXIOName(globus_xio_attr_cntl);

    if(user_attr == NULL)
    {
        return GlobusXIOErrorParameter("user_attr");
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
                goto exit;
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
            goto exit;
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

  exit:

    va_end(ap);

    return res;
}

/*
 *
 */
globus_result_t
globus_xio_attr_destroy(
    globus_xio_attr_t                           attr)
{
    int                                         ctr;
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_result_t                             tmp_res;
    GlobusXIOName(globus_xio_attr_destroy);

    if(attr == NULL)
    {
        return GlobusXIOErrorParameter("attr");
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

    return res;
}

globus_result_t
globus_xio_attr_copy(
    globus_xio_attr_t *                         dst,
    globus_xio_attr_t                           src)
{
    globus_i_xio_attr_t *                       xio_attr_src;
    globus_i_xio_attr_t *                       xio_attr_dst;
    globus_result_t                             res;
    int                                         ctr;
    int                                         ctr2;
    GlobusXIOName(globus_xio_attr_copy);

    if(dst == NULL)
    {
        return GlobusXIOErrorParameter("dst");
    }

    if(src == NULL)
    {
        return GlobusXIOErrorParameter("src");
    }

    xio_attr_src = src;

    xio_attr_dst = (globus_i_xio_attr_t *)
            globus_malloc(sizeof(globus_i_xio_attr_t));

    /* check for memory alloc failure */
    if(xio_attr_dst == NULL)
    {
        return GlobusXIOErrorMemory("xio_attr_dst");
    }

    xio_attr_dst->entry = (globus_i_xio_attr_ent_t *)
        globus_malloc(sizeof(globus_i_xio_attr_ent_t) *
            GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);
    if(xio_attr_dst->entry == NULL)
    {
        globus_free(xio_attr_dst);
        return GlobusXIOErrorMemory("xio_attr_dst->entry");
    }

    memset(xio_attr_dst, 0, sizeof(globus_i_xio_attr_t));
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

            return res;
        }
    }

    *dst = xio_attr_dst;

    return GLOBUS_SUCCESS;
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
    globus_xio_data_descriptor_t *              data_desc,
    globus_xio_handle_t                         handle)
{
    globus_i_xio_op_t *                         op;
    globus_i_xio_context_t *                    context;
    GlobusXIOName(globus_xio_data_descriptor_init);

    if(data_desc == NULL)
    {
        return GlobusXIOErrorParameter("data_desc");
    }
    if(handle == NULL)
    {
        return GlobusXIOErrorParameter("handle");
    }

    context = handle->context;
    op = (globus_i_xio_op_t *) globus_memory_pop_node(&context->op_memory);

    /* check for memory alloc failure */
    if(op == NULL)
    {
        return GlobusXIOErrorMemory("xio_dd");
    }

    memset(op, '\0', sizeof(globus_i_xio_op_t) + 
        (sizeof(globus_i_xio_op_entry_t) * (context->stack_size - 1)));
    op->stack_size = handle->stack_size;
    op->progress = GLOBUS_TRUE;
    op->_op_context = context;

    *data_desc = op;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_data_descriptor_destroy(
    globus_xio_data_descriptor_t                data_desc)
{
    int                                         ctr;
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_result_t                             tmp_res;
    globus_i_xio_op_t *                         op;
    GlobusXIOName(globus_xio_data_descriptor_destroy);

    if(data_desc == NULL)
    {
        return GlobusXIOErrorParameter("data_desc");
    }

    op = (globus_i_xio_op_t *) data_desc;

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

    globus_free(op);

    return res;
}

globus_result_t
globus_xio_data_descriptor_cntl(
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    ...)
{
    globus_result_t                             res;
    int                                         ndx;
    int                                         ctr;
    globus_i_xio_op_t *                         op;
    va_list                                     ap;
    GlobusXIOName(globus_xio_data_descriptor_cntl);

    if(data_desc == NULL)
    {
        return GlobusXIOErrorParameter("data_desc");
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
                        return res;
                    }
                }
                ndx = ctr;
            }
        }
        if(ndx == -1)
        {
            /* throw error */
            return GlobusXIOErrorInvalidDriver("not found");
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
            return res;
        }
        va_end(ap);
    }
    else
    {
        /* TODO: add code for general dd attributes */
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_data_descriptor_copy(
    globus_xio_data_descriptor_t *              dst,
    globus_xio_data_descriptor_t                src)
{
    globus_i_xio_op_t *                         op_src;
    globus_i_xio_op_t *                         op_dst;
    globus_result_t                             res;
    int                                         ctr;
    int                                         ctr2;
    int                                         tmp_size;
    GlobusXIOName(globus_xio_data_descriptor_copy);

    if(dst == NULL)
    {
        return GlobusXIOErrorParameter("dst");
    }

    if(src == NULL)
    {
        return GlobusXIOErrorParameter("src");
    }

    op_src = src;

    res = globus_xio_data_descriptor_init(&op_dst, op_src->_op_handle);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
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

            return res;
        }
    }

    *dst = op_dst;

    return GLOBUS_SUCCESS;
}

/************************************************************************
 *                  stack functions
 ***********************************************************************/
globus_result_t
globus_xio_stack_init(
    globus_xio_stack_t *                        stack,
    globus_xio_attr_t                           stack_attr)
{
    globus_i_xio_stack_t *                      xio_stack;
    GlobusXIOName(globus_xio_stack_init);

    if(stack == NULL)
    {
        return GlobusXIOErrorParameter("stack");
    }

    xio_stack = globus_malloc(sizeof(globus_i_xio_stack_t));
    memset(xio_stack, '\0', sizeof(globus_i_xio_stack_t));
    globus_mutex_init(&xio_stack->mutex, NULL);

    *stack = xio_stack;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_stack_push_driver(
    globus_xio_stack_t                          stack,
    globus_xio_driver_t                         driver)
{
    globus_i_xio_stack_t *                      xio_stack;
    globus_result_t                             res = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_stack_push_driver);

    if(stack == NULL)
    {
        return GlobusXIOErrorParameter("stack");
    }
    if(driver == NULL)
    {
        return GlobusXIOErrorParameter("driver");
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

    return res;
}

globus_result_t
globus_xio_stack_destroy(
    globus_xio_stack_t                          stack)
{
    GlobusXIOName(globus_xio_stack_destroy);

    if(stack == NULL)
    {
        return GlobusXIOErrorParameter("stack");
    }

    globus_mutex_destroy(&stack->mutex);
    globus_list_free(stack->driver_stack);
    globus_free(stack);

    return GLOBUS_SUCCESS;
}
