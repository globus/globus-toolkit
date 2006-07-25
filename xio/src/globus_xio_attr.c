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

#include "globus_common.h"
#include "globus_i_xio.h"

globus_list_t *                         globus_i_xio_outstanding_attrs_list;
globus_list_t *                         globus_i_xio_outstanding_dds_list;

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
    globus_xio_attr_t *                 attr)
{
    globus_result_t                     res;
    globus_i_xio_attr_t *               xio_attr;
    GlobusXIOName(globus_xio_attr_init);

    GlobusXIODebugEnter();
    
    if(attr == NULL)
    {
        res = GlobusXIOErrorParameter("attr");
        goto err;
    }
   
    /* allocate the attr */ 
    xio_attr = (globus_i_xio_attr_t *)
                globus_calloc(sizeof(globus_i_xio_attr_t), 1);
    if(xio_attr == NULL)
    {
        res = GlobusXIOErrorMemory("attr");
        goto err;
    }

    xio_attr->entry = (globus_i_xio_attr_ent_t *)
        globus_calloc(sizeof(globus_i_xio_attr_ent_t) *
            GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE, 1);
    if(xio_attr->entry == NULL)
    {
        *attr = GLOBUS_NULL;
        globus_free(xio_attr);
        res = GlobusXIOErrorMemory("attr->entry");
        goto err;
    }

    /* zero it out */
    xio_attr->max = GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE;
    xio_attr->space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    
    globus_mutex_lock(&globus_i_xio_mutex);
    {
        globus_list_insert(&globus_i_xio_outstanding_attrs_list, xio_attr);
    }
    globus_mutex_unlock(&globus_i_xio_mutex);
    
    *attr = xio_attr;

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *
 */
globus_result_t
globus_xio_attr_cntl(
    globus_xio_attr_t                   user_attr,
    globus_xio_driver_t                 driver,
    int                                 cmd,
    ...)
{
    va_list                             ap;
    globus_result_t                     res;
    globus_i_xio_attr_t *               attr;
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

    res = globus_i_xio_driver_attr_cntl(attr, driver, cmd, ap);
    if(res != GLOBUS_SUCCESS)
    {
        va_end(ap);
        goto err;
    }

    va_end(ap);

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

/*
 *
 */
globus_result_t
globus_xio_attr_destroy(
    globus_xio_attr_t                   attr)
{
    int                                 ctr;
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_result_t                     tmp_res;
    GlobusXIOName(globus_xio_attr_destroy);

    GlobusXIODebugEnter();
    
    if(attr == NULL)
    {
        res = GlobusXIOErrorParameter("attr");
        goto err;
    }
    
    globus_mutex_lock(&globus_i_xio_mutex);
    {
        if(!attr->unloaded)
        {
            for(ctr = 0; ctr < attr->ndx; ctr++)
            {
                GlobusXIODebugPrintf(
                    GLOBUS_XIO_DEBUG_INFO_VERBOSE, 
                    (_XIOSL("[globus_xio_attr_destroy]: destroying attr @0x%x "
                        "driver @0x%x, %s\n"), 
                    attr,
                    attr->entry[ctr].driver,
                    attr->entry[ctr].driver->name));
                                
                /* report the last seen error but be sure to attempt to clean 
                    them all */
                tmp_res = attr->entry[ctr].driver->attr_destroy_func(
                        attr->entry[ctr].driver_data);
                if(tmp_res != GLOBUS_SUCCESS)
                {
                    res = tmp_res;
                }
            }
            
            globus_list_remove(
                &globus_i_xio_outstanding_attrs_list,
                globus_list_search(
                    globus_i_xio_outstanding_attrs_list, attr));
        }
    }
    globus_mutex_unlock(&globus_i_xio_mutex);
    
    globus_callback_space_destroy(attr->space);
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
    globus_xio_attr_t *                 dst,
    globus_xio_attr_t                   src)
{
    globus_i_xio_attr_t *               xio_attr_src;
    globus_i_xio_attr_t *               xio_attr_dst;
    globus_result_t                     res;
    int                                 ctr;
    int                                 ctr2;
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
    xio_attr_dst->space = xio_attr_src->space;
    globus_callback_space_reference(xio_attr_dst->space);

    xio_attr_dst->open_timeout_cb = xio_attr_src->open_timeout_cb;
    xio_attr_dst->open_timeout_period = xio_attr_src->open_timeout_period;
    xio_attr_dst->read_timeout_cb = xio_attr_src->read_timeout_cb;
    xio_attr_dst->read_timeout_period = xio_attr_src->read_timeout_period;
    xio_attr_dst->write_timeout_cb = xio_attr_src->write_timeout_cb;
    xio_attr_dst->write_timeout_period = xio_attr_src->write_timeout_period;
    xio_attr_dst->close_timeout_cb = xio_attr_src->close_timeout_cb;
    xio_attr_dst->close_timeout_period = xio_attr_src->close_timeout_period;
    xio_attr_dst->accept_timeout_cb = xio_attr_src->accept_timeout_cb;
    xio_attr_dst->accept_timeout_period = xio_attr_src->accept_timeout_period;
    xio_attr_dst->cancel_open = xio_attr_src->cancel_open;
    xio_attr_dst->cancel_close = xio_attr_src->cancel_close;
    xio_attr_dst->cancel_read = xio_attr_src->cancel_read;
    xio_attr_dst->cancel_write = xio_attr_src->cancel_write;
    xio_attr_dst->no_cancel = xio_attr_src->no_cancel;
    xio_attr_dst->timeout_arg = xio_attr_src->timeout_arg;
    
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
    
    globus_mutex_lock(&globus_i_xio_mutex);
    {
        globus_list_insert(&globus_i_xio_outstanding_attrs_list, xio_attr_dst);
    }
    globus_mutex_unlock(&globus_i_xio_mutex);
    
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
    globus_xio_data_descriptor_t *      data_desc,
    globus_xio_handle_t                 handle)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                 op;
    globus_i_xio_context_t *            context;
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
    globus_mutex_lock(&context->mutex);
    {
        GlobusXIOOperationCreate(op, context);
        if(op != NULL)
        {
            op->type = GLOBUS_XIO_OPERATION_TYPE_DD;
            handle->ref++;
            op->_op_handle = handle;
            op->ref = 1;
            op->is_user_dd = GLOBUS_TRUE;
        }
        else
        {
            res = GlobusXIOErrorMemory("xio_dd");
        }
    }
    globus_mutex_unlock(&context->mutex);

    if(res != GLOBUS_SUCCESS)
    {
        goto err;
    }
    *data_desc = op;
    
    globus_mutex_lock(&globus_i_xio_mutex);
    {
        globus_list_insert(&globus_i_xio_outstanding_dds_list, op);
    }
    globus_mutex_unlock(&globus_i_xio_mutex);
    
    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    *data_desc = NULL;
    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_data_descriptor_destroy(
    globus_xio_data_descriptor_t        data_desc)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    globus_i_xio_op_t *                 op;
    globus_i_xio_handle_t *             handle;
    globus_bool_t                       destroy_handle = GLOBUS_FALSE;
    globus_list_t *                     node;
    GlobusXIOName(globus_xio_data_descriptor_destroy);

    GlobusXIODebugEnter();
    
    if(data_desc == NULL)
    {
        res = GlobusXIOErrorParameter("data_desc");
        goto err;
    }

    op = (globus_i_xio_op_t *) data_desc;

    globus_mutex_lock(&globus_i_xio_mutex);
    {
        /* make sure we haven't destroyed it already */
        node = globus_list_search(globus_i_xio_outstanding_dds_list, op);
        if(node)
        {
            globus_list_remove(&globus_i_xio_outstanding_dds_list, node);
        }
    }
    globus_mutex_unlock(&globus_i_xio_mutex);
    
    if(node == NULL)
    {
        res = GlobusXIOErrorParameter("data_desc already destroyed");
        goto err;
    }
    
    handle = op->_op_handle;
    
    globus_mutex_lock(&handle->context->mutex);
    {
        GlobusXIOOpDec(op);
        if(op->ref == 0)
        {
            globus_i_xio_op_destroy(op, &destroy_handle);
        }
    }
    globus_mutex_unlock(&handle->context->mutex);
    
    if(destroy_handle)
    {
        globus_i_xio_handle_destroy(handle);
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_data_descriptor_cntl(
    globus_xio_data_descriptor_t        data_desc,
    globus_xio_driver_t                 driver,
    int                                 cmd,
    ...)
{
    globus_result_t                     res;
    globus_i_xio_op_t *                 op;
    va_list                             ap;
    GlobusXIOName(globus_xio_data_descriptor_cntl);

    GlobusXIODebugEnter();
    
    if(data_desc == NULL)
    {
        res = GlobusXIOErrorParameter("data_desc");
        goto err;
    }

    op = (globus_i_xio_op_t *) data_desc;

#   ifdef HAVE_STDARG_H
    {
        va_start(ap, cmd);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    res = globus_i_xio_driver_dd_cntl(op, driver, op->type, cmd, ap);

    va_end(ap);

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
globus_xio_data_descriptor_copy(
    globus_xio_data_descriptor_t *      dst,
    globus_xio_data_descriptor_t        src)
{
    globus_i_xio_op_t *                 op_src;
    globus_i_xio_op_t *                 op_dst;
    globus_result_t                     res;
    int                                 ctr;
    int                                 ctr2;
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

            goto err_destroy_op;
        }
    }

    *dst = op_dst;

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

  err_destroy_op:
    globus_xio_data_descriptor_destroy(op_dst);
    
  err:

    GlobusXIODebugExitWithError();
    return res;
}

/************************************************************************
 *                  stack functions
 ***********************************************************************/
globus_result_t
globus_xio_stack_init(
    globus_xio_stack_t *                stack,
    globus_xio_attr_t                   stack_attr)
{
    globus_i_xio_stack_t *              xio_stack;
    GlobusXIOName(globus_xio_stack_init);

    GlobusXIODebugEnter();
    
    if(stack == NULL)
    {
        GlobusXIODebugExitWithError();
        return GlobusXIOErrorParameter("stack");
    }

    xio_stack = globus_malloc(sizeof(globus_i_xio_stack_t));
    memset(xio_stack, '\0', sizeof(globus_i_xio_stack_t));

    *stack = xio_stack;

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_stack_copy(
    globus_xio_stack_t *                dst,
    globus_xio_stack_t                  src)
{
    globus_i_xio_stack_t *		xio_stack_src;
    globus_i_xio_stack_t *		xio_stack_dst;
    globus_result_t                     res;
    GlobusXIOName(globus_xio_stack_push_driver);
                    
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

    xio_stack_src = src;

    xio_stack_dst = (globus_i_xio_stack_t *)
        globus_calloc(1, sizeof(globus_i_xio_stack_t));

    /* check for memory alloc failure */
    if(xio_stack_dst == NULL)
    {
        res = GlobusXIOErrorMemory("xio_stack_dst");
        goto err;
    }

    xio_stack_dst->size = xio_stack_src->size;
    xio_stack_dst->driver_stack = globus_list_copy(
					xio_stack_src->driver_stack);
    *dst = xio_stack_dst;

    GlobusXIODebugExit();

    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_stack_push_driver(
    globus_xio_stack_t                  stack,
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_t                 p_d;
    globus_i_xio_stack_t *              xio_stack;
    globus_result_t                     res = GLOBUS_SUCCESS;
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

    /* if in the transport position and has a push stack */
    if(driver->push_driver_func != NULL && xio_stack->pushing_driver != driver)
    {
        p_d = xio_stack->pushing_driver;
        xio_stack->pushing_driver = driver;
        res = driver->push_driver_func(driver, xio_stack);
        xio_stack->pushing_driver = p_d;
        if(res != GLOBUS_SUCCESS)
        {
            goto err;
        }
    }
    /* if a transport driver position */
    else if(xio_stack->size == 0)
    {
        if(driver->transport_open_func == NULL)
        {
            res = GlobusXIOErrorInvalidDriver(
                _XIOSL("open function not defined"));
            goto err;
        }
        else
        {
            xio_stack->size++;
            globus_list_insert(&xio_stack->driver_stack, driver);
        }
    }
    else if(driver->transport_open_func != NULL)
    {
        res = GlobusXIOErrorInvalidDriver(
            _XIOSL("transport can only be at bottom of stack"));
        goto err;
    }
    else
    {
        xio_stack->size++;
        globus_list_insert(&xio_stack->driver_stack, driver);
    }

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

globus_result_t
globus_xio_stack_destroy(
    globus_xio_stack_t                  stack)
{
    globus_result_t                     res;
    GlobusXIOName(globus_xio_stack_destroy);

    GlobusXIODebugEnter();
    
    if(stack == NULL)
    {
        res = GlobusXIOErrorParameter("stack");
        goto err;
    }

    globus_list_free(stack->driver_stack);
    globus_free(stack);

    GlobusXIODebugExit();
    return GLOBUS_SUCCESS;

  err:

    GlobusXIODebugExitWithError();
    return res;
}

/* STRING PARSING ATTR SETTING */
void
globus_i_xio_string_cntl_parser(
    const char *                        env_str,
    globus_xio_string_cntl_table_t *    table,
    void *                              attr,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    int                                 i;
    char *                              key;
    char *                              val;
    char *                              tmp_s;
    globus_list_t *                     list;

    list = globus_list_from_string(env_str, '#', NULL);

    while(!globus_list_empty(list))
    {
        key = globus_list_first(list);

        tmp_s = strchr(key, '=');
        if(tmp_s != NULL)
        {
            *tmp_s = '\0';
            val = tmp_s + 1;

            for(i = 0; table[i].key != NULL; i++)
            {
                /* if we have a match */
                if(strcmp(table[i].key, key) == 0)
                {
                    table[i].parse_func(attr, key, val, table[i].cmd, cntl_func);
                }
            }
        }
        globus_free(key);
        list = globus_list_rest(list);
    }
}

globus_result_t
globus_xio_string_cntl_bouncer(
    globus_xio_driver_attr_cntl_t       cntl_func,
    void *                              attr,
    int                                 cmd,
    ...)
{
    globus_result_t                     result;
    va_list                             ap;

    va_start(ap, cmd);
    result = cntl_func(attr, cmd, ap);
    va_end(ap);

    return result;
}

static
int
globus_xio_string_cntl_tb_kmgint(
    const char *                        arg,
    globus_off_t *                      out_i)
{
    int                                 i;
    int                                 sc;
    GlobusXIOName(globus_xio_string_cntl_tb_kmgint);

    GlobusXIODebugEnter();

    sc = sscanf(arg, "%d", &i);
    if(sc != 1)
    {
        return 1;
    }
    if(strchr(arg, 'K') != NULL)
    {
        *out_i = (globus_off_t)i * 1024;
    }
    else if(strchr(arg, 'M') != NULL)
    {
        *out_i = (globus_off_t)i * 1024 * 1024;
    }
    else if(strchr(arg, 'G') != NULL)
    {
        *out_i = (globus_off_t)i * 1024 * 1024 * 1024;
    }
    else
    {
        *out_i = (globus_off_t)i;
    }

    return 0;
}

globus_result_t
globus_xio_string_cntl_formated_off(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    int                                 sc;
    globus_off_t                        o;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_string_cntl_formated_off);

    GlobusXIODebugEnter();

    sc = globus_xio_string_cntl_tb_kmgint(val, &o);
    if(sc != 0)
    {
        result = GlobusXIOErrorParse(val);
    }
    else
    {
        result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, o);
    }
    GlobusXIODebugExit();

    return result;
}

globus_result_t
globus_xio_string_cntl_formated_int(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    int                                 sc;
    int                                 i;
    globus_off_t                        o;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_string_cntl_formated_int);

    GlobusXIODebugEnter();

    sc = globus_xio_string_cntl_tb_kmgint(val, &o);
    if(sc != 0)
    {
        result = GlobusXIOErrorParse(val);
    }
    else
    {
        i = (int) o;
        result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, i);
    }
    GlobusXIODebugExit();
    return result;
}

globus_result_t
globus_xio_string_cntl_int(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    int                                 sc;
    int                                 i;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_string_cntl_int);

    GlobusXIODebugEnter();

    sc = sscanf(val, "%d", &i);
    if(sc != 1)
    {
        result = GlobusXIOErrorParse(val);
    }
    else
    {
        result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, i);
    }
    GlobusXIODebugExit();
    return result;
}

globus_result_t
globus_xio_string_cntl_int_int(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    int                                 sc;
    int                                 i;
    int                                 j;
    char *                              tmp_s;
    char *                              new_val;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_string_cntl_int_int);

    GlobusXIODebugEnter();

    /* turn all non digits into spaces for the scanf easiness */
    tmp_s = strdup(val);
    if(tmp_s == NULL)
    {
        result = GlobusXIOErrorParse(val);
        return result;
    }
    new_val = tmp_s;
    while(*tmp_s != '\0')
    {
        if(!isdigit(*tmp_s))
        {
            *tmp_s = ' ';
        }
        tmp_s++;
    }

    sc = sscanf(new_val, "%d %d", &i, &j);
    free(new_val);
    if(sc != 2)
    {
        result = GlobusXIOErrorParse(val);
    }
    else
    {
        result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, i, j);
    }
    GlobusXIODebugExit();
    return result;
}

globus_result_t
globus_xio_string_cntl_float(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    int                                 sc;
    float                               f;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_string_cntl_float);

    GlobusXIODebugEnter();

    sc = sscanf(val, "%f", &f);
    if(sc != 1)
    {
        result = GlobusXIOErrorParse(val);
    }
    else
    {
        result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, f);
    }
    GlobusXIODebugExit();
    return result;
}

globus_result_t
globus_xio_string_cntl_string(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_string_cntl_string);

    GlobusXIODebugEnter();

    result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, val);

    GlobusXIODebugExit();
    return result;
}

globus_result_t
globus_xio_string_cntl_bool(
    void *                              attr,
    const char *                        key,
    const char *                        val,
    int                                 cmd,
    globus_xio_driver_attr_cntl_t       cntl_func)
{
    int                                 sc;
    int                                 i;
    globus_bool_t                       found = GLOBUS_FALSE;
    globus_bool_t                       b;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusXIOName(globus_xio_string_cntl_bool);

    GlobusXIODebugEnter();

    if(strcasecmp(val, "yes") == 0)
    {
        b = GLOBUS_TRUE;
        found = GLOBUS_TRUE;
    }
    else if(strcasecmp(val, "y") == 0)
    {
        b = GLOBUS_TRUE;
        found = GLOBUS_TRUE;
    }
    else if(strcasecmp(val, "true") == 0)
    {
        b = GLOBUS_TRUE;
        found = GLOBUS_TRUE;
    }
    else if(strcasecmp(val, "t") == 0)
    {
        b = GLOBUS_TRUE;
        found = GLOBUS_TRUE;
    }
    else if(strcasecmp(val, "no") == 0)
    {
        b = GLOBUS_FALSE;
        found = GLOBUS_TRUE;
    }
    else if(strcasecmp(val, "n") == 0)
    {
        b = GLOBUS_FALSE;
        found = GLOBUS_TRUE;
    }
    else if(strcasecmp(val, "false") == 0)
    {
        b = GLOBUS_FALSE;
        found = GLOBUS_TRUE;
    }
    else if(strcasecmp(val, "f") == 0)
    {
        b = GLOBUS_FALSE;
        found = GLOBUS_TRUE;
    }
    else
    {
        sc = sscanf(val, "%d", &i);
        if(sc == 1)
        {
            b = i;
            found = GLOBUS_TRUE;
        }
    }
    if(found)
    {
        result = globus_xio_string_cntl_bouncer(cntl_func, attr, cmd, b);
    }
    else
    {
        result = GlobusXIOErrorParse(val);
    }

    GlobusXIODebugExit();
    return result;
}


