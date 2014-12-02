/*
 * Copyright 1999-2014 University of Chicago
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
#include "globus_xio_net_manager_driver.h"

#include "globus_net_manager.h"
#include "globus_net_manager_context.h"

GlobusDebugDefine(GLOBUS_XIO_NET_MANAGER);
GlobusXIODeclareDriver(net_manager);

#define GlobusXIONetManagerDebugPrintf(level, message)                  \
    GlobusDebugPrintf(GLOBUS_XIO_NET_MANAGER, level, message)

#define GlobusXIONetManagerDebugEnter()                                 \
    GlobusXIONetManagerDebugPrintf(                                     \
        GLOBUS_XIO_NET_MANAGER_DEBUG_TRACE,                              \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIONetManagerDebugExit()                                  \
    GlobusXIONetManagerDebugPrintf(                                     \
        GLOBUS_XIO_NET_MANAGER_DEBUG_TRACE,                              \
        ("[%s] Exiting\n", _xio_name))

typedef enum
{
    GLOBUS_XIO_NET_MANAGER_DEBUG_ERROR = 1,
    GLOBUS_XIO_NET_MANAGER_DEBUG_WARNING = 2,
    GLOBUS_XIO_NET_MANAGER_DEBUG_TRACE = 4,
    GLOBUS_XIO_NET_MANAGER_DEBUG_INFO = 8,
} globus_xio_net_manager_debug_levels_t;

typedef struct
{
    globus_net_manager_attr_t          *attr_array;
    char                               *task_id;
    globus_net_manager_context_t        context;
}
globus_l_xio_net_manager_attr_t;

static
int
globus_l_xio_net_manager_activate(void);

static
int
globus_l_xio_net_manager_deactivate(void);

#include "version.h"

GlobusXIODefineModule(net_manager) =
{
    "globus_xio_net_manager",
    globus_l_xio_net_manager_activate,
    globus_l_xio_net_manager_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
void
globus_l_xio_net_manager_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_finished_open(NULL, op, result);
}

static
globus_result_t
globus_l_xio_net_manager_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_net_manager_open_cb, NULL);
    return res;
}

static
void
globus_l_xio_net_manager_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_xio_driver_finished_close(op, result);
}

static
globus_result_t
globus_l_xio_net_manager_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    res = globus_xio_driver_pass_close(
        op, globus_l_xio_net_manager_close_cb, NULL);
    return res;
}

static
void
globus_l_xio_net_manager_read_cb(
    struct globus_i_xio_op_s *          op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_read(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_net_manager_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_size_t                       wait_for;
    globus_result_t                     res;

    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_read(
        op, (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_net_manager_read_cb, NULL);
    return res;
}

static
globus_result_t
globus_l_xio_net_manager_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_write(
        op, (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        NULL, NULL);

    return res;
}

static
globus_result_t
globus_l_xio_net_manager_attr_init(
    void                              **attr)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_xio_net_manager_attr_t    *a;

    a = malloc(sizeof(globus_l_xio_net_manager_attr_t));
    if (!a)
    {
        result = GLOBUS_FAILURE;
        goto malloc_attr_exit;
    }

    a->attr_array = NULL;
    a->task_id = NULL;
    a->context = NULL;

malloc_attr_exit:
    *attr = a;
    return result;
}
/* globus_l_xio_net_manager_attr_init() */

static
globus_result_t
globus_l_xio_net_manager_attr_copy(
    void                              **dest,
    void                               *src)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_xio_net_manager_attr_t    *s = src, *d;

    if (!dest)
    {
        result = GLOBUS_FAILURE;
        goto null_dest;
    }
    if (!s)
    {
        result = GLOBUS_FAILURE;
        goto null_src;
    }
    d = malloc(sizeof(globus_l_xio_net_manager_attr_t));
    if (!d)
    {
        result = GLOBUS_FAILURE;
        goto malloc_d_failed;
    }
    d->task_id = NULL;
    if (s->task_id)
    {
        d->task_id = strdup(s->task_id);
        if (!d->task_id)
        {
            result = GLOBUS_FAILURE;
            goto strdup_task_id_failed;
        }
    }

    result = globus_net_manager_attr_array_copy(
            &d->attr_array,
            s->attr_array);
    if (result)
    {
        goto attr_array_copy_failed;
    }
    result = globus_net_manager_context_init(
            &d->context,
            d->attr_array);
    if (result)
    {
attr_array_copy_failed:
        free(d->task_id);
strdup_task_id_failed:
        free(d);
malloc_d_failed:
null_src:
        *dest = NULL;
null_dest:
        ;
    }
    return result;
}
/* globus_l_xio_net_manager_attr_copy() */

static
inline
globus_result_t
globus_l_xio_net_manager_attr_set_string_options(
    globus_l_xio_net_manager_attr_t    *attr,
    const char                         *options_string)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_list_t                      *options;
    int                                 num_options;
    globus_net_manager_attr_t          *new_attrs;
    char                               *scope = NULL;
    char                               *new_task_id = NULL;
    globus_net_manager_context_t        new_context = NULL;
    size_t                              attrnum = 0;

    options = globus_list_from_string(options_string, ';', NULL);
    num_options = globus_list_size(options);

    if (num_options == 0)
    {
        goto no_options;
    }
    new_attrs = calloc(num_options+1, sizeof(globus_net_manager_attr_t));
    if (!new_attrs)
    {
        result = GLOBUS_FAILURE;
        goto new_attrs_calloc_fail;
    }
    while (!globus_list_empty(options))
    {
        char                           *opt, *val;

        opt = globus_list_remove(&options, options);
        val = strchr(opt, '=');
        if (!val)
        {
            result = GLOBUS_FAILURE;
            free(opt);
            goto no_equals;
        }
        *val++ = '\0';

        if (strcmp(opt, "manager") == 0)
        {
            free(scope);
            scope = strdup(val);
            if (!scope)
            {
                result = GLOBUS_FAILURE;
                free(opt);
                new_attrs[attrnum++] = globus_net_manager_null_attr;
                goto strdup_scope_fail;
            }
        }
        else
        {
            if (strcmp(opt, "task-id") == 0)
            {
                new_task_id = strdup(val);
                if (!new_task_id)
                {
                    result = GLOBUS_FAILURE;
                    free(opt);
                    new_attrs[attrnum++] = globus_net_manager_null_attr;
                    goto strdup_task_id_fail;
                }
            }
            else
            {
                if (!scope)
                {
                    result = GLOBUS_FAILURE;
                    free(opt);
                    new_attrs[attrnum++] = globus_net_manager_null_attr;
                    goto no_scope;
                }
                result = globus_net_manager_attr_init(
                        &new_attrs[attrnum++],
                        scope,
                        opt,
                        val);
                if (!result)
                {
                    free(opt);
                    new_attrs[attrnum-1] = globus_net_manager_null_attr;
                    goto new_attr_init_fail;
                }
            }
        }
        free(opt);
    }
    new_attrs[attrnum++] = globus_net_manager_null_attr;
    if (new_attrs)
    {
        result = globus_net_manager_context_init(
                    &new_context,
                    new_attrs);
        if (result)
        {
            goto new_context_init_fail;
        }
    }
    if (new_task_id)
    {
        free(attr->task_id);
        attr->task_id = new_task_id;
        new_task_id = NULL;
    }
    if (new_attrs)
    {
        globus_net_manager_attr_array_delete(attr->attr_array);
        attr->attr_array = new_attrs;
        new_attrs = NULL;

        globus_net_manager_context_destroy(&attr->context);
        attr->context = new_context;
        new_context = NULL;
    }

new_context_init_fail:
new_attr_init_fail:
strdup_task_id_fail:
strdup_scope_fail:
no_scope:
no_equals:
    free(new_task_id);
    free(scope);
    globus_net_manager_attr_array_delete(new_attrs);
new_attrs_calloc_fail:
    globus_list_destroy_all(options, free);
no_options:
    return result;
}
/* globus_l_xio_net_manager_attr_set_string_options() */

static
inline
globus_result_t
globus_l_xio_net_manager_attr_get_string_options(
    globus_l_xio_net_manager_attr_t    *attr,
    char                              **out_string)
{
    size_t                              out_len = 0;
    const char                         *prev_scope = NULL;
    char                               *output = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    if (attr->task_id)
    {
        out_len += snprintf(NULL, 0, "task-id=%s;", attr->task_id);
    }
    if (attr->attr_array)
    {
        for (int i = 0; attr->attr_array[0].scope != NULL; i++)
        {
            if ((!prev_scope) || strcmp(attr->attr_array[i].scope, prev_scope))
            {
                out_len += snprintf(NULL, 0, "manager=%s;",
                        attr->attr_array[i].scope);
                prev_scope = attr->attr_array[i].scope;
            }
            out_len += snprintf(NULL, 0, "%s=%s;",
                        attr->attr_array[i].name,
                        attr->attr_array[i].value);
        }
    }
    output = malloc(out_len);
    if (!output)
    {
        result = GLOBUS_FAILURE;
        goto output_malloc_fail;
    }
    out_len = 0;
    if (attr->task_id)
    {
        out_len += sprintf(output + out_len, "task-id=%s;", attr->task_id);
    }
    if (attr->attr_array)
    {
        for (int i = 0; attr->attr_array[i].scope != NULL; i++)
        {
            if ((!prev_scope) || strcmp(attr->attr_array[i].scope, prev_scope))
            {
                out_len += sprintf(output + out_len, "manager=%s;",
                        attr->attr_array[i].scope);
                prev_scope = attr->attr_array[i].scope;
            }
            out_len += sprintf(output + out_len, "%s=%s;",
                        attr->attr_array[i].name,
                        attr->attr_array[i].value);
        }
    }
output_malloc_fail:
    *out_string = output;
    return result;
}
/* globus_l_xio_net_manager_attr_get_string_options() */

static
inline
globus_result_t
globus_l_xio_net_manager_pre_listen(
    globus_l_xio_net_manager_attr_t    *attr)
{
    return GLOBUS_FAILURE;
}
/* globus_l_xio_net_manager_pre_listen() */

static
inline
globus_result_t
globus_l_xio_net_manager_set_task_id(
    globus_l_xio_net_manager_attr_t    *attr,
    const char                         *in_string)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *new_task_id = NULL;

    if (in_string)
    {
        new_task_id = strdup(in_string);
        if (!new_task_id)
        {
            result = GLOBUS_FAILURE;
            goto strdup_task_id_fail;
        }
    }
    free(attr->task_id);
    attr->task_id = new_task_id;

strdup_task_id_fail:
    return result;
}
/* globus_l_xio_net_manager_set_task_id() */

static
inline
globus_result_t
globus_l_xio_net_manager_get_task_id(
    globus_l_xio_net_manager_attr_t    *attr,
    char                              **out_string)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    if (!out_string)
    {
        result = GLOBUS_FAILURE;
        goto null_out_string;
    }
    if (attr->task_id)
    {
        *out_string = strdup(attr->task_id);
        if (!*out_string)
        {
            result = GLOBUS_FAILURE;
            goto strdup_task_id_fail;
        }
    }
    else
    {
        *out_string = NULL;
    }

strdup_task_id_fail:
null_out_string:
    return result;
}
/* globus_l_xio_net_manager_set_task_id() */

static
globus_result_t
globus_l_xio_net_manager_attr_cntl(
    void                               *attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    const char                         *const_in_string;
    char                              **out_string;
    const char                        **const_out_string;

    if (!attr)
    {
        result = GLOBUS_FAILURE;
        goto null_attr;
    }
    
    switch (cmd)
    {
        case GLOBUS_XIO_SET_STRING_OPTIONS:
            const_in_string = va_arg(ap, const char *);
            if (const_in_string)
            {
                result = globus_l_xio_net_manager_attr_set_string_options(
                        attr, const_in_string);
            }
            break;
        case GLOBUS_XIO_GET_STRING_OPTIONS:
            out_string = va_arg(ap, char **);
            if (!out_string)
            {
                result = GLOBUS_FAILURE;
                break;
            }
            result = globus_l_xio_net_manager_attr_get_string_options(
                    attr, out_string);
            break;

        case GLOBUS_XIO_GET_DRIVER_NAME:
            const_out_string = va_arg(ap, const char **);
            if (!const_out_string)
            {
                result = GLOBUS_FAILURE;
                goto fail_get_driver_name;
            }
            *const_out_string = "net_manager";
            break;

        case GLOBUS_XIO_NET_MANAGER_PRE_LISTEN:
            result = globus_l_xio_net_manager_pre_listen(attr);
            break;
        case GLOBUS_XIO_NET_MANAGER_SET_TASK_ID:
            const_in_string = va_arg(ap, char *);
            result = globus_l_xio_net_manager_set_task_id(
                    attr, const_in_string);
            break;
        case GLOBUS_XIO_NET_MANAGER_GET_TASK_ID:
            out_string = va_arg(ap, char **);
            result = globus_l_xio_net_manager_get_task_id(attr, out_string);
            break;
        default:
            result = GLOBUS_FAILURE;
    }

fail_get_driver_name:
null_attr:
    return result;
}
/* globus_l_xio_net_manager_attr_cntl() */

static
globus_result_t
globus_l_xio_net_manager_attr_destroy(
    void                               *attr)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_xio_net_manager_attr_t    *a = attr;

    if (!a)
    {
        result = GLOBUS_FAILURE;
        goto null_a_exit;
    }
    globus_net_manager_attr_array_delete(a->attr_array);
    free(a->task_id);
    globus_net_manager_context_destroy(&a->context);

null_a_exit:
    return result;
}

static
globus_result_t
globus_l_xio_net_manager_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "net_manager", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_net_manager_open,
        globus_l_xio_net_manager_close,
        globus_l_xio_net_manager_read,
        globus_l_xio_net_manager_write,
        NULL,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_net_manager_attr_init,
        globus_l_xio_net_manager_attr_copy,
        globus_l_xio_net_manager_attr_cntl,
        globus_l_xio_net_manager_attr_destroy);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_net_manager_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    net_manager,
    globus_l_xio_net_manager_init,
    globus_l_xio_net_manager_destroy);

static
int
globus_l_xio_net_manager_activate(void)
{
    int                                 rc;

    GlobusDebugInit(GLOBUS_XIO_NET_MANAGER, TRACE);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto activate_xio_fail;
    }
    rc = globus_module_activate(GLOBUS_NET_MANAGER_MODULE);

    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(net_manager);
    }
    else
    {
        globus_module_deactivate(GLOBUS_XIO_MODULE);
    }

activate_xio_fail:
    return rc;
}

static
int
globus_l_xio_net_manager_deactivate(void)
{
    GlobusXIOUnRegisterDriver(net_manager);
    globus_module_deactivate(GLOBUS_NET_MANAGER_MODULE);
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 0;
}
