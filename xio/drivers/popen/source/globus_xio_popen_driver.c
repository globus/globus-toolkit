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
#include "globus_xio_popen_driver.h"
#include "version.h"
#include <stdio.h>

GlobusDebugDefine(GLOBUS_XIO_POPEN);

#define GlobusXIOPOpenDebugPrintf(level, message)                            \
    GlobusDebugPrintf(GLOBUS_XIO_POPEN, level, message)

#define GlobusXIOPOpenDebugEnter()                                           \
    GlobusXIOPOpenDebugPrintf(                                               \
        GLOBUS_L_XIO_POPEN_DEBUG_TRACE,                                      \
        (_XIOSL("[%s] Entering\n"), _xio_name))
        
#define GlobusXIOPOpenDebugExit()                                            \
    GlobusXIOPOpenDebugPrintf(                                               \
        GLOBUS_L_XIO_POPEN_DEBUG_TRACE,                                      \
        (_XIOSL("[%s] Exiting\n"), _xio_name))

#define GlobusXIOPOpenDebugExitWithError()                                   \
    GlobusXIOPOpenDebugPrintf(                                               \
        GLOBUS_L_XIO_POPEN_DEBUG_TRACE,                                      \
        (_XIOSL("[%s] Exiting with error\n"), _xio_name))

enum globus_l_xio_error_levels
{
    GLOBUS_L_XIO_POPEN_DEBUG_TRACE       = 1,
    GLOBUS_L_XIO_POPEN_DEBUG_INFO        = 2
};

static
int
globus_l_xio_popen_activate(void);

static
int
globus_l_xio_popen_deactivate(void);

GlobusXIODefineModule(popen) =
{
    "globus_xio_popen",
    globus_l_xio_popen_activate,
    globus_l_xio_popen_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*
 *  attribute structure
 */
typedef struct xio_l_popen_attr_s
{
    globus_bool_t                       use_blocking_io;
    globus_bool_t                       pass_env;
    char *                              program_name;
    char **                             argv;
    int                                 argc;
} xio_l_popen_attr_t;

/* default attr */
static const xio_l_popen_attr_t         xio_l_popen_attr_default =
{
    GLOBUS_FALSE,
    GLOBUS_FALSE,
    NULL,
    NULL,
    0
};

/*
 *  handle structure
 */
typedef struct xio_l_popen_handle_s
{
    globus_xio_system_file_handle_t     in_system;
    globus_xio_system_file_handle_t     out_system;
    globus_xio_system_file_t            infd;
    globus_xio_system_file_t            outfd;
    globus_bool_t                       use_blocking_io;
    globus_mutex_t                      lock; /* only used to protect below */
    globus_off_t                        file_position;
    pid_t                               pid;
} xio_l_popen_handle_t;

#define GlobusXIOPOpenPosition(handle)                                \
    globus_l_xio_popen_update_position(handle, 0, SEEK_CUR)

static
globus_off_t
globus_l_xio_popen_update_position(
    xio_l_popen_handle_t *              handle,
    globus_off_t                        offset,
    int                                 whence)
{
    globus_mutex_lock(&handle->lock);
    {
        handle->file_position += offset;
        offset = handle->file_position;
    }
    globus_mutex_unlock(&handle->lock);
    
    return offset;
}

static
globus_result_t
globus_l_xio_popen_attr_init(
    void **                             out_attr)
{
    xio_l_popen_attr_t *                attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_popen_attr_init);

    GlobusXIOPOpenDebugEnter();
    /*
     *  create a file attr structure and intialize its values
     */
    attr = (xio_l_popen_attr_t *) globus_malloc(sizeof(xio_l_popen_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }

    memcpy(attr, &xio_l_popen_attr_default, sizeof(xio_l_popen_attr_t));
    *out_attr = attr;

    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOPOpenDebugExitWithError();
    return result;
}

/*
 *  copy an attribute structure
 */
static
globus_result_t
globus_l_xio_popen_attr_copy(
    void **                             dst,
    void *                              src)
{
    xio_l_popen_attr_t *                attr;
    xio_l_popen_attr_t *                src_attr;
    globus_result_t                     result;
    int                                 i;
    GlobusXIOName(globus_l_xio_popen_attr_copy);

    GlobusXIOPOpenDebugEnter();

    src_attr = (xio_l_popen_attr_t *) src;
    attr = (xio_l_popen_attr_t *) globus_malloc(sizeof(xio_l_popen_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }

    memcpy(attr, src_attr, sizeof(xio_l_popen_attr_t));
    if(src_attr->program_name != NULL)
    {
        attr->program_name = strdup(src_attr->program_name);
    }
    if(src_attr->argc > 0)
    {
        attr->argv = (char **)globus_calloc(attr->argc+1, sizeof(char*));
        for(i = 0; i < attr->argc; i++)
        {
            attr->argv[i] = strdup(src_attr->argv[i]);
        }
        attr->argv[i] = NULL;
    }
    *dst = attr;

    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOPOpenDebugExitWithError();
    return result;
}

static
globus_result_t
globus_l_xio_popen_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    int                                 i;
    char **                             argv;
    xio_l_popen_attr_t *                attr;
    GlobusXIOName(globus_l_xio_popen_attr_cntl);

    GlobusXIOPOpenDebugEnter();

    attr = (xio_l_popen_attr_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_POPEN_SET_PROGRAM:
            attr->argc = va_arg(ap, int);
            argv = va_arg(ap, char **);
            attr->argv = calloc(attr->argc + 1, sizeof(char *));
            for(i = 0; i < attr->argc; i++)
            {
                attr->argv[i] = strdup(argv[i]);
            }
            attr->argv[i] = NULL;
            attr->program_name = strdup(attr->argv[0]);
            break;

        case GLOBUS_XIO_POPEN_SET_PASS_ENV:
            attr->pass_env = va_arg(ap, globus_bool_t);
            break;

        case GLOBUS_XIO_POPEN_SET_BLOCKING_IO:
            attr->use_blocking_io = va_arg(ap, globus_bool_t);
            break;

        default:
            break;
    }

    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_popen_attr_destroy(
    void *                              driver_attr)
{
    int                                 i;
    xio_l_popen_attr_t *                attr;
    GlobusXIOName(globus_l_xio_popen_attr_destroy);

    GlobusXIOPOpenDebugEnter();

    attr = (xio_l_popen_attr_t *) driver_attr;

    if(attr->argc > 0)
    {
        for(i = 0; i < attr->argc; i++)
        {
            free(attr->argv[i]);
        }
        free(attr->argv);
    }
    if(attr->program_name != NULL)
    {
        free(attr->program_name);
    }
    globus_free(driver_attr);

    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;
}




static
globus_result_t
globus_l_xio_popen_handle_init(
    xio_l_popen_handle_t **             handle)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_popen_handle_init);
    
    GlobusXIOPOpenDebugEnter();
    
    *handle = (xio_l_popen_handle_t *)
        globus_calloc(1, sizeof(xio_l_popen_handle_t));
    if(!*handle)
    {
        result = GlobusXIOErrorMemory("handle");
        goto error_handle;
    }
    
    globus_mutex_init(&(*handle)->lock, NULL);
    
    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;

error_handle:
    GlobusXIOPOpenDebugExitWithError();
    return result;    
}

static
void
globus_l_xio_popen_handle_destroy(
    xio_l_popen_handle_t *              handle)
{
    GlobusXIOName(globus_l_xio_popen_handle_destroy);
    
    GlobusXIOPOpenDebugEnter();
    
    globus_mutex_destroy(&handle->lock);
    globus_free(handle);
    
    GlobusXIOPOpenDebugExit();
}

static
void
globus_l_xio_popen_child(
    xio_l_popen_attr_t *                attr,
    const globus_xio_contact_t *        contact_info,
    int *                               infds,
    int *                               outfds)
{
    int                                 rc;

    close(outfds[1]);
    close(infds[0]);
    rc = dup2(outfds[0], STDIN_FILENO);
    if(rc < 0)
    {
        goto error;
    }
    rc = dup2(infds[1], STDOUT_FILENO);
    if(rc < 0)
    {
        goto error;
    }
    if(attr->pass_env)
    {
        rc = execv(attr->program_name, attr->argv);
    }
    else
    {
        char *                          env[] = {0};
        rc = execve(attr->program_name, attr->argv, env);
    }

error:
    exit(rc);
}

/*
 *  open a file
 */
static
globus_result_t
globus_l_xio_popen_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    int                                 rc;
    int                                 infds[2];
    int                                 outfds[2];
    xio_l_popen_handle_t *              handle;
    xio_l_popen_attr_t *                attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_popen_open);
    
    GlobusXIOPOpenDebugEnter();
    
    attr = (xio_l_popen_attr_t *) 
        driver_attr ? driver_attr : &xio_l_popen_attr_default;
    result = globus_l_xio_popen_handle_init(&handle);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_popen_handle_init", result);
        goto error_handle;
    }

    rc = pipe(infds);
    if(rc != 0)
    {
        result = GlobusXIOErrorSystemError("pipe", errno);
        goto error_in_pipe;
    }
    rc = pipe(outfds);
    if(rc != 0)
    {
        result = GlobusXIOErrorSystemError("pipe", errno);
        goto error_out_pipe;
    }

    handle->pid = fork();
    if(handle->pid == 0)
    {
        globus_l_xio_popen_child(attr, contact_info, infds, outfds);
    }
    fcntl(outfds[1], F_SETFD, FD_CLOEXEC);
    fcntl(infds[0], F_SETFD, FD_CLOEXEC);

    handle->infd = infds[0];
    handle->outfd = outfds[1];

    result = globus_xio_system_file_init(&handle->out_system, handle->outfd);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_xio_system_file_init", result);
        goto error_init;
    }
    result = globus_xio_system_file_init(&handle->in_system, handle->infd);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_xio_system_file_init", result);
        goto error_init;
    }
    
    close(outfds[0]);
    close(infds[1]);
    globus_xio_driver_finished_open(handle, op, GLOBUS_SUCCESS);
    
    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    close(outfds[0]);
    close(outfds[1]);
error_out_pipe:
    close(infds[0]);
    close(infds[1]);
error_in_pipe:
    globus_l_xio_popen_handle_destroy(handle);
error_handle:
    GlobusXIOPOpenDebugExitWithError();
    return result;
}

/*
 *  close a file
 */
static
globus_result_t
globus_l_xio_popen_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    xio_l_popen_handle_t *              handle;
    GlobusXIOName(globus_l_xio_popen_close);

    GlobusXIOPOpenDebugEnter();
    
    handle = (xio_l_popen_handle_t *) driver_specific_handle;
    
    globus_xio_system_file_destroy(handle->in_system);
    globus_xio_system_file_destroy(handle->out_system);
    
    globus_xio_system_file_close(handle->infd);
    globus_xio_system_file_close(handle->outfd);
    
    globus_xio_driver_finished_close(op, GLOBUS_SUCCESS);
    globus_l_xio_popen_handle_destroy(handle);
    
    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_popen_system_read_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_popen_system_read_cb);
    
    GlobusXIOPOpenDebugEnter();
    
    op = (globus_xio_operation_t) user_arg;
    
    globus_l_xio_popen_update_position(
        (xio_l_popen_handle_t *) globus_xio_operation_get_driver_specific(op),
        nbytes,
        SEEK_CUR);
        
    globus_xio_driver_finished_read(op, result, nbytes);
    
    GlobusXIOPOpenDebugExit();
}

/*
 *  read from a file
 */
static
globus_result_t
globus_l_xio_popen_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    xio_l_popen_handle_t *              handle;
    globus_size_t                       nbytes;
    globus_result_t                     result;
    globus_off_t                        offset;
    GlobusXIOName(globus_l_xio_popen_read);

    GlobusXIOPOpenDebugEnter();
    
    handle = (xio_l_popen_handle_t *) driver_specific_handle;
    
    offset = GlobusXIOPOpenPosition(handle);
            
    /* if buflen and waitfor are both 0, we behave like register select */
    if((globus_xio_operation_get_wait_for(op) == 0 &&
        (iovec_count > 1 || iovec[0].iov_len > 0)) ||
        (handle->use_blocking_io &&
        globus_xio_driver_operation_is_blocking(op)))
    {
        result = globus_xio_system_file_read(
            handle->in_system,
            offset,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            &nbytes);
        
        globus_l_xio_popen_update_position(handle, nbytes, SEEK_CUR);
        globus_xio_driver_finished_read(op, result, nbytes);
        result = GLOBUS_SUCCESS;
    }
    else
    {
        result = globus_xio_system_file_register_read(
            op,
            handle->in_system,
            offset,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            globus_l_xio_popen_system_read_cb,
            op);
    }
    
    GlobusXIOPOpenDebugExit();
    return result;
}

static
void
globus_l_xio_popen_system_write_cb(
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_operation_t              op;
    GlobusXIOName(globus_l_xio_popen_system_write_cb);
    
    GlobusXIOPOpenDebugEnter();
    
    op = (globus_xio_operation_t) user_arg;
    
    globus_l_xio_popen_update_position(
        (xio_l_popen_handle_t *) globus_xio_operation_get_driver_specific(op),
        nbytes,
        SEEK_CUR);
        
    globus_xio_driver_finished_write(op, result, nbytes);
    
    GlobusXIOPOpenDebugExit();
}

/*
 *  write to a file
 */
static
globus_result_t
globus_l_xio_popen_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    xio_l_popen_handle_t *              handle;
    globus_size_t                       nbytes;
    globus_result_t                     result;
    globus_off_t                        offset;
    GlobusXIOName(globus_l_xio_popen_write);
    
    GlobusXIOPOpenDebugEnter();
    
    handle = (xio_l_popen_handle_t *) driver_specific_handle;
    
    offset = GlobusXIOPOpenPosition(handle);
            
    /* if buflen and waitfor are both 0, we behave like register select */
    if((globus_xio_operation_get_wait_for(op) == 0 &&
        (iovec_count > 1 || iovec[0].iov_len > 0)) ||
        (handle->use_blocking_io &&
        globus_xio_driver_operation_is_blocking(op)))
    {
        result = globus_xio_system_file_write(
            handle->out_system,
            offset,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            &nbytes);
        
        globus_l_xio_popen_update_position(handle, nbytes, SEEK_CUR);
        globus_xio_driver_finished_write(op, result, nbytes);
        result = GLOBUS_SUCCESS;
    }
    else
    {
        result = globus_xio_system_file_register_write(
            op,
            handle->out_system,
            offset,
            iovec,
            iovec_count,
            globus_xio_operation_get_wait_for(op),
            globus_l_xio_popen_system_write_cb,
            op);
    }
    
    GlobusXIOPOpenDebugExit();
    return result;
}

static globus_xio_string_cntl_table_t popen_l_string_opts_table[] =

{
    {"blocking", GLOBUS_XIO_POPEN_SET_BLOCKING_IO,
        globus_xio_string_cntl_bool},
    {"pass_env", GLOBUS_XIO_POPEN_SET_PASS_ENV,
        globus_xio_string_cntl_bool},
    {"argv", GLOBUS_XIO_POPEN_SET_PROGRAM,
        globus_xio_string_cntl_string_list},
    {0}
};


static
globus_result_t
globus_l_xio_popen_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_popen_init);
    
    GlobusXIOPOpenDebugEnter();
    
    /* I dont support any driver options, so I'll ignore the ap */
    
    result = globus_xio_driver_init(&driver, "file", GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_popen_init", result);
        goto error_init;
    }

    globus_xio_driver_set_transport(
        driver,
        globus_l_xio_popen_open,
        globus_l_xio_popen_close,
        globus_l_xio_popen_read,
        globus_l_xio_popen_write,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_popen_attr_init,
        globus_l_xio_popen_attr_copy,
        globus_l_xio_popen_attr_cntl,
        globus_l_xio_popen_attr_destroy);

    globus_xio_driver_string_cntl_set_table(
        driver,
        popen_l_string_opts_table);

    *out_driver = driver;
    
    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;

error_init:
    GlobusXIOPOpenDebugExitWithError();
    return result;
}

static
void
globus_l_xio_popen_destroy(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_popen_destroy);
    
    GlobusXIOPOpenDebugEnter();
    
    globus_xio_driver_destroy(driver);
    
    GlobusXIOPOpenDebugExit();
}

GlobusXIODefineDriver(
    popen,
    globus_l_xio_popen_init,
    globus_l_xio_popen_destroy);

static
int
globus_l_xio_popen_activate(void)
{
    int                                 rc;
    
    GlobusXIOName(globus_l_xio_popen_activate);
    
    GlobusDebugInit(GLOBUS_XIO_POPEN, TRACE INFO);
    
    GlobusXIOPOpenDebugEnter();
    
    rc = globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto error_activate;
    }
    
    GlobusXIORegisterDriver(popen);
    
    GlobusXIOPOpenDebugExit();
    return GLOBUS_SUCCESS;

error_activate:
    GlobusXIOPOpenDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_POPEN);
    return rc;
}

static
int
globus_l_xio_popen_deactivate(void)
{
    GlobusXIOName(globus_l_xio_popen_deactivate);
    
    GlobusXIOPOpenDebugEnter();
    
    GlobusXIOUnRegisterDriver(popen);
    globus_module_deactivate(GLOBUS_XIO_SYSTEM_MODULE);
    
    GlobusXIOPOpenDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_POPEN);
    
    return GLOBUS_SUCCESS;
}
