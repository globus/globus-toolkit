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
#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_xio_bidi_driver.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_mode_e_driver.h"
#include "version.h"


#define GlobusXIOBidiDebugPrintf(level, message)                            \
    GlobusDebugPrintf(GLOBUS_XIO_BIDI, level, message)

#define GlobusXIOBidiDebugEnter()                                           \
    GlobusXIOBidiDebugPrintf(                                               \
        GLOBUS_L_XIO_BIDI_DEBUG_TRACE,                                      \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOBidiDebugExit()                                            \
    GlobusXIOBidiDebugPrintf(                                               \
        GLOBUS_L_XIO_BIDI_DEBUG_TRACE,                                      \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOBidiDebugExitWithError()                                   \
    GlobusXIOBidiDebugPrintf(                                               \
        GLOBUS_L_XIO_BIDI_DEBUG_TRACE,                                      \
        ("[%s] Exiting with error\n", _xio_name))

enum globus_l_xio_error_levels
{
    GLOBUS_L_XIO_BIDI_DEBUG_TRACE       = 1,
    GLOBUS_L_XIO_BIDI_DEBUG_INFO        = 2
};

typedef enum globus_i_xio_bidi_state_s
{

    GLOBUS_XIO_BIDI_NONE=1,
    GLOBUS_XIO_BIDI_OPEN,
    GLOBUS_XIO_BIDI_OPENING,
    GLOBUS_XIO_BIDI_SENDING_EOD,
    GLOBUS_XIO_BIDI_EOF_RECEIVED,
    GLOBUS_XIO_BIDI_EOF_DELIVERED,
    GLOBUS_XIO_BIDI_CLOSING,
    GLOBUS_XIO_BIDI_BOOTSTRAP_CLOSED,
    GLOBUS_XIO_BIDI_READWRITE_CLOSED,
    GLOBUS_XIO_BIDI_ERROR

} globus_i_xio_bidi_state_t;

static int
globus_l_xio_bidi_activate();

static int
globus_l_xio_bidi_deactivate();


GlobusXIODefineModule(bidi) =
{
    "globus_xio_bidi",
    globus_l_xio_bidi_activate,
    globus_l_xio_bidi_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef struct 
{
    globus_bool_t				isserver;
    int						read_port;
    globus_xio_stack_t 				read_stack;
    globus_xio_stack_t 				write_stack;
    globus_xio_stack_t 				bootstrap_stack;
    globus_xio_bidi_attr_cntl_callback_t	read_attr_cntl_cb;
    globus_xio_bidi_attr_cntl_callback_t	write_attr_cntl_cb;
    globus_xio_bidi_attr_cntl_callback_t	bootstrap_attr_cntl_cb;
    globus_xio_attr_t                   	xio_read_attr;
    globus_xio_attr_t                   	xio_write_attr;
    globus_xio_attr_t				bootstrap_attr;
    globus_xio_driver_t				mode_e_driver;
} globus_l_xio_bidi_attr_t;


/*
 *  *  handle structure
 *   */
typedef struct 
{
    globus_l_xio_bidi_attr_t *		attr;
    globus_xio_handle_t * 			read_handle;
    globus_xio_handle_t *			write_handle;
    globus_xio_server_t * 			read_server;
    globus_xio_server_t  			bootstrap_server;
    globus_xio_handle_t  			bootstrap_handle;
    char *					my_contact_string;
    unsigned char *                     	buffer;
    char *					bootstrap_cs;
    globus_xio_operation_t			outstanding_op;
    globus_xio_operation_t			open_op;
    int						operation_count;
    globus_mutex_t				mutex;
    globus_i_xio_bidi_state_t			state;
} globus_l_xio_bidi_handle_t;

typedef struct
{
    globus_l_xio_bidi_attr_t *			attr;
    globus_xio_server_t				bootstrap_server;
    char *					bootstrap_cs;
    char *					my_contact_string;
    globus_xio_operation_t			outstanding_op;
} globus_l_xio_bidi_server_t;

static
globus_result_t
globus_l_xio_bidi_handle_destroy(
    globus_l_xio_bidi_handle_t *      		handle);


static
void
globus_l_xio_bidi_read_server_accept_cb(
    globus_xio_server_t			server,
    globus_xio_handle_t			read_handle,
    globus_result_t			result,
    void *				user_arg);


static void
globus_l_xio_bidi_read_handle_close_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg);

GlobusDebugDefine(GLOBUS_XIO_BIDI);

static
globus_result_t
globus_l_xio_bidi_attr_init(
    void **                                     out_attr)
{
    globus_l_xio_bidi_attr_t *             bidi_attr;
    globus_result_t			   result;

    GlobusXIOName(globus_l_xio_bidi_attr_init);
    
    GlobusXIOBidiDebugEnter();


    bidi_attr = (globus_l_xio_bidi_attr_t *)
        globus_malloc(sizeof(globus_l_xio_bidi_attr_t));

    memset(bidi_attr, 0, sizeof(globus_l_xio_bidi_attr_t));

    bidi_attr->isserver = GLOBUS_FALSE;
    bidi_attr->read_port = 0;


    result=globus_xio_driver_load("mode_e", &bidi_attr->mode_e_driver);
    if (result!=GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_xio_attr_init(&bidi_attr->xio_read_attr);
    if (result != GLOBUS_SUCCESS)
    {   
        goto error_attr_init;
    }       
    if (bidi_attr->read_attr_cntl_cb)
    {       
        result = bidi_attr->read_attr_cntl_cb(bidi_attr->xio_read_attr);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_attr_cntl;
        }
    }   
    result = globus_xio_attr_init(&bidi_attr->xio_write_attr);
    if (result != GLOBUS_SUCCESS)
    {   
        goto error_attr_init;
    }       
    if (bidi_attr->write_attr_cntl_cb)
    {       
        result = bidi_attr->write_attr_cntl_cb(bidi_attr->xio_write_attr);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_attr_cntl;
        }
    }



    /* set the out parameter to the driver attr */
    *out_attr = bidi_attr;

    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;

error:
error_attr_cntl:
error_attr_init:
    return GLOBUS_FAILURE;
}

/*
 *  *  modify the attribute structure
 *   */
static
globus_result_t
globus_l_xio_bidi_attr_cntl(
    void *                                      attr,
    int                                         cmd,
    va_list                                     ap)
{
    globus_l_xio_bidi_attr_t *           bidi_attr;
    globus_result_t			 result = GLOBUS_FAILURE;

    GlobusXIOName(globus_l_xio_bidi_attr_cntl);

    GlobusXIOBidiDebugEnter();

    bidi_attr = (globus_l_xio_bidi_attr_t *) attr;
    switch(cmd)
    {
        case GLOBUS_XIO_BIDI_SET_PORT:
	{
	    bidi_attr->read_port = va_arg(ap, int);
            break;
	}
        case GLOBUS_XIO_BIDI_SET_READ_STACK:
	{
	    result = globus_xio_stack_copy(&bidi_attr->read_stack, 
			          va_arg(ap, globus_xio_stack_t));
            break;
	}

        case GLOBUS_XIO_BIDI_SET_WRITE_STACK:
	{
	   result = globus_xio_stack_copy(&bidi_attr->write_stack, 
			          va_arg(ap, globus_xio_stack_t));
            break;
	}

        case GLOBUS_XIO_BIDI_SET_BOOTSTRAP_STACK:
	{
	    result = globus_xio_stack_copy(&bidi_attr->read_stack, 
			          va_arg(ap, globus_xio_stack_t));
            break;
	}

        case GLOBUS_XIO_BIDI_GET_READ_STACK:
	{
	    globus_xio_stack_t * stack = va_arg(ap, globus_xio_stack_t *);
	    *stack = bidi_attr->read_stack;
            break;
	}

        case GLOBUS_XIO_BIDI_GET_WRITE_STACK:
	{
	    globus_xio_stack_t * stack = va_arg(ap, globus_xio_stack_t *);
	    *stack = bidi_attr->write_stack;
            break;
	}

        case GLOBUS_XIO_BIDI_GET_BOOTSTRAP_STACK:
	{
	    globus_xio_stack_t * stack = va_arg(ap, globus_xio_stack_t *);
	    *stack = bidi_attr->bootstrap_stack;
            break;
	}
        case GLOBUS_XIO_BIDI_SET_READ_ATTR:
	{
	    result = globus_xio_attr_copy(&bidi_attr->xio_read_attr, 
			          va_arg(ap, globus_xio_attr_t));
            break;
	}
        case GLOBUS_XIO_BIDI_GET_READ_ATTR:
	{
	    globus_xio_attr_t * attr = va_arg(ap, globus_xio_attr_t *);
	    *attr = bidi_attr->xio_read_attr;
            break;
	}
        case GLOBUS_XIO_BIDI_SET_WRITE_ATTR:
	{
	    result = globus_xio_attr_copy(&bidi_attr->xio_write_attr, 
			          va_arg(ap, globus_xio_attr_t));
            break;
	}
        case GLOBUS_XIO_BIDI_GET_WRITE_ATTR:
	{
	    globus_xio_attr_t * attr = va_arg(ap, globus_xio_attr_t *);
	    *attr = bidi_attr->xio_write_attr;
            break;
	}
        case GLOBUS_XIO_BIDI_SET_BOOTSTRAP_ATTR:
	{
	    result = globus_xio_attr_copy(&bidi_attr->bootstrap_attr, 
			          va_arg(ap, globus_xio_attr_t));
            break;
	}
        case GLOBUS_XIO_BIDI_GET_BOOTSTRAP_ATTR:
	{
	    globus_xio_attr_t * attr = va_arg(ap, globus_xio_attr_t *);
	    *attr = bidi_attr->bootstrap_attr;
            break;
	}
        case GLOBUS_XIO_BIDI_APPLY_READ_ATTR_CNTLS:
        {
            globus_xio_bidi_attr_cntl_callback_t attr_cntl_cb;
            attr_cntl_cb = va_arg(ap, globus_xio_bidi_attr_cntl_callback_t);
            bidi_attr->read_attr_cntl_cb = attr_cntl_cb;
            break;
        }
        case GLOBUS_XIO_BIDI_APPLY_WRITE_ATTR_CNTLS:
        {
            globus_xio_bidi_attr_cntl_callback_t attr_cntl_cb;
            attr_cntl_cb = va_arg(ap, globus_xio_bidi_attr_cntl_callback_t);
            bidi_attr->write_attr_cntl_cb = attr_cntl_cb;
            break;
        }
        case GLOBUS_XIO_BIDI_APPLY_BOOTSTRAP_ATTR_CNTLS:
        {
            globus_xio_bidi_attr_cntl_callback_t attr_cntl_cb;
            attr_cntl_cb = va_arg(ap, globus_xio_bidi_attr_cntl_callback_t);
            bidi_attr->bootstrap_attr_cntl_cb = attr_cntl_cb;
            break;
        }
	case GLOBUS_XIO_BIDI_SET_MAX_WRITE_STREAMS:
	{
	    globus_result_t		res;
	    
	    if (res!=GLOBUS_SUCCESS)
	    {
		goto error;
	    }
	    globus_xio_attr_cntl(
                bidi_attr->xio_write_attr,
                bidi_attr->mode_e_driver,
                GLOBUS_XIO_MODE_E_SET_NUM_STREAMS,
	        va_arg(ap, int));
	    break;
	}

        default:
            return GLOBUS_FAILURE;
            break;
    }
    if (result != GLOBUS_SUCCESS)
    {
error:
	GlobusXIOBidiDebugExitWithError();
	return GLOBUS_FAILURE;
    }
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;
}

/*
 *  *  copy an attribute structure
 *   */
static
globus_result_t
globus_l_xio_bidi_attr_copy(
    void **                                     dst,
    void *                                      src)
{
    globus_l_xio_bidi_attr_t *           bidi_attr;
    globus_l_xio_bidi_attr_t *           src_attr;
    globus_result_t			 result;

    GlobusXIOName(globus_l_xio_bidi_attr_copy);
    GlobusXIOBidiDebugEnter();

    bidi_attr = (globus_l_xio_bidi_attr_t *)
        globus_malloc(sizeof(globus_l_xio_bidi_attr_t));
    if(!bidi_attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_bidi_attr;
    }

    src_attr = (globus_l_xio_bidi_attr_t *) src;
    memcpy(bidi_attr, src_attr, sizeof(globus_l_xio_bidi_attr_t));
    if(src_attr->read_stack)
    {
	result = globus_xio_stack_copy(&bidi_attr->read_stack, 
					src_attr->read_stack);
	if (result != GLOBUS_SUCCESS)
	{
	    goto error_bidi_attr;
	}
    }
    if(src_attr->write_stack)
    {
	result = globus_xio_stack_copy(&bidi_attr->write_stack, 
					src_attr->write_stack);
	if (result != GLOBUS_SUCCESS)
	{
	    goto error_bidi_attr;
	}
    }
    if(src_attr->bootstrap_stack)
    {
	result = globus_xio_stack_copy(&bidi_attr->bootstrap_stack, 
					src_attr->bootstrap_stack);
	if (result != GLOBUS_SUCCESS)
	{
	    goto error_bidi_attr;
	}
    }
    if(src_attr->xio_read_attr)
    {    
	result = globus_xio_attr_copy(&bidi_attr->xio_read_attr,
				    src_attr->xio_read_attr);
	if (result != GLOBUS_SUCCESS)
	{
	    goto error_bidi_attr;
	}
    }

    if(src_attr->xio_write_attr)
    {    
	result = globus_xio_attr_copy(&bidi_attr->xio_write_attr,
				    src_attr->xio_write_attr);
	if (result != GLOBUS_SUCCESS)
	{
	    goto error_bidi_attr;
	}
    }
    
    if(src_attr->bootstrap_attr)
    {    
	result = globus_xio_attr_copy(&bidi_attr->bootstrap_attr,
				    src_attr->bootstrap_attr);
	if (result != GLOBUS_SUCCESS)
	{
	    goto error_bidi_attr;
	}
    }

    *dst = bidi_attr;
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;

  error_bidi_attr:
    GlobusXIOBidiDebugExitWithError();
    return result;
}

/*
 *  *  destroy an attr structure
 *   */
static
globus_result_t
globus_l_xio_bidi_attr_destroy(
    void *                                      attr)
{
    globus_l_xio_bidi_attr_t *           bidi_attr;

    GlobusXIOName(globus_l_xio_bidi_attr_destroy);

    GlobusXIOBidiDebugEnter();
    bidi_attr=(globus_l_xio_bidi_attr_t *)attr;

    globus_xio_stack_destroy(bidi_attr->read_stack);
    globus_xio_stack_destroy(bidi_attr->write_stack);
    globus_free(attr);
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;
}



static
globus_result_t
globus_l_xio_bidi_bootstrap_handle_create(
    globus_l_xio_bidi_handle_t **     out_handle,
    globus_l_xio_bidi_attr_t *        attr)
{
    globus_l_xio_bidi_handle_t *      handle;
    globus_result_t                     result;
    globus_xio_driver_t			driver;

    GlobusXIOName(globus_l_xio_bootstrap_handle_create);

    GlobusXIOBidiDebugEnter();

    handle = (globus_l_xio_bidi_handle_t *)
                globus_malloc(sizeof(globus_l_xio_bidi_handle_t));
    handle->state=GLOBUS_XIO_BIDI_NONE;

    if (handle == GLOBUS_NULL)
    {   
        result = GlobusXIOErrorMemory("handle");
        goto error_handle;
    }
    memset(handle, 0, sizeof(globus_l_xio_bidi_handle_t));

    /*FIXME*/
    handle->buffer=globus_malloc(256*sizeof(globus_size_t));
    memset(handle->buffer, 0, 256*sizeof(globus_size_t));

    if (!attr)
    {   
        result = globus_l_xio_bidi_attr_init((void**)&handle->attr);
        if (result != GLOBUS_SUCCESS)
        {   
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_bidi_attr_init", result);
            goto error_attr;
        }
    }
    else
    {   
        result = globus_l_xio_bidi_attr_copy(
                                (void**)&handle->attr, (void*)attr);
        if (result != GLOBUS_SUCCESS)
        {   
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_bidi_attr_copy", result);
            goto error_attr;
        }
    }

    if (!handle->attr->bootstrap_stack)
    {
        result = globus_xio_driver_load("tcp", &driver);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_driver_load;
        }
        result = globus_xio_stack_init(&handle->attr->bootstrap_stack, NULL);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_stack_init;
        }
        result = globus_xio_stack_push_driver(handle->attr->bootstrap_stack, driver);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_push_driver;
        }
    }

    if(handle->attr->isserver)
    {}
    else
    {
	result = globus_xio_attr_init(&handle->attr->bootstrap_attr);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_push_driver;
        }
    }
    globus_mutex_init(&handle->mutex, NULL);
    *out_handle = handle;
    return GLOBUS_SUCCESS;

error_push_driver:
    if (!handle->attr->bootstrap_stack)
    {
        globus_xio_stack_destroy(handle->attr->bootstrap_stack);
    }
error_stack_init:
    if (!handle->attr->bootstrap_stack)
    {
        globus_xio_driver_unload(driver);
    }
error_driver_load:
    globus_l_xio_bidi_attr_destroy(handle->attr);
error_attr:
    /*globus_free(handle);*/
error_handle:
    GlobusXIOBidiDebugExitWithError();
    return result;
}


static
globus_result_t
globus_l_xio_bidi_handle_destroy(
    globus_l_xio_bidi_handle_t *      handle)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_bidi_handle_destroy);

    GlobusXIOBidiDebugEnter();
    result = globus_l_xio_bidi_attr_destroy(handle->attr);
    if(result != GLOBUS_SUCCESS)
    {   
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_bidi_attr_destroy", result);
        goto error;
    }
    if (handle->bootstrap_server)
    {   
        /*globus_xio_server_close(handle->bootstrap_server);*/
    }
    globus_free(handle);
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;

error:
    GlobusXIOBidiDebugExitWithError();
    return result;
}


static globus_result_t
globus_l_xio_bidi_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    globus_l_xio_bidi_handle_t *		handle;
    globus_l_xio_bidi_server_t *		server;
    globus_l_xio_bidi_attr_t *		attr;
    globus_result_t			result;
    globus_xio_contact_t                my_contact_info;
    globus_xio_driver_t			driver=GLOBUS_NULL;

    GlobusXIOName(globus_l_xio_bidi_server_init);

    GlobusXIOBidiDebugEnter();

    attr = (globus_l_xio_bidi_attr_t *) driver_attr;
    if (!attr)
    {   
        result = globus_l_xio_bidi_attr_init((void**)&attr);
        if (result != GLOBUS_SUCCESS)
        {   
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_bidi_attr_init", result);
            goto error_attr;
        }
    }

    server = (globus_l_xio_bidi_server_t *)
                globus_malloc(sizeof(globus_l_xio_bidi_server_t));
    server->attr=attr;
    attr->isserver=1;

    if (!attr)
    {
        attr = server->attr;
    }
/*XXX*/
    globus_xio_driver_load("tcp", &driver);
    if (!attr->bootstrap_stack)
    {
        result = globus_xio_driver_load("tcp", &driver);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_driver_load;
        }
        result = globus_xio_stack_init(&attr->bootstrap_stack, NULL);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_stack_init;
        }
        result = globus_xio_stack_push_driver(attr->bootstrap_stack, driver);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_push_driver;
        }
    }

    if(attr->isserver)
    {
        result = globus_xio_attr_init(&attr->bootstrap_attr);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_push_driver;
        }
        result = globus_xio_attr_cntl( 
		    		attr->bootstrap_attr, 
				driver, 
				GLOBUS_XIO_TCP_SET_PORT, 
				attr->read_port);
        if (result != GLOBUS_SUCCESS)
        {
            goto error_push_driver;
        }
        result = globus_xio_attr_cntl(
            attr->bootstrap_attr,
            driver,
            GLOBUS_XIO_TCP_SET_REUSEADDR,
            GLOBUS_TRUE);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_push_driver;
        }
    }
    result = globus_xio_server_create(
            		&server->bootstrap_server, 
			attr->bootstrap_attr, 
			attr->bootstrap_stack);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_server_create;
    }
    result = globus_xio_server_get_contact_string(
		    			server->bootstrap_server, 
		    			&server->bootstrap_cs);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_get_cs;
    }
    result = globus_xio_contact_parse(&my_contact_info, 
					server->bootstrap_cs);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_parse_cs;
    }
    result = globus_xio_driver_pass_server_init(op, &my_contact_info, server);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_pass_server_init;
    }
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;

error_push_driver:
    if (!handle->attr->bootstrap_stack)
    {
        globus_xio_stack_destroy(handle->attr->bootstrap_stack);
    }
error_stack_init:
    if (!handle->attr->bootstrap_stack)
    {
        globus_xio_driver_unload(driver);
    }
error_driver_load:
    globus_l_xio_bidi_attr_destroy(handle->attr);
error_pass_server_init:
error_parse_cs:
error_get_cs:
    /*globus_xio_server_close(handle->bootstrap_server);*/
error_server_create:
   // globus_xio_attr_destroy(attr->xio_read_attr);
error_attr:
    globus_l_xio_bidi_handle_destroy(handle);
    GlobusXIOBidiDebugExitWithError();
    return result;
}

void
globus_l_xio_bidi_request_accept_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_result_t			res;

    globus_xio_driver_finished_accept(op, user_arg, res);    

}
    

static globus_result_t
globus_l_xio_bidi_create_read_handle(
    void *                              user_arg)
{
    globus_result_t   	                      result;
    globus_l_xio_bidi_handle_t  *			handle;
    globus_xio_attr_t			attr=NULL;
    globus_xio_driver_t                 mode_e;
    globus_xio_driver_t                 ordering;


    GlobusXIOName(globus_l_xio_bidi_create_read_handle);

    GlobusXIOBidiDebugEnter();
    result = globus_xio_attr_init(&attr);

    if (user_arg !=NULL)
    {   
        handle=(globus_l_xio_bidi_handle_t *)user_arg;
	
	handle->read_server=(globus_xio_server_t *)globus_malloc(
				sizeof(globus_xio_server_t));
	
        memset(handle->read_server, 0, sizeof(globus_xio_server_t));

	handle->read_handle=(globus_xio_handle_t *)globus_malloc(
				sizeof(globus_xio_handle_t));

        memset(handle->read_handle, 0, sizeof(globus_xio_handle_t));

	if(!handle->attr->read_stack)
	{

	    globus_xio_stack_init(&handle->attr->read_stack, NULL);
	    /*globus_xio_stack_init(&stack, NULL);*/

            result=globus_xio_driver_load("mode_e", &mode_e);
	    if (result!=GLOBUS_SUCCESS)
	    {
		goto error;
	    }
            result=globus_xio_driver_load("ordering", &ordering);
	    if (result!=GLOBUS_SUCCESS)
	    {
                goto error;
	    }
            result=globus_xio_stack_push_driver(
			    		handle->attr->read_stack, 
			    		mode_e);
	    if (result!=GLOBUS_SUCCESS)
	    {
                goto error;
	    }
            result=globus_xio_stack_push_driver(
			    		handle->attr->read_stack, 
					ordering);
	    if (result!=GLOBUS_SUCCESS)
	    {
                goto error;
	    }
	}
/*FIXME should be using attrs so users can pass in options*/
	if (handle->attr->read_attr_cntl_cb)
	{
	    result = handle->attr->read_attr_cntl_cb(
			    			handle->attr->xio_read_attr);
	    if (result != GLOBUS_SUCCESS)
	    {
		goto error_attr_cntl;
	    }
	}
	result = globus_xio_server_create(handle->read_server, 
					  handle->attr->xio_read_attr, 
					  handle->attr->read_stack);
	if (result!=GLOBUS_SUCCESS)
	{
            goto error;
	}

       result = globus_xio_server_get_contact_string(*handle->read_server,
                       &handle->my_contact_string); 
       printf("CONTACT: %s\n", handle->my_contact_string);
			
    }
    GlobusXIOBidiDebugExit();                             
    return result;
error_attr_cntl:
    globus_xio_attr_destroy(handle->attr->xio_read_attr);
error:
    if(*handle->read_server)
    {
        globus_xio_server_close(*handle->read_server);
    }
    GlobusXIOBidiDebugExitWithError();
    return result;
}

static globus_result_t
globus_l_xio_bidi_create_write_handle(
    void *                              user_arg)
{
    globus_result_t   	                      result;
    globus_l_xio_bidi_handle_t  *			handle;
    globus_xio_attr_t			attr=NULL;
    globus_xio_driver_t                 ordering;


    GlobusXIOName(globus_l_xio_bidi_create_write_handle);

    GlobusXIOBidiDebugEnter();
    result = globus_xio_attr_init(&attr);

    if (user_arg !=NULL)
    {   
        handle=(globus_l_xio_bidi_handle_t *)user_arg;
	handle->write_handle=(globus_xio_handle_t *)globus_malloc(
			sizeof(globus_xio_handle_t));
        memset(handle->write_handle, 0, sizeof(globus_xio_handle_t));


	if(!handle->attr->write_stack)
	{

	    globus_xio_stack_init(&handle->attr->write_stack, NULL);

            result=globus_xio_driver_load("ordering", &ordering);
	    if (result!=GLOBUS_SUCCESS)
	    {
                goto error;
	    }
            result=globus_xio_stack_push_driver(
			    		handle->attr->write_stack, 
			    		handle->attr->mode_e_driver);
			    		//mode_e);
	    if (result!=GLOBUS_SUCCESS)
	    {
                goto error;
	    }
            result=globus_xio_stack_push_driver(
			    		handle->attr->write_stack, 
					ordering);
	    if (result!=GLOBUS_SUCCESS)
	    {
                goto error;
	    }
	}

        result = globus_xio_handle_create(handle->write_handle, 
					handle->attr->write_stack);
	if (result!=GLOBUS_SUCCESS)
	{
            goto error;
	}

			
	GlobusXIOBidiDebugExit();                             
	return result;
    }
error:
    GlobusXIOBidiDebugExitWithError();
    return GLOBUS_FAILURE;
}



void
globus_l_xio_bidi_accept_cb(
    globus_xio_server_t server, 
    globus_xio_handle_t accepted_handle, 
    globus_result_t result, 
    void * user_arg)
{
	globus_l_xio_bidi_handle_t * handle;

    GlobusXIOName(globus_l_xio_bidi_accept_cb);

    GlobusXIOBidiDebugEnter();

    handle=user_arg;

    if(result != GLOBUS_SUCCESS)
    {
    /*    globus_l_xio_bidi_handle_destroy(user_arg);*/
        goto error;
    }
    
    handle->bootstrap_handle=accepted_handle;

    globus_xio_driver_finished_accept(handle->outstanding_op, 
		    			handle, 
					result);

    GlobusXIOBidiDebugExit();
    return;

 error:
    /*globus_xio_driver_finished_accept(handle->outstanding_op, NULL, result);*/
    GlobusXIOBidiDebugExitWithError();
    return;
}

static globus_result_t
globus_l_xio_bidi_accept(
    void *                              driver_server,
    globus_xio_operation_t              accept_op)
{
    globus_result_t                     result;
    globus_l_xio_bidi_handle_t *      handle;
    globus_l_xio_bidi_server_t	*		server;
    
    GlobusXIOName(globus_l_xio_bidi_accept);
    GlobusXIOBidiDebugEnter();
    
    server = (globus_l_xio_bidi_server_t*)driver_server;
    result = globus_l_xio_bidi_bootstrap_handle_create(&handle, server->attr);
    if (result != GLOBUS_SUCCESS)
    {       
        /*goto error_handle_create;*/
    }       
    handle->attr->isserver = GLOBUS_TRUE;
    handle->outstanding_op = accept_op;

    result = globus_xio_server_register_accept(
		    		server->bootstrap_server,
				globus_l_xio_bidi_accept_cb, 
				handle);
    if (result != GLOBUS_SUCCESS)
    {   
        goto error_register_accept;
    }

    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;


    error_register_accept:
    return result;
}

static globus_result_t
globus_l_xio_bidi_server_cntl(
    void *                              driver_server,
    int                                 cmd,
    va_list                             ap)
{
    GlobusXIOName(globus_l_xio_bidi_server_cntl);

    GlobusXIOBidiDebugEnter();
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_bidi_server_destroy(
    void *                              driver_server)
{
    GlobusXIOName(globus_l_xio_bidi_server_destroy);

    GlobusXIOBidiDebugEnter();
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_bidi_link_cntl(
    void *                              driver_link,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_xio_bidi_handle_t *        accepted_handle;
    globus_result_t                     result;
    char **                             out_string;
    globus_l_xio_bidi_handle_t *        out_handle;
    GlobusXIOName(globus_l_xio_bidi_link_cntl);

    GlobusXIOBidiDebugEnter();
    accepted_handle = (globus_l_xio_bidi_handle_t *) driver_link;
    switch(cmd)
    { 
      /* globus_xio_system_handle_t *   handle_out */
      case GLOBUS_XIO_TCP_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_handle_t *);
        *out_handle = *accepted_handle;
        break;

      /* char **                        contact_string_out */
      case GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT:
      case GLOBUS_XIO_TCP_GET_LOCAL_CONTACT:
      case GLOBUS_XIO_TCP_GET_REMOTE_NUMERIC_CONTACT:
      case GLOBUS_XIO_TCP_GET_REMOTE_CONTACT:
      case GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT:
      case GLOBUS_XIO_GET_LOCAL_CONTACT:
      case GLOBUS_XIO_GET_REMOTE_NUMERIC_CONTACT:
      case GLOBUS_XIO_GET_REMOTE_CONTACT:
        out_string = va_arg(ap, char **);
        /*result = globus_l_xio_tcp_contact_string(
            *accepted_handle, cmd, out_string);*/
	globus_xio_driver_t	driver;
	globus_xio_driver_load("tcp", &driver);
	result = globus_xio_handle_cntl(
            accepted_handle->bootstrap_handle,  
	    GLOBUS_XIO_QUERY,
            cmd, 
            out_string);
        if(result != GLOBUS_SUCCESS)
        {   
            result = GlobusXIOErrorWrapFailed(
                "globus_l_xio_tcp_contact_string", result);
            goto error_contact;
        }
        break;

      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;
        break;
    }

    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;

error_invalid:
error_contact:
    GlobusXIOBidiDebugExitWithError();
    return result;
                 
}

globus_result_t
globus_l_xio_bidi_link_destroy(
    void *                              driver_link)
{   
    globus_l_xio_bidi_handle_t *      handle;
    GlobusXIOName(globus_l_xio_bidi_link_destroy);

    GlobusXIOBidiDebugEnter();
    handle = (globus_l_xio_bidi_handle_t *) driver_link;
    globus_l_xio_bidi_handle_destroy(handle);

    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_bidi_register_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_bidi_handle_t *        handle;
    GlobusXIOName(globus_l_xio_bidi_register_open_cb);
    GlobusXIOBidiDebugEnter();
    
    handle=(globus_l_xio_bidi_handle_t *)user_arg; 
    if(result==GLOBUS_SUCCESS)
    {
	globus_xio_driver_finished_open(handle, handle->open_op, result);
         GlobusXIOBidiDebugExit();
	return;
    }
    else
    {
        GlobusXIOBidiDebugExitWithError(); 	
    }
}

static
void
globus_l_xio_bidi_read_server_accept_cb(
    globus_xio_server_t			server,
    globus_xio_handle_t			read_handle,
    globus_result_t			result,
    void *				user_arg)
{
    globus_l_xio_bidi_handle_t *	handle;
    globus_result_t			res;
    
    GlobusXIOName(globus_l_xio_bidi_read_server_accept_cb);
    GlobusXIOBidiDebugEnter();

    if(result!=GLOBUS_SUCCESS)
    {
        goto error;
    }
    handle=(globus_l_xio_bidi_handle_t *)user_arg;
    *handle->read_handle=read_handle;


    res = globus_xio_register_open(*handle->read_handle,
		    		    NULL,
				    handle->attr->xio_read_attr,
				    globus_l_xio_bidi_register_open_cb,
				    handle);

    if (res!=GLOBUS_SUCCESS)
    {
	goto error;
    }

     GlobusXIOBidiDebugExit();
     return; 
error:
     GlobusXIOBidiDebugExitWithError();
     return;
}


static
void
globus_l_xio_bidi_handshake_open_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_bidi_handle_t *        handle;
    globus_result_t			res;
    GlobusXIOName(globus_l_xio_bidi_handshake_open_cb);
    GlobusXIOBidiDebugEnter();
    
    handle=(globus_l_xio_bidi_handle_t *)user_arg; 
    if(result==GLOBUS_SUCCESS)
    {

        res = globus_xio_server_register_accept( 
				*handle->read_server, 
				globus_l_xio_bidi_read_server_accept_cb, 
				handle);
	if (res !=GLOBUS_SUCCESS)
	{
	    GlobusXIOBidiDebugExitWithError();
	}
         GlobusXIOBidiDebugExit();
	return;
    }
    else
    {
        GlobusXIOBidiDebugExitWithError(); 	
    }
}


void
globus_l_xio_bidi_end_handshake_cb(
    globus_xio_handle_t 		xio_handle, 
    globus_result_t 			result, 
    globus_byte_t * 			buffer, 
    globus_size_t 			len, 
    globus_size_t 			nbytes, 
    globus_xio_data_descriptor_t 	data_desc, 
    void * 				user_arg)
{
    globus_l_xio_bidi_handle_t *        handle;

    GlobusXIOName(globus_l_xio_bidi_end_handshake_cb);

    GlobusXIOBidiDebugEnter();

    handle=user_arg;
    globus_mutex_lock(&handle->mutex); 
    handle->operation_count++;

    /*When we're here the second time, both the read and write handles have
     * been created
     * */

    if (handle->operation_count ==2)
    {
	if (handle->attr->write_attr_cntl_cb)
	{
	    result = handle->attr->write_attr_cntl_cb(
			    			handle->attr->xio_write_attr);
	    if (result != GLOBUS_SUCCESS)
	    {
		goto error_attr_cntl;
	    }
	}
/* ???  should this be so serialized? register_server_accept happens in the 
 * callback for the register open on the read handle*/
        result = globus_xio_register_open(*handle->write_handle, 
				 handle->buffer, 
				 handle->attr->xio_write_attr,
				 globus_l_xio_bidi_handshake_open_cb,
				 handle);
    }
    
    if(result!=GLOBUS_SUCCESS)
    {
	goto error;
    }
    
    handle->state=GLOBUS_XIO_BIDI_OPEN;
    globus_mutex_unlock(&handle->mutex);
					
    GlobusXIOBidiDebugExit();
    return;
error_attr_cntl:
    globus_xio_attr_destroy(handle->attr->xio_write_attr);
error:
    GlobusXIOBidiDebugExitWithError();
    return;
}


static
void
globus_l_xio_bidi_open_cb(
    globus_xio_handle_t 		xio_handle,
    globus_result_t 			result, 
    void * 				user_arg)
{
    globus_result_t			res;
    globus_l_xio_bidi_handle_t *	handle;

    GlobusXIOName(globus_l_xio_bidi_open_cb);

    GlobusXIOBidiDebugEnter();

    handle = (globus_l_xio_bidi_handle_t *)user_arg;

    if(result != GLOBUS_SUCCESS)
    {   
        goto error_destroy_handle;
    } 


    /*set up the driver_handle to be used in subsequent calls*/
        res = globus_l_xio_bidi_create_read_handle(handle);
        res = globus_l_xio_bidi_create_write_handle(handle);

    handle->operation_count=0;

	res = globus_xio_register_read(
					xio_handle,
					handle->buffer,
					256,
					1,
					NULL,
					globus_l_xio_bidi_end_handshake_cb,
					handle);

	    /*FIXME strlen*/
        if(res != GLOBUS_SUCCESS)
        {
	    goto error_read_handle_failed;
        }
	
        res = globus_xio_register_write(
			xio_handle, 
			handle->my_contact_string,
			strlen(handle->my_contact_string),
			1,
			NULL,
			globus_l_xio_bidi_end_handshake_cb,
			handle);



    if(res != GLOBUS_SUCCESS)
    {
	goto error_read_handle_failed;
    }	

    GlobusXIOBidiDebugExit();

    return;

  error_read_handle_failed:
    GlobusXIOBidiDebugExit();
    return;
  error_destroy_handle:
    globus_l_xio_bidi_handle_destroy(handle);
    GlobusXIOBidiDebugExit();
    return;
}

/*
 *  open
 */
static
globus_result_t
globus_l_xio_bidi_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     result;
    globus_l_xio_bidi_handle_t *   	handle;

    globus_l_xio_bidi_attr_t *		attr;
    globus_xio_handle_t			bs_handle;
 
    GlobusXIOName(globus_l_xio_bidi_open);

    GlobusXIOBidiDebugEnter();

    handle = (globus_l_xio_bidi_handle_t *) driver_link;
    attr = (globus_l_xio_bidi_attr_t *) driver_attr;

    if (!handle) /* Client */
    {   
        result = globus_l_xio_bidi_bootstrap_handle_create(&handle, attr);
        if (result != GLOBUS_SUCCESS)
        {   
            goto error_handle_create;
        }
        if(attr==NULL)
        {
 	    result = globus_l_xio_bidi_attr_init((void **) &attr);         
	    if(result!=GLOBUS_SUCCESS)
	    {
	        goto error_xio_handle_create;
	    }
	    attr->isserver=GLOBUS_FALSE;
        }
   

        result = globus_xio_handle_create(&bs_handle,
				handle->attr->bootstrap_stack);
	if(result!=GLOBUS_SUCCESS)
	{
	    goto error_xio_handle_create;
	}
    }
    handle->open_op=op;
    if(!handle->attr->isserver) 
    {
        result = globus_xio_register_open(bs_handle,
		    		contact_info->unparsed, 
				NULL,
				globus_l_xio_bidi_open_cb, 
				handle);
	if(result!=GLOBUS_SUCCESS)
	{
	    goto error_xio_handle_create;
	}
	handle->bootstrap_handle=bs_handle;
    }
    else
    {
        result = globus_xio_register_open(handle->bootstrap_handle,
				NULL,
				NULL,
				globus_l_xio_bidi_open_cb, 
				handle);
    }
    if (result != GLOBUS_SUCCESS)
    {
	goto error_server_open;
    }
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;

    globus_l_xio_bidi_handle_destroy(handle);
  error_server_open:
  error_handle_create:
  error_xio_handle_create:
    GlobusXIOBidiDebugExitWithError(); 
    return result;
}

void
globus_l_xio_bidi_read_server_close_cb(
    globus_xio_server_t                 server,
        void *                              user_arg)
{
    globus_l_xio_bidi_handle_t *	handle;

    GlobusXIOName(globus_l_xio_bidi_read_server_close_cb);
    GlobusXIOBidiDebugEnter();
    handle=user_arg;
        if(handle->outstanding_op)
        {
	    if(handle->state==GLOBUS_XIO_BIDI_CLOSING)
	    {
                globus_xio_driver_finished_close(handle->outstanding_op, GLOBUS_SUCCESS);
	    }
	}
	globus_mutex_unlock(&handle->mutex);
        GlobusXIOBidiDebugExit();
    
}

void
globus_l_xio_bidi_bootstrap_server_close_cb(
    globus_xio_server_t                 server,
        void *                              user_arg)
{
    globus_l_xio_bidi_handle_t *	handle;

    GlobusXIOName(globus_l_xio_bidi_bootstrap_server_close_cb);
    GlobusXIOBidiDebugEnter();
    handle=user_arg;

    if (*handle->read_server)
    {   
        globus_xio_server_register_close(*handle->read_server,
			globus_l_xio_bidi_read_server_close_cb,
			handle);
    }
        GlobusXIOBidiDebugExit();
    
}

    

    

static void
globus_l_xio_bidi_close_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_bidi_handle_t *     handle;
    
    GlobusXIOName(globus_l_xio_bidi_close_cb);

    GlobusXIOBidiDebugEnter();
    handle = (globus_l_xio_bidi_handle_t *) user_arg;


    if (handle->bootstrap_server)
    {   
        globus_xio_server_register_close(handle->bootstrap_server,
					globus_l_xio_bidi_bootstrap_server_close_cb,
					handle);
    }
    else
    {
	globus_l_xio_bidi_bootstrap_server_close_cb(NULL, handle);
    }

    if (result==GLOBUS_SUCCESS)
    {
        GlobusXIOBidiDebugExit();
    }else
    {
    GlobusXIOBidiDebugExitWithError();
    }
}

static void
globus_l_xio_bidi_write_handle_close_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_bidi_handle_t *     handle;
    globus_result_t		     res;
    
    GlobusXIOName(globus_l_xio_bidi_write_handle_close_cb);

    GlobusXIOBidiDebugEnter();
    handle = (globus_l_xio_bidi_handle_t *) user_arg;

    res = globus_xio_register_close(handle->bootstrap_handle, 
		    	handle->attr->bootstrap_attr,
			globus_l_xio_bidi_close_cb,
			handle);
    if (handle->state!=GLOBUS_XIO_BIDI_CLOSING)
    {
        handle->state=GLOBUS_XIO_BIDI_READWRITE_CLOSED;
    }
    if(res !=GLOBUS_SUCCESS)
    {
    GlobusXIOBidiDebugExitWithError();
    }
        GlobusXIOBidiDebugExit();
}

static void
globus_l_xio_bidi_read_handle_close_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_bidi_handle_t *     handle;
    globus_result_t		     res;
    
    GlobusXIOName(globus_l_xio_bidi_read_handle_close_cb);

    GlobusXIOBidiDebugEnter();
    handle = (globus_l_xio_bidi_handle_t *) user_arg;
    /*XXX globus_mutex_lock(&handle->mutex);*/
/*TODAY
    globus_xio_handle_cancel_operations(*handle->write_handle,
		    		GLOBUS_XIO_CANCEL_WRITE);*/
        res = globus_xio_register_close(*handle->write_handle, 
		    	handle->attr->xio_write_attr,
			globus_l_xio_bidi_write_handle_close_cb,
			handle);
    
    if(res !=GLOBUS_SUCCESS)
    {
    GlobusXIOBidiDebugExitWithError();
    }

        GlobusXIOBidiDebugExit();
}
/*
 *  close
 */
static
globus_result_t
globus_l_xio_bidi_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_l_xio_bidi_handle_t *	handle;

    GlobusXIOName(globus_l_xio_bidi_close);

    GlobusXIOBidiDebugEnter();

    handle=driver_specific_handle;
    res=GLOBUS_SUCCESS;

    globus_mutex_lock(&handle->mutex);
    handle->outstanding_op=op;
    if((handle->state!=GLOBUS_XIO_BIDI_BOOTSTRAP_CLOSED)&
	(handle->state!=GLOBUS_XIO_BIDI_READWRITE_CLOSED))
    {
    }
       if((handle->state!=GLOBUS_XIO_BIDI_CLOSING)&
		(handle->state!=GLOBUS_XIO_BIDI_BOOTSTRAP_CLOSED)&
		 (handle->state!=GLOBUS_XIO_BIDI_READWRITE_CLOSED))
       {

       handle->state=GLOBUS_XIO_BIDI_CLOSING;
       
    res = globus_xio_register_close(*handle->read_handle, 
		    	handle->attr->xio_read_attr,
			globus_l_xio_bidi_read_handle_close_cb,
			handle);
       }
       else
       {
           if(handle->state==GLOBUS_XIO_BIDI_READWRITE_CLOSED)
           {	/* This means that bootstrap connection failed, and r/w
		   alread closed, so we should just finish the close */
		   
	        globus_xio_driver_finished_close(handle->outstanding_op, GLOBUS_SUCCESS);
		globus_mutex_unlock(&handle->mutex); /*XXX*/
           }
       }
    if(res !=GLOBUS_SUCCESS)
    {
	goto error;
    }

    
        GlobusXIOBidiDebugExit();
    return res;
error:
    GlobusXIOBidiDebugExitWithError();
    return res;
}

static
void
globus_l_xio_bidi_read_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_xio_operation_t 		op;
    globus_result_t			res;

    GlobusXIOName(globus_l_xio_bidi_read_cb);

    GlobusXIOBidiDebugEnter();
    op=user_arg;       

    if(globus_xio_driver_eof_received(op))
    {
printf("XXX read is eof\n");
    }
		    
    globus_xio_driver_finished_read(op, result, nbytes);

    GlobusXIOBidiDebugExit();
}
/*
 *  read
 */
static
globus_result_t
globus_l_xio_bidi_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;
    globus_l_xio_bidi_handle_t *	handle;
    globus_size_t			nbytes;

    GlobusXIOName(globus_l_xio_bidi_read);

    GlobusXIOBidiDebugEnter();

    wait_for = globus_xio_operation_get_wait_for(op);

    handle=driver_specific_handle;

    if (handle->state==GLOBUS_XIO_BIDI_OPEN)
    {
        res = globus_xio_register_readv(
			*handle->read_handle,
		    	(globus_xio_iovec_t *)iovec, 
			iovec_count,
			wait_for,
			NULL,
			globus_l_xio_bidi_read_cb,
			op);
    }
    else
    {
	    return GlobusXIOErrorEOF(); 
    }


        if(res != GLOBUS_SUCCESS)
        {
/*            res = GlobusXIOErrorWrapFailed(
                "globus_l_xio_bidi_read", res);*/
            goto error_register;
        }

        GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;
error_register:
    GlobusXIOBidiDebugExitWithError();
    return res;
}

static
void
globus_l_xio_bidi_write_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_xio_iovec_t *                iovec,
    int                                 iovec_count,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_xio_operation_t 		op;

    op=user_arg;        
    globus_xio_driver_finished_write(op, result, nbytes);
}
/*
 *  write
 */
static
globus_result_t
globus_l_xio_bidi_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;
    globus_l_xio_bidi_handle_t *	handle;
    globus_size_t                       nbytes;

    GlobusXIOName(globus_l_xio_bidi_write);

    GlobusXIOBidiDebugEnter();

    wait_for = globus_xio_operation_get_wait_for(op);
    handle=driver_specific_handle;

    if (handle->state==GLOBUS_XIO_BIDI_OPEN)
    {
        res = globus_xio_register_writev(*handle->write_handle,
		    	(globus_xio_iovec_t *)iovec, 
			iovec_count,
			wait_for,
			NULL,
			globus_l_xio_bidi_write_cb,
			op);
    }
    else
    {
	    /*Should probably return a different error*/
	    return GlobusXIOErrorEOF(); 
    }
		    	
        if(res != GLOBUS_SUCCESS)
        {
            res = GlobusXIOErrorWrapFailed(
                "globus_l_xio_bidi_write", res);
            goto error_register;
        }

        GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;
error_register:
    GlobusXIOBidiDebugExitWithError();
    return res;
}


static globus_result_t
globus_l_xio_bidi_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_bidi_init);

    GlobusXIOBidiDebugEnter();

    res = globus_xio_driver_init(&driver, "bidi", NULL);
    if(res != GLOBUS_SUCCESS)
    {
	        GlobusXIOBidiDebugExit();
        return res;
    }

    globus_xio_driver_set_transport(
        driver,
        globus_l_xio_bidi_open,
        globus_l_xio_bidi_close,
        globus_l_xio_bidi_read,
        globus_l_xio_bidi_write,
        globus_l_xio_bidi_link_cntl);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_bidi_server_init,
        globus_l_xio_bidi_accept,
        globus_l_xio_bidi_server_destroy,
        globus_l_xio_bidi_server_cntl,
        globus_l_xio_bidi_link_cntl,
	NULL);
	/*globus_l_xio_bidi_link_destroy);*/


    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_bidi_attr_init,
        globus_l_xio_bidi_attr_copy,
        globus_l_xio_bidi_attr_cntl,
        globus_l_xio_bidi_attr_destroy);

    *out_driver = driver;
    GlobusXIOBidiDebugExit();
    return GLOBUS_SUCCESS;
}

static void
globus_l_xio_bidi_destroy(
    globus_xio_driver_t                 driver)
{
    GlobusXIOName(globus_l_xio_bidi_destroy);

    GlobusXIOBidiDebugEnter();

    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    bidi,
    globus_l_xio_bidi_init,
    globus_l_xio_bidi_destroy);

static
int
globus_l_xio_bidi_activate(void)
{
    int                                 rc;

    GlobusXIOName(globus_l_xio_bidi_activate);
    GlobusDebugInit(GLOBUS_XIO_BIDI, TRACE INTERNAL_TRACE);
    GlobusXIOBidiDebugEnter();

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(bidi);
	GlobusXIOBidiDebugExit();
    }
    else
    {
	globus_module_deactivate(GLOBUS_XIO_MODULE);
	GlobusXIOBidiDebugExitWithError();
	GlobusDebugDestroy(GLOBUS_XIO_BIDI);
    }
        GlobusXIOBidiDebugExit();
    return rc;
}

static
int
globus_l_xio_bidi_deactivate(void)
{
    GlobusXIOName(globus_l_xio_bidi_deactivate);

    GlobusXIOBidiDebugEnter();

    GlobusXIOUnRegisterDriver(bidi);
        GlobusXIOBidiDebugExit();
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
