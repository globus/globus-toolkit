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

#include "globus_xio.h"

/**
 * Notes about this example:
 * 
 * This example is 100% blind.  It treats all drivers the same and doesn't use
 * any of the driver specific attributes.  In the real world, that would be
 * unavoidable. For example, if you would like to set a specific port for the
 * server to listen on, that would require a TCP specific attribute.  Also,
 * if you use file as a driver for the destination, normally you would want
 * that file truncated.  Since that behavior is not the default of the file
 * driver, if the file already exists, the resulting file may be the wrong
 * size.
 */
 
typedef struct
{
    globus_xio_handle_t                 source_handle;
    globus_xio_handle_t                 dest_handle;
    char *                              source_cs;
    char *                              dest_cs;
    globus_bool_t                       eof_received;
    globus_bool_t                       source_is_open;
    globus_object_t *                   error;
    globus_size_t                       buffer_size;
    
    globus_mutex_t                      lock;
    globus_cond_t                       cond;
    int                                 cb_count;
} copy_info_t;

void
test_result(
    globus_result_t                     result)
{
    char *                              message;
    if(result == GLOBUS_SUCCESS)
    {
        return;
    }
    
    message = globus_error_print_friendly(globus_error_peek(result));
    fprintf(stderr, "Error: %s\n", message);
    globus_free(message);

    globus_assert(0);
}

void
help()
{
    printf("globus-xio-async-copy\n"
        "    -sD <source driver>         { -sC <contact string> | -s }\n"
        "    -dD <destination driver>      -dC <contact string>\n"
        "-----------------\n"
        "options:\n"
        "-h                     Print this help\n"
        "-sD <driver>           The driver for the source of the copy\n"
        "-dD <driver>           The driver for the dest of the copy\n"
        "    The above two commands can be used more than once\n"
        "    The stack will be setup in the order listed\n"
        "-sC <contact string>   The contact string to be used for the source\n"
        "-dC <contact string>   The contact string to be used for the dest\n"
        "-s                     The source is a server.\n"
        "-b <buffer size>       The buffer size to use.\n"
        "-i                     Interactive use. Will write stdin to source.\n"
        "\n"
        "-----------------\n"
        "example uses:\n"
        "a file to file copy\n"
        " %% globus-xio-async-copy -sD file -sC <source_file> -dD file -dC <dest_file>\n"
        "a tcp server source to a file destination:\n"
        " %% globus-xio-async-copy -sD tcp -s -dD file -dC <output_file>\n"
        "       - The contact info of the tcp server will be printed\n"
        "       - globus-xio-client -D tcp <contact info> can be used to\n"
        "            communicate with this server\n"
        "\n"
        "Hints: the file driver supports stdin://, stdout://, and stderr:// for\n"
        " contact strings.  Their usage should be obvious\n");
}

static
void
wakeup_main(
    copy_info_t *                       copy_info,
    globus_result_t                     result)
{
    if(result != GLOBUS_SUCCESS && copy_info->error == NULL)
    {
        copy_info->error = globus_error_get(result);
    }
    
    globus_mutex_lock(&copy_info->lock);
    {
        copy_info->cb_count--;
        if(copy_info->cb_count == 0)
        {
            globus_cond_signal(&copy_info->cond);
        }
    }
    globus_mutex_unlock(&copy_info->lock);
}

static
void
close_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    copy_info_t *                       copy_info;
    
    copy_info = (copy_info_t *) user_arg;
    wakeup_main(copy_info, result);
}

static
void
close_handles_and_wakeup_main(
    copy_info_t *                       copy_info,
    globus_byte_t *                     buffer,
    globus_result_t                     result)
{
    if(buffer)
    {
        globus_free(buffer);
    }
    
    if(result != GLOBUS_SUCCESS && copy_info->error == NULL)
    {
        copy_info->error = globus_error_get(result);
    }
    
    /* this here will be the only example I give of a concurrent operation
     * if both handles are created, I will close them both at the same time.
     * the cb_count will.  If I have two outstanding
     * close callbacks, I will incrememnt it to two
     */
    globus_mutex_lock(&copy_info->lock);
    {
        if(copy_info->source_handle)
        {
            result = globus_xio_register_close(
                copy_info->source_handle,
                NULL,
                close_callback,
                copy_info);
            if(result == GLOBUS_SUCCESS)
            {
                copy_info->cb_count++;
            }
        }
        
        if(copy_info->dest_handle)
        {
            result = globus_xio_register_close(
                copy_info->dest_handle,
                NULL,
                close_callback,
                copy_info);
            if(result == GLOBUS_SUCCESS)
            {
                copy_info->cb_count++;
            }
        }
    }
    globus_mutex_unlock(&copy_info->lock);

    /* this will remove the reference on 
     * the callback that main registerd out
     */
    wakeup_main(copy_info, result);
}

static
void 
source_read_callback(
    globus_xio_handle_t                 handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

static
void 
dest_write_callback(
    globus_xio_handle_t                 handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    copy_info_t *                       copy_info;
    
    copy_info = (copy_info_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    /* just finished writing the last buffer, lets read the next if
     * we haven't already received eof
     * 
     * normally, a flag like eof_received would need to be protected by a 
     * mutex, but since I know I've serialized everything, it's unnecessary
     * here.
     */
    if(!copy_info->eof_received)
    {
        result = globus_xio_register_read(
            copy_info->source_handle,
            buffer,
            copy_info->buffer_size,
            1,
            NULL,
            source_read_callback,
            copy_info);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        /* eof has been received, we're done.  Close all the handles;
         */
        close_handles_and_wakeup_main(copy_info, buffer, GLOBUS_SUCCESS);
    }

    return;

error:
    close_handles_and_wakeup_main(copy_info, buffer, result);
}

static
void 
source_read_callback(
    globus_xio_handle_t                 handle, 
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes, 
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    copy_info_t *                       copy_info;
    
    copy_info = (copy_info_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        if(globus_xio_error_is_eof(result))
        {
            /* on eof, we'll just set a flag and write any remaining data */
            copy_info->eof_received = GLOBUS_TRUE;
        }
        else
        {
            goto error;
        }
    }
    
    /* write the buffer we just read in to the destination */
    if(nbytes > 0)
    {
        result = globus_xio_register_write(
            copy_info->dest_handle,
            buffer,
            nbytes,
            nbytes,
            NULL,
            dest_write_callback,
            copy_info);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    else
    {
        /* there is no data to write. since we passed a waitforbytes of 1,
         * this MUST mean that we just received eof.  In that case, were done
         */
        globus_assert(copy_info->eof_received);
        close_handles_and_wakeup_main(copy_info, buffer, GLOBUS_SUCCESS);
    }
    
    /* in a high performance application, this is where I would register the
     * next read (if we haven't received eof yet) so that it could be done
     * while we're writing the current buffer.  Again, to avoid concurrency
     * and buffer management issues, I am keeping this simple example
     * serialized.
     */
    
    return;

error:
    close_handles_and_wakeup_main(copy_info, buffer, result);
}

static
void
dest_open_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    copy_info_t *                       copy_info;
    globus_byte_t *                     buffer = NULL;
    
    copy_info = (copy_info_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    buffer = (globus_byte_t *) globus_malloc(copy_info->buffer_size);
    if(!buffer)
    {
        result = globus_error_put(
            globus_error_wrap_errno_error(
                NULL,
                errno,
                0,
                __FILE__,
                "dest_open_callback",
                __LINE__,
                "Could not malloc buffer\n"));
        goto error;
    }

    /* now we have opened the source and destination.  let's start reading
     * from the source
     */
    result = globus_xio_register_read(
        copy_info->source_handle,
        buffer,
        copy_info->buffer_size,
        1, /* for high throughput, you would set this to the full buffer length
            * but, since I don't know how we're being used, I'll just wait for
            * any data
            */
        NULL,
        source_read_callback,
        copy_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    return;
    
error:
    close_handles_and_wakeup_main(copy_info, buffer, result);
}

static
void
source_open_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    copy_info_t *                       copy_info;
    
    copy_info = (copy_info_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    /* now we have opened the source, let's open the destination
     * normally, these two opens could have happened simulaneously, but,
     * in the interest of keeping this example trivial, I am serializing all
     * operations
     */
    result = globus_xio_register_open(
        copy_info->dest_handle,
        copy_info->dest_cs,
        NULL,
        dest_open_callback,
        copy_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    /**
     * This signal here is for the interactive support.  Ignore it if you're
     * using this example to learn the async model
     */
    globus_mutex_lock(&copy_info->lock);
    {
        copy_info->source_is_open = GLOBUS_TRUE;
        globus_cond_signal(&copy_info->cond);
    }
    globus_mutex_unlock(&copy_info->lock);
    
    return;
    
error:
    close_handles_and_wakeup_main(copy_info, NULL, result);
}

static
void
source_server_accept_callback(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    copy_info_t *                       copy_info;
    
    /* I am only going to accept one connection, so I'll close this server
     * right now.  Don't care about the callback, so I'll leave it null
     */
    globus_xio_server_register_close(server, NULL, NULL);
    
    copy_info = (copy_info_t *) user_arg;
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    
    /* now we can open the source handle that has just been accepted */
    copy_info->source_handle = handle;
    result = globus_xio_register_open(
        copy_info->source_handle,
        copy_info->source_cs, /* this is usually NULL for accepted handles */
        NULL,
        source_open_callback,
        copy_info);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
        
    return;
    
error:
    close_handles_and_wakeup_main(copy_info, NULL, result);
}

int
main(
    int                                 argc,
    char **                             argv)
{
    globus_xio_driver_t                 driver;
    globus_xio_stack_t                  source_stack;
    globus_xio_stack_t                  dest_stack;
    globus_xio_server_t                 server;
    char *                              source_cs = NULL;
    char *                              dest_cs = NULL;
    globus_size_t                       buffer_size = 64 * 1024;
    globus_bool_t                       source_is_server = GLOBUS_FALSE;
    globus_result_t                     result;
    int                                 i;
    copy_info_t                         copy_info;
    globus_list_t *                     driver_list = NULL;
    int                                 rc = 0;
    globus_bool_t                       interactive = GLOBUS_FALSE;
    
    if(argc < 2)
    {
        help();
        return 1;
    }

    globus_module_activate(GLOBUS_XIO_MODULE);
    
    globus_xio_stack_init(&source_stack, NULL);
    globus_xio_stack_init(&dest_stack, NULL);
    
    /* parse all of the parameters */
    for(i = 1; i < argc; i++)
    {
        if(strcmp(argv[i], "-h") == 0)
        {
            help();
            return 0;
        }
        else if(strcmp(argv[i], "-sD") == 0 && i + 1 < argc)
        {
            /* a source driver, push it on the stack */
            i++;
            result = globus_xio_driver_load(argv[i], &driver);
            test_result(result);
            result = globus_xio_stack_push_driver(source_stack, driver);
            test_result(result);
            globus_list_insert(&driver_list, driver);
        }
        else if(strcmp(argv[i], "-dD") == 0 && i + 1 < argc)
        {
            /* a dest driver, push it on the stack */
            i++;
            result = globus_xio_driver_load(argv[i], &driver);
            test_result(result);
            result = globus_xio_stack_push_driver(dest_stack, driver);
            test_result(result);
            globus_list_insert(&driver_list, driver);
        }
        else if(strcmp(argv[i], "-sC") == 0 && i + 1 < argc)
        {
            source_cs = argv[++i];
        }
        else if(strcmp(argv[i], "-dC") == 0 && i + 1 < argc)
        {
            dest_cs = argv[++i];
        }
        else if(strcmp(argv[i], "-s") == 0)
        {
            source_is_server = GLOBUS_TRUE;
        }
        else if(strcmp(argv[i], "-b") == 0 && i + 1 < argc)
        {
            buffer_size = atoi(argv[++i]);
        }
        else if(strcmp(argv[i], "-i") == 0)
        {
            interactive = GLOBUS_TRUE;
        }
    }

    if(!dest_cs)
    {
        fprintf(
            stderr, "Error: A destination contact string must be supplied\n");
        return 1;
    }
    
    /* set up the copy info that will be passed through all of the callbacks */
    copy_info.source_handle = NULL;
    copy_info.dest_handle = NULL;
    copy_info.source_cs = source_cs;
    copy_info.dest_cs = dest_cs;
    copy_info.buffer_size = buffer_size;
    copy_info.eof_received = GLOBUS_FALSE;
    copy_info.source_is_open = GLOBUS_FALSE;
    globus_mutex_init(&copy_info.lock, NULL);
    globus_cond_init(&copy_info.cond, NULL);
    copy_info.cb_count = 1;
    copy_info.error = NULL;
    
    /* lets create the destination handle ahead of time so I don't have to
     * hang on to the stack.  I will actually open the destination later
     */
    result = globus_xio_handle_create(&copy_info.dest_handle, dest_stack);
    test_result(result);
    
    /* to keep things simple, I will start it all off by opening the source */
    if(source_is_server)
    {
        /* for a server, we'll first accept a new handle for the source and
         * then open it
         */
        result = globus_xio_server_create(&server, NULL, source_stack);
        test_result(result);
        result = globus_xio_server_get_contact_string(server, &source_cs);
        test_result(result);
        printf("Server contact string: %s\n", source_cs);
        globus_free(source_cs);
        result = globus_xio_server_register_accept(
            server,
            source_server_accept_callback,
            &copy_info);
        test_result(result);
    }
    else
    {
        /* otherwise, we'll just start by opening the source now */
        result = globus_xio_handle_create(
            &copy_info.source_handle, source_stack);
        test_result(result);
        result = globus_xio_register_open(
            copy_info.source_handle,
            copy_info.source_cs,
            NULL,
            source_open_callback,
            &copy_info);
        test_result(result);
    }
    
    /**
     * ignore this if you're using this example to learn the async programming
     * model
     */
    if(interactive && source_is_server)
    {
        globus_xio_stack_t              stdin_stack;
        globus_xio_handle_t             stdin_handle;
        globus_byte_t                   buffer[1024];
        
        result = globus_xio_driver_load("file", &driver);
        test_result(result);
        result = globus_xio_stack_init(&stdin_stack, NULL);
        test_result(result);
        result = globus_xio_stack_push_driver(stdin_stack, driver);
        test_result(result);
        result = globus_xio_handle_create(&stdin_handle, stdin_stack);
        test_result(result);
        globus_xio_stack_destroy(stdin_stack);
        result = globus_xio_open(stdin_handle, "stdin://", NULL);
        test_result(result);
        
        /**
         * wait for source to connect
         */
        globus_mutex_lock(&copy_info.lock);
        {
            while(!copy_info.source_is_open && !copy_info.error)
            {
                globus_cond_wait(&copy_info.cond, &copy_info.lock);
            }
        }
        globus_mutex_unlock(&copy_info.lock);
        
        if(copy_info.source_is_open)
        {
            printf("Source has connected\n");
        }
        
        /**
         * copy stdin to source.
         */
        while(result == GLOBUS_SUCCESS && 
            !copy_info.eof_received && !copy_info.error)
        {
            size_t                      nbytes;
            
            result = globus_xio_read(stdin_handle,
                buffer, sizeof(buffer), 1, &nbytes, NULL);
            if(nbytes > 0 && !copy_info.eof_received && !copy_info.error)
            {
                result = globus_xio_write(copy_info.source_handle,
                    buffer, nbytes, nbytes, &nbytes, NULL);
            }
        }
        
        globus_xio_close(stdin_handle, NULL);
        globus_xio_driver_unload(driver);
        if(!copy_info.eof_received && !copy_info.error)
        {
            globus_xio_handle_cancel_operations(
                copy_info.source_handle, GLOBUS_XIO_CANCEL_READ);
        }
    }
    
    /* wait for it to all be done */
    globus_mutex_lock(&copy_info.lock);
    {
        while(copy_info.cb_count > 0)
        {
            globus_cond_wait(&copy_info.cond, &copy_info.lock);
        }
    }
    globus_mutex_unlock(&copy_info.lock);
    
    globus_mutex_destroy(&copy_info.lock);
    globus_cond_destroy(&copy_info.cond);
    
    /* any error from within the callbacks was save here */
    if(copy_info.error)
    {
        char *                          message;
        
        message = globus_error_print_friendly(copy_info.error);
        fprintf(stderr, "Error: %s\n", message);
        globus_free(message);
        globus_object_free(copy_info.error);
        rc = 1;
    }
    
    /* clean up memory,  (note the stacks can be destroyed any time after use
     * the drivers can only unloaded when you're done with the xio handles
     */
    globus_xio_stack_destroy(source_stack);
    globus_xio_stack_destroy(dest_stack);
    while(!globus_list_empty(driver_list))
    {
        driver = (globus_xio_driver_t)
            globus_list_remove(&driver_list, driver_list);
        globus_xio_driver_unload(driver);
    }
    
    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return rc;
}
