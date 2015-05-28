/*
 * Copyright 1999-2008 University of Chicago
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

#include "gssapi_test_utils.h"
#include <sys/types.h>

#include "globus_preload.h"

#define NUM_CLIENTS 10
#define ITERATIONS 10

struct thread_arg
{
    gss_buffer_desc                     init_token;
    globus_bool_t                       init_token_ready;
    globus_bool_t                       init_done;
    gss_buffer_desc                     accept_token;
    globus_bool_t                       accept_token_ready;
    globus_bool_t                       accept_done;
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
};

static int                              client_thread_count = 0;
static int                              server_thread_count = 0;
static int                              client_failed = 0;
static globus_fifo_t                    arg_queue;
static globus_mutex_t                   mutex;
static globus_cond_t                    cond;

void *
server_func(
    void *                              arg);

void *
client_func(
    void *                              arg);


int
main()
{
    gss_cred_id_t                       credential;
    struct thread_arg                   thread_args[NUM_CLIENTS] = {{0}};
    globus_thread_t                     thread_handle;
    int                                 i;
    int                                 ret;
    int                                 error;
    int                                 thread_num = 0;

    LTDL_SET_PRELOADED_SYMBOLS();

    globus_thread_set_model(THREAD_MODEL);

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);

    printf("1..%d\n", NUM_CLIENTS);
    globus_mutex_init(&mutex, NULL);
    globus_cond_init(&cond, NULL);
    globus_fifo_init(&arg_queue);
    credential = globus_gsi_gssapi_test_acquire_credential();

    if(credential == GSS_C_NO_CREDENTIAL)
    {
	fprintf(stderr,"Unable to acquire credential\n");
	exit(-1);
    }

    /* start the clients here */
    globus_mutex_lock(&mutex);
    for(i=0;i<NUM_CLIENTS;i++)
    {
        thread_args[i] = (struct thread_arg) {
            .init_token = { 0 },
            .init_token_ready = GLOBUS_FALSE,
            .accept_token = { 0 },
            .accept_token_ready = GLOBUS_FALSE
        };
        globus_mutex_init(&thread_args[i].mutex, NULL);
        globus_cond_init(&thread_args[i].cond, NULL);
        client_thread_count++;

	globus_thread_create(&thread_handle,NULL,client_func,&thread_args[i]);
    }
    while (client_thread_count > 0)
    {
        while (client_thread_count > 0 && globus_fifo_empty(&arg_queue))
        {
            globus_cond_wait(&cond, &mutex);
        }
        if (!globus_fifo_empty(&arg_queue))
        {
            globus_thread_create(&thread_handle,NULL,server_func,globus_fifo_dequeue(&arg_queue));
            server_thread_count++;
        }
    }

    /* wait for last thread to terminate */
    while (client_thread_count > 0 && server_thread_count > 0)
    {
        globus_cond_wait(&cond, &mutex);
    }
    globus_mutex_unlock(&mutex);


    globus_mutex_destroy(&mutex);
    globus_cond_destroy(&cond);

    globus_gsi_gssapi_test_release_credential(&credential); 

    globus_module_deactivate_all();

    exit(client_failed);
}


void *
server_func(
    void *                              arg)
{
    struct thread_arg *                 thread_args = arg;
    globus_bool_t                       authenticated;
    gss_ctx_id_t                        context = GSS_C_NO_CONTEXT;
    OM_uint32                           major_status, minor_status, ms;
    gss_cred_id_t                       credential;
    
    credential = globus_gsi_gssapi_test_acquire_credential();
    globus_mutex_lock(&thread_args->mutex);
    do
    {
        while (!thread_args->accept_token_ready)
        {
            globus_cond_wait(&thread_args->cond, &thread_args->mutex);
        }
        thread_args->accept_token_ready = GLOBUS_FALSE;

        major_status = gss_accept_sec_context(&minor_status,
                                              &context,
                                              credential,
                                              &thread_args->accept_token,
                                              GSS_C_NO_CHANNEL_BINDINGS,
                                              NULL,
                                              NULL,
                                              &thread_args->init_token,
                                              NULL,
                                              NULL,
                                              NULL);
        gss_release_buffer(&ms, &thread_args->accept_token);
        thread_args->accept_token = (gss_buffer_desc) {0};
        thread_args->accept_token_ready = GLOBUS_FALSE;
        if (thread_args->init_token.length > 0)
        {
            thread_args->init_token_ready = GLOBUS_TRUE;
            globus_cond_signal(&thread_args->cond);
        }
    } while (major_status == GSS_S_CONTINUE_NEEDED);
    thread_args->accept_done = GLOBUS_TRUE;
    globus_cond_signal(&thread_args->cond);
    globus_mutex_unlock(&thread_args->mutex);
    
    if (major_status != GSS_S_COMPLETE)
    {
	fprintf(stderr, "SERVER: Authentication failed: %s\n",
		globus_error_print_friendly(globus_error_peek(minor_status)));
    }

    globus_mutex_lock(&mutex);
    {
        server_thread_count--;
        
        if(server_thread_count == 0)
        {
            globus_cond_signal(&cond);
        }
    }
    globus_mutex_unlock(&mutex);
    return NULL;
}


void *
client_func(
    void *                              arg)
{
    struct thread_arg *                 thread_args = arg;
    gss_ctx_id_t                        context_handle = GSS_C_NO_CONTEXT;
    int                                 connect_fd;
    int                                 result;
    int                                 failed = 0;
    OM_uint32                           major_status, minor_status, ms;
    gss_cred_id_t                       credential;
    
    credential = globus_gsi_gssapi_test_acquire_credential();
    for (int i = 0; i < ITERATIONS && !failed; i++)
    {
        globus_mutex_lock(&thread_args->mutex);
        thread_args->init_done = GLOBUS_FALSE;
        thread_args->init_token = (gss_buffer_desc) {0};
        thread_args->init_token_ready = GLOBUS_TRUE;
        thread_args->accept_token = (gss_buffer_desc) {0};
        thread_args->accept_token_ready = GLOBUS_FALSE;
        thread_args->accept_done = GLOBUS_FALSE;
        context_handle = GSS_C_NO_CONTEXT;
        globus_mutex_unlock(&thread_args->mutex);

        globus_mutex_lock(&mutex);
        globus_fifo_enqueue(&arg_queue, arg);
        globus_cond_signal(&cond);
        globus_mutex_unlock(&mutex);

        globus_mutex_lock(&thread_args->mutex);
        do
        {
            while (!thread_args->init_token_ready)
            {
                globus_cond_wait(&thread_args->cond, &thread_args->mutex);
            }
            major_status = gss_init_sec_context(
                    &minor_status,
                    credential,
                    &context_handle,
                    NULL, // target_name
                    GSS_C_NO_OID, // mech_type
                    0, // req_flags
                    0, // default_time
                    GSS_C_NO_CHANNEL_BINDINGS,
                    &thread_args->init_token,
                    NULL,
                    &thread_args->accept_token,
                    NULL, // ret_flags
                    NULL); // time_ret

            if (thread_args->init_token.length > 0)
            {
                gss_release_buffer(
                        &ms,
                        &thread_args->init_token);
            }
            thread_args->init_token_ready = GLOBUS_FALSE;
            thread_args->init_token = (gss_buffer_desc) {0};

            if (thread_args->accept_token.length > 0)
            {
                thread_args->accept_token_ready = GLOBUS_TRUE;
	        globus_cond_signal(&thread_args->cond);
            }
        }
        while (major_status == GSS_S_CONTINUE_NEEDED);
        thread_args->init_done = GLOBUS_TRUE;
        while ((!thread_args->init_done) || (!thread_args->accept_done))
	{
            globus_cond_wait(&thread_args->cond, &thread_args->mutex);
	}
        globus_mutex_unlock(&thread_args->mutex);

	if (major_status != GSS_S_COMPLETE)
	{
	    fprintf(stderr, "CLIENT: Authentication failed: %s\n",
		globus_error_print_friendly(globus_error_peek(minor_status)));
            failed = GLOBUS_TRUE;
	}
        gss_delete_sec_context(&minor_status, &context_handle, NULL);
    }

    globus_mutex_lock(&mutex);
    {
        client_thread_count--;
        client_failed += failed;

        printf("%s\n", failed ? "not ok" : "ok");
        
        if(client_thread_count == 0)
        {
            globus_cond_signal(&cond);
        }
    }
    globus_mutex_unlock(&mutex);
    
    return NULL;
}
