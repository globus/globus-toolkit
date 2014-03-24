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
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#include "globus_preload.h"

#define NUM_CLIENTS 10
#define ITERATIONS 10

struct thread_arg
{
    gss_cred_id_t                       credential;
    int                                 fd;
    globus_sockaddr_t *                 address;
    socklen_t   			len;
};

#ifdef _WIN32
#undef perror
#define perror(m) do { \
	int perror__wsaerr = WSAGetLastError(); \
        printf(m ": %d\n", perror__wsaerr); \
	} while (0)
#endif

static int                              client_thread_count = 0;
static int                              server_thread_count = 0;
static int                              pending_connects = 0;
static int                              client_failed =0 ;
static globus_mutex_t                   mutex;
static globus_cond_t                    done;

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
    int                                 listen_fd;
    int                                 accept_fd;
    struct sockaddr_in                  address = {0};
    globus_sockaddr_t                   connect_address;
    globus_socklen_t                    connect_address_len = sizeof(connect_address);
    struct thread_arg *                 arg = NULL;
    globus_thread_t                     thread_handle;
    int                                 i;
    int                                 ret;
    int                                 error;

    LTDL_SET_PRELOADED_SYMBOLS();

    globus_thread_set_model(THREAD_MODEL);

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);

    printf("1..%d\n", NUM_CLIENTS);
    /* initialize global mutex */
    globus_mutex_init(&mutex, NULL);

    /* and the condition variable */

    globus_cond_init(&done, NULL);
    
    /* setup listener */
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    ret = bind(listen_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_in));
    if (ret != 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    ret = getsockname(listen_fd, (struct sockaddr *) &connect_address, &connect_address_len);
    if (ret != 0)
    {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    ret = listen(listen_fd, -1);
    if (ret != 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    /* acquire credentials */
    credential = globus_gsi_gssapi_test_acquire_credential();

    if(credential == GSS_C_NO_CREDENTIAL)
    {
	fprintf(stderr,"Unable to aquire credential\n");
	exit(-1);
    }

    /* start the clients here */
    for(i=0;i<NUM_CLIENTS;i++)
    {
	arg = malloc(sizeof(struct thread_arg));

	arg->address = &connect_address;
	arg->len = connect_address_len;

	arg->credential = credential;
	
        globus_mutex_lock(&mutex);
        {
            client_thread_count++;
        }
        globus_mutex_unlock(&mutex);

	globus_thread_create(&thread_handle,NULL,client_func,(void *) arg);
    }
    
    /* accept connections */

    globus_mutex_lock(&mutex);
    while (client_thread_count > 0)
    {
        while (pending_connects > 0)
	{
            accept_fd = accept(listen_fd,NULL,0);

            if(accept_fd < 0)
            {
                perror("accept");
                abort();
            }
	
            arg = malloc(sizeof(struct thread_arg));

            arg->fd = accept_fd;
            arg->credential = credential;

            server_thread_count++;
            pending_connects--;
            globus_thread_create(&thread_handle,NULL,server_func,(void *) arg);
        }
        globus_cond_wait(&done, &mutex);
    }

    /* wait for last thread to terminate */
    while (server_thread_count > 0)
    {
        globus_cond_wait(&done, &mutex);
    }
    globus_mutex_unlock(&mutex);


    /* destroy global mutex */

    globus_mutex_destroy(&mutex);

    /* and the condition variable */

    globus_cond_destroy(&done);
    
    /* close the listener */

    close(listen_fd);
    
    /* release credentials */

    globus_gsi_gssapi_test_release_credential(&credential); 

    globus_module_deactivate_all();

    exit(client_failed);
}


void *
server_func(
    void *                              arg)
{
    struct thread_arg *                 thread_args;
    globus_bool_t                       authenticated;
    gss_ctx_id_t                        context_handle = GSS_C_NO_CONTEXT;
    char *                              user_id = NULL;
    gss_cred_id_t                       credential = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t                       delegated_cred = GSS_C_NO_CREDENTIAL;
    
    thread_args = (struct thread_arg *) arg;

    authenticated = globus_gsi_gssapi_test_authenticate(
	thread_args->fd,
	GLOBUS_TRUE, 
	thread_args->credential, 
	&context_handle, 
	&user_id, 
	&delegated_cred);
    
    if(authenticated == GLOBUS_FALSE)
    {
	fprintf(stderr, "SERVER: Authentication failed\n");
    }

    close(thread_args->fd);
    
    free(thread_args);
    
    globus_gsi_gssapi_test_cleanup(&context_handle,
				   user_id,
				   &delegated_cred);

    globus_mutex_lock(&mutex);
    {
        server_thread_count--;
        
        if(server_thread_count == 0)
        {
            globus_cond_signal(&done);
        }
    }
    globus_mutex_unlock(&mutex);


    return NULL;
}


void *
client_func(
    void *                              arg)
{
    struct thread_arg *                 thread_args;
    globus_bool_t                       authenticated;
    gss_ctx_id_t                        context_handle = GSS_C_NO_CONTEXT;
    char *                              user_id = NULL;
    gss_cred_id_t                       credential = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t                       delegated_cred = GSS_C_NO_CREDENTIAL;
    int                                 connect_fd;
    int                                 result;
    int                                 i;
    int                                 failed = 0;
    
    thread_args = (struct thread_arg *) arg;

    for(i=0;i<ITERATIONS;i++)
    {
        globus_mutex_lock(&mutex);
        pending_connects++;
        globus_mutex_unlock(&mutex);
	connect_fd = socket(AF_INET, SOCK_STREAM, 0);

        do
        {
            result = connect(connect_fd,
                             (struct sockaddr *) thread_args->address,
                             thread_args->len);
        }
        while (result != 0);

	authenticated = globus_gsi_gssapi_test_authenticate(
	    connect_fd,
	    GLOBUS_FALSE, 
	    thread_args->credential, 
	    &context_handle, 
	    &user_id, 
	    &delegated_cred);

	if(authenticated == GLOBUS_FALSE)
	{
	    fprintf(stderr, "CLIENT: Authentication failed\n");
            failed = 1;
	}
    
	globus_gsi_gssapi_test_cleanup(&context_handle,
				       user_id,
				       &delegated_cred);
	user_id = NULL;

	close(connect_fd);
    }

    free(thread_args);

    globus_mutex_lock(&mutex);
    {
        client_thread_count--;
        client_failed += failed;

        printf("%s\n", failed ? "not ok" : "ok");
        
        if(client_thread_count == 0)
        {
            globus_cond_signal(&done);
        }
    }
    globus_mutex_unlock(&mutex);
    
    return NULL;
}
