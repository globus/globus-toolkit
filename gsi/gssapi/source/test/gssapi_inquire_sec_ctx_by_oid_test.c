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
#ifndef WIN32
#include <sys/socket.h>
#include <sys/un.h>
#else
#include <winsock2.h>
#define pid_t int
#define fork() NULL
#endif

struct context_arg
{
    gss_cred_id_t                       credential;
    int                                 fd;
};

int
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
    struct context_arg *                arg = NULL;
    pid_t                               pid;
    int                                 socks[2];
    int                                 rc;

    /* ToDo: Make this run on windows */
#   ifdef WIN32
    printf("1..1\n");
    printf("ok # SKIP This Test Doesn't Run On Windows Yet\n");
    exit(77);
#   endif

    /* module activation */

    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_activate(GLOBUS_COMMON_MODULE);
    
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
    if (rc < 0)
    {
        perror("socketpair");
        exit(EXIT_FAILURE);
    }

    /* acquire credentials */
    credential = globus_gsi_gssapi_test_acquire_credential();

    if(credential == GSS_C_NO_CREDENTIAL)
    {
        fprintf(stderr,"Unable to aquire credential\n");
        exit(-1);
    }

    pid = fork();

    if(pid == 0)
    {
        /* child */
     	arg = malloc(sizeof(struct context_arg));
        
        arg->fd = socks[0];
        close(socks[1]);
        
	arg->credential = credential;

        client_func(arg);
    }
    else if (pid > 0)
    {
        printf("1..1\n");
	arg = malloc(sizeof(struct context_arg));
        
	arg->fd = socks[1];
        close(socks[0]);
        
	arg->credential = credential;

        rc = server_func(arg);
        if (rc == 0)
        {
            printf("ok\n");
        }
        else
        {
            printf("not ok\n");
        }
    }
    else
    {
        printf("1..1\n");
        perror("not ok - fork");
        exit(EXIT_FAILURE);
    }

    
    /* release credentials */
    globus_gsi_gssapi_test_release_credential(&credential); 
    
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);

    exit(rc);
}


int
server_func(
    void *                              arg)
{
    struct context_arg *                server_args;
    globus_bool_t                       result;
    gss_ctx_id_t                        context_handle = GSS_C_NO_CONTEXT;
    char *                              user_id = NULL;
    gss_cred_id_t                       delegated_cred = GSS_C_NO_CREDENTIAL;
    
    server_args = (struct context_arg *) arg;

    result = globus_gsi_gssapi_test_authenticate(
	server_args->fd,
	GLOBUS_TRUE, 
	server_args->credential, 
	&context_handle, 
	&user_id, 
	&delegated_cred);
    
    if(result == GLOBUS_FALSE)
    {
	fprintf(stderr, "SERVER: Authentication failed\n");
        return 1;
    }

    result = globus_gsi_gssapi_test_dump_cert_chain(
        "cert_chain.txt",
        context_handle);

    if(result == GLOBUS_FALSE)
    {
	fprintf(stderr, "SERVER: Failed to dump cert chain\n");
        return 1;
    }
    
    close(server_args->fd);
    
    free(server_args);
    
    globus_gsi_gssapi_test_cleanup(&context_handle,
				   user_id,
				   &delegated_cred);
    
    return 0;
}

void *
client_func(
    void *                              arg)
{
    struct context_arg *                client_args;
    globus_bool_t                       authenticated;
    gss_ctx_id_t                        context_handle = GSS_C_NO_CONTEXT;
    char *                              user_id = NULL;
    gss_cred_id_t                       delegated_cred = GSS_C_NO_CREDENTIAL;
    int                                 result;
    
    client_args = (struct context_arg *) arg;

    authenticated = globus_gsi_gssapi_test_authenticate(
        client_args->fd,
        GLOBUS_FALSE, 
        client_args->credential, 
        &context_handle, 
        &user_id, 
        &delegated_cred);
    
    if(authenticated == GLOBUS_FALSE)
    {
        fprintf(stderr, "CLIENT: Authentication failed\n");
        exit(1);
    }
    
    globus_gsi_gssapi_test_cleanup(&context_handle,
                                   user_id,
                                   &delegated_cred);
    user_id = NULL;
    
    close(client_args->fd);

    free(client_args);

    return NULL;
}
