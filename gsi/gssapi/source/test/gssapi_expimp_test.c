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
#define fork() -1
#endif

static int skip_test = 0;

struct context_arg
{
    gss_cred_id_t                       credential;
    int                                 fd;
};

int
server_func(
    void *                              arg);

void
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
    int                                 childrc;
    int                                 rc = EXIT_SUCCESS;
    int                                 socks[2];

    /* ToDo: Make this run on windows */
#   ifdef WIN32
    printf("This Test Doesn't Run On Windows Yet\n");
    exit(0);
#   endif

    /* module activation */

    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_activate(GLOBUS_COMMON_MODULE);
    
    /* setup listener */

    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
    if (rc < 0)
    {
        perror("socketpair");
        rc = EXIT_FAILURE;
        goto done;
    }

    /* acquire credentials */
    credential = globus_gsi_gssapi_test_acquire_credential();

    if(credential == GSS_C_NO_CREDENTIAL)
    {
        fprintf(stderr,"Unable to aquire credential\n");
        rc = EXIT_FAILURE;
        goto done;
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
	arg = malloc(sizeof(struct context_arg));
        
	arg->fd = socks[1];
        close(socks[0]);
        
	arg->credential = credential;

        rc = server_func(arg);

        if (waitpid(pid, &childrc, 0) < 0)
        {
            int save_errno = errno;
            fprintf(stderr, "[%d] Error determining process exit status: %s\n",
                    save_errno,
                    strerror(save_errno));
            rc = EXIT_FAILURE;
        } else if (!WIFEXITED(childrc))
        {
            fprintf(stderr, "Child process died\n");
            rc = EXIT_FAILURE;
        }
        else if (WEXITSTATUS(childrc) != EXIT_SUCCESS)
        {
            fprintf(stderr, "Child process exited with exit status %d\n",
                    (int) WEXITSTATUS(childrc));
            rc = EXIT_FAILURE;
        }
    }
    else
    {
        rc = EXIT_FAILURE;
    }

    if (pid != 0)
    {
done:
        printf("%sok gssapi_expimp_test%s\n",
            (rc == 0) ? "" : "not ",
            (rc == 0 && skip_test)
                ? " # skip GSS_C_TRANS_FLAG not in context" :"");
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
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    OM_uint32                           flags;
    
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
        return EXIT_FAILURE;
    }

    major_status = gss_inquire_context(
            &minor_status,
            context_handle,
            NULL,
            NULL,
            NULL,
            NULL,
            &flags,
            NULL,
            NULL);

    if (major_status == GSS_S_COMPLETE)
    {
        if (!(flags & GSS_C_TRANS_FLAG))
        {
            skip_test = 1;
            return EXIT_SUCCESS;
        }
    }

    result = globus_gsi_gssapi_test_export_context("context.dat",
                                                   &context_handle);
    
    if(result == GLOBUS_FALSE)
    {
	fprintf(stderr, "SERVER: Export failed\n");
        return EXIT_FAILURE;
    }

    context_handle = GSS_C_NO_CONTEXT;
    
    result = globus_gsi_gssapi_test_import_context("context.dat",
                                                   &context_handle);
    
    if(result == GLOBUS_FALSE)
    {
	fprintf(stderr, "SERVER: Import failed\n");
        return EXIT_FAILURE;
    }

    result = globus_gsi_gssapi_test_send_hello(server_args->fd,
                                               context_handle);

    if(result == GLOBUS_FALSE)
    {
	fprintf(stderr, "SERVER: Send hello failed\n");
        return EXIT_FAILURE;
    }

    close(server_args->fd);
    
    free(server_args);

    globus_gsi_gssapi_test_cleanup(&context_handle,
				   user_id,
				   &delegated_cred);
    
    return EXIT_SUCCESS;
}

void
client_func(
    void *                              arg)
{
    struct context_arg *                client_args;
    gss_ctx_id_t                        context_handle = GSS_C_NO_CONTEXT;
    char *                              user_id = NULL;
    gss_cred_id_t                       delegated_cred = GSS_C_NO_CREDENTIAL;
    globus_bool_t                       result;
    int                                 rc;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    OM_uint32                           flags;
    
    client_args = (struct context_arg *) arg;

    result = globus_gsi_gssapi_test_authenticate(
        client_args->fd,
        GLOBUS_FALSE, 
        client_args->credential, 
        &context_handle, 
        &user_id, 
        &delegated_cred);
    
    if(result == GLOBUS_FALSE)
    {
        fprintf(stderr, "CLIENT: Authentication failed\n");
        exit(1);
    }

    major_status = gss_inquire_context(
            &minor_status,
            context_handle,
            NULL,
            NULL,
            NULL,
            NULL,
            &flags,
            NULL,
            NULL);


    if (major_status == GSS_S_COMPLETE)
    {
        if (!(flags & GSS_C_TRANS_FLAG))
        {
            return;
        }
    }
    

    result = globus_gsi_gssapi_test_receive_hello(client_args->fd,
                                                  context_handle);

    if(result == GLOBUS_FALSE)
    {
	fprintf(stderr, "CLIENT: Receive hello failed\n");
        exit(1);
    }    

    globus_gsi_gssapi_test_cleanup(&context_handle,
                                   user_id,
                                   &delegated_cred);
    user_id = NULL;
    
    close(client_args->fd);

    free(client_args);

    return;
}
