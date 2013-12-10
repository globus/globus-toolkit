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

#include "globus_gram_client.h"
#include "gssapi.h"

#include <stdio.h> 
#include <string.h>

static
void
nonblocking_callback_func(
    void *				user_callback_arg,
    globus_gram_protocol_error_t	errorcode,
    const char *			job_contact,
    globus_gram_protocol_job_state_t	state,
    globus_gram_protocol_error_t	job_failure_code);

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_bool_t			done;
    int					errorcode;
    int					status;
} my_monitor_t;

int main(int argc, char ** argv)
{
    int					rc;
    char *				rm_contact;
    my_monitor_t			Monitor;
    gss_cred_id_t                       credential;
    globus_gram_client_attr_t           attr;
    OM_uint32                           major_status, minor_status;

    /* Retrieve relevant parameters from the command line */ 
    if (argc < 2 || argc > 3)
    {
        /* invalid parameters passed */
        printf("Usage: %s resource_manager_contact [credential path]\n",
                argv[0]);
        return(1);
    }

    rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "ERROR: gram module activation failed\n");
	return(1);
    }

    globus_gram_client_attr_init(&attr);

    if(argc == 3)
    {
        gss_buffer_desc buffer;
        buffer.value = globus_libc_malloc(
                strlen("X509_USER_PROXY=") +
                strlen(argv[2]) + 1);
        sprintf(buffer.value, "X509_USER_PROXY=%s", argv[2]);
        buffer.length = strlen(buffer.value);

        major_status = gss_import_cred(
                &minor_status,
                &credential,
                GSS_C_NO_OID,
                1,
                &buffer,
                0,
                NULL);
        if(major_status != GSS_S_COMPLETE)
        {
            fprintf(stderr, "ERROR: could not import cred from %s\n", argv[2]);
            return(1);
        }
        rc = globus_gram_client_attr_set_credential(attr, credential);

        if(rc != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "ERROR: setting credential on attr\n");
            return 1;
        }
        globus_free(buffer.value);
    }

    rm_contact = globus_libc_strdup(argv[1]);

    globus_mutex_init(&Monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&Monitor.cond, (globus_condattr_t *) NULL);

    globus_mutex_lock(&Monitor.mutex);
    Monitor.done = GLOBUS_FALSE;
    Monitor.status = 0;
    Monitor.errorcode = 0;

    rc = globus_gram_client_register_ping(rm_contact,
			 attr,
		         nonblocking_callback_func,
			 &Monitor);

    if(rc != GLOBUS_SUCCESS)
    {
	Monitor.errorcode = rc;
	Monitor.done = GLOBUS_TRUE;
    }
    while(!Monitor.done)
    {
	globus_cond_wait(&Monitor.cond, &Monitor.mutex);
    }
    globus_mutex_unlock(&Monitor.mutex);

    globus_mutex_destroy(&Monitor.mutex);
    globus_cond_destroy(&Monitor.cond);

    if(argc == 3)
    {
        gss_release_cred(&minor_status, &credential);
    }
    globus_gram_client_attr_destroy(&attr);

    /* Deactivate GRAM */
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    return Monitor.errorcode;
}

static
void
nonblocking_callback_func(
    void *				user_callback_arg,
    globus_gram_protocol_error_t	errorcode,
    const char *			job_contact,
    globus_gram_protocol_job_state_t	state,
    globus_gram_protocol_error_t	job_failure_code)
{
    my_monitor_t * Monitor = (my_monitor_t *) user_callback_arg;

    globus_mutex_lock(&Monitor->mutex);

    Monitor->errorcode = errorcode;
    /*   Monitor->job_failure_code = job_failure_code; */
    Monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&Monitor->cond);

    globus_mutex_unlock(&Monitor->mutex);
}
