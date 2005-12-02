/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_gram_client.h"
#include "gssapi.h"

#include <stdio.h> 
#include <string.h>

static
void
callback_func(
    void *				user_callback_arg,
    char *				job_contact,
    int					state,
    int					job_failure_code);

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
    char *				job_contact;
} my_monitor_t;

int main(int argc, char ** argv)
{
    int					rc;
    char *				callback_contact;
    char *				rm_contact;
    char *				specification;
    my_monitor_t			Monitor;
    gss_cred_id_t                       credential;
    globus_gram_client_attr_t           attr;

    /* Retrieve relevant parameters from the command line */ 
    if (argc < 3 || argc > 4)
    {
        /* invalid parameters passed */
        printf("Usage: %s resource_manager_contact rsl_spec [credential path]\n",
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

    if(argc == 4)
    {
        OM_uint32 major_status, minor_status;
        gss_buffer_desc buffer;
        buffer.value = globus_libc_malloc(
                strlen("X509_USER_PROXY=") +
                strlen(argv[3]) + 1);
        sprintf(buffer.value, "X509_USER_PROXY=%s", argv[3]);
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
            fprintf(stderr, "ERROR: could not import cred from %s\n", argv[3]);
            return(1);
        }
        rc = globus_gram_client_attr_set_credential(attr, credential);

        if(rc != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "ERROR: setting credential on attr\n");
            return 1;
        }
    }

    rm_contact = globus_libc_strdup(argv[1]);
    specification = globus_libc_strdup(argv[2]);

    globus_mutex_init(&Monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&Monitor.cond, (globus_condattr_t *) NULL);

    globus_gram_client_callback_allow(callback_func,
                       (void *) &Monitor,
                       &callback_contact);

    globus_mutex_lock(&Monitor.mutex);
    Monitor.done = GLOBUS_FALSE;
    Monitor.job_contact = GLOBUS_NULL;
    Monitor.status = 0;
    Monitor.errorcode = 0;

    rc = globus_gram_client_register_job_request(rm_contact,
                         specification,
	                 GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE|
	                 GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED,
		         callback_contact,
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

    globus_gram_client_job_contact_free(Monitor.job_contact);
    globus_gram_client_attr_destroy(&attr);
    globus_gram_client_callback_disallow(callback_contact);
    globus_free(callback_contact);
    globus_free(rm_contact);
    globus_free(specification);
    
    /* Deactivate GRAM */
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    return Monitor.errorcode;
}

static
void
callback_func(void * user_callback_arg,
              char * job_contact,
              int state,
              int errorcode)
{
    nonblocking_callback_func(user_callback_arg,
	                      0,
			      job_contact,
			      state,
			      errorcode);
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
    if(Monitor->job_contact == GLOBUS_NULL)
    {
	Monitor->job_contact = globus_libc_strdup(job_contact);
    }

    switch(state)
    {
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
        Monitor->done = GLOBUS_TRUE;
	Monitor->errorcode = job_failure_code;
        globus_cond_signal(&Monitor->cond);
	break;
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
        Monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&Monitor->cond);
	break;
    default:
	if(errorcode != 0)
	{
	    Monitor->done = GLOBUS_TRUE;
	    Monitor->errorcode = errorcode;
	}
        globus_cond_signal(&Monitor->cond);
	break;
    }
    globus_mutex_unlock(&Monitor->mutex);
}
