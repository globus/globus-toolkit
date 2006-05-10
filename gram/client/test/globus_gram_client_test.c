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

/* A C Program to test GRAM, submitting a simple job, and 
 * waiting until it executes
 */

/*************************************************
                Included Files
**************************************************/

/* The header file which includes all the GRAM functions */
#include "globus_gram_client.h"

#include <stdio.h> 
#include <string.h>


/**************************************************
                  Functions
***************************************************/


/* This is a function that you write..later...but which must 
 * have this definition. It is the function used when the remote 
 * Job Manager needs to contact your local program to inform it 
 * about the status of the remote  program. It is passed along 
 * with the the job_request to the remote computer
 */

static void callback_func(void * user_callback_arg,
                          char * job_contact,
                          int state,
                          int errorcode);

/**************************************************
                 Type Definitions
*************************************************/

/* Setting up the GRAM monitor. The monitor will stall
 * this program until the remote program is terminated, 
 * either through failure or naturally. Without the monitor,
 * this program would submit the job, and end before the job
 * completed. The monitor works with a lock. Only one function
 * may access the Done flag at a time, so in order to access it,
 * the gram must set a lock on the monitor variable, so that 
 * nothing else may access it, then change it, and finally 
 * unlock it. This is seen later in the code.
 */ 


/* This whole structure is the monitor */

typedef struct
{
    globus_mutex_t mutex;
    globus_cond_t cond;
    globus_bool_t done;
    int simple_install_test;
} my_monitor_t;


/***************************************************
                   Main Code
***************************************************/

int main(int argc, char ** argv)
{
    int job_state_mask;
    int rc; /* The return value of the request function. 
             * If successful, it should be 0 */

    char * callback_contact; /* This is the identifier for 
                              * the callback, returned by 
                              * globus_gram_job_request
                              */

    char * job_contact; /* This is the identifier for the job,
                         * returned by globus_gram_job_request
                         */

    char * rm_contact;
    char * specification;
    my_monitor_t Monitor;

    /* Retrieve relevant parameters from the command line */ 

    if (argc!= 3 && argc != 4 && argc != 5)
    {
        /* invalid parameters passed */
        printf("Usage: %s <rm_contact> <specification> "
                         "<job_state_mask> <-debug>\n",
                argv[0]);
        return(1);
    }

    if ((rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE))
	!= GLOBUS_SUCCESS)
    {
	printf("\tERROR: gram module activation failed\n");
	return(1);
    }

    rm_contact = (char *)globus_malloc(strlen(argv[1])+1);
    strcpy(rm_contact, argv[1]);
    specification = (char *)globus_malloc(strlen(argv[2])+1);
    strcpy(specification, argv[2]);
    if (argc > 3)
    {
        Monitor.simple_install_test = 0;
        job_state_mask = atoi(argv[3]);
    }
    else
    {
        /* this will tell the callback function to NOT print any messages
         * but to still detect when the job is done.  This is intended for
         * an administrator who wants to verify if a gatekeeper is up or down.
         */

	printf("\n\tTEST: running simple install test");
        Monitor.simple_install_test = 1;
        job_state_mask = GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL;
    }

    /* Initialize the monitor function to look for callbacks.  It 
     * initializes the locking mechanism, and then the condition 
     * variable
     */

    globus_mutex_init(&Monitor.mutex, (globus_mutexattr_t *) NULL);
    globus_cond_init(&Monitor.cond, (globus_condattr_t *) NULL);

    /* entering the monitor and clearing the flag. Locking the 
     * Monitor to prevent anything else from changing the value of
     * Monitor.done
     */
    globus_mutex_lock(&Monitor.mutex);

    /* Change the value of Monitor.done to false, initializing it */	
    Monitor.done = GLOBUS_FALSE;

    /* Releasing the lock on the monitor, letting anything else access it */
    globus_mutex_unlock(&Monitor.mutex);

    /* Setting up the communications port for returning the callback. 
     * You pass it the callback function.  The callback_contact is the
     * callback identifier returned by the function
     */

    globus_gram_client_callback_allow(callback_func,
                       (void *) &Monitor,
                       &callback_contact);

    printf("\n\tTEST: submitting to resource manager...\n");

    /* Send the GRAM request.  The rm_contact, specification, and
     * job_state_mask were retrieved earlier from the command line    
     * The callback_contact was just returned by 
     * globus_gram_client_callback_allow.  The job_request is returned by
     * this function
     */

    rc = globus_gram_client_job_request(rm_contact,
                         specification,
	                 job_state_mask,
		         callback_contact,
                         &job_contact);

    if (rc != 0) /* if there is an error */
    {
        printf("TEST: gram error: %d - %s\n", 
                rc, 
                /* translate the error into english */
                globus_gram_client_error_string(rc));
        return(1);
    }

#ifdef SIGNAL
    printf("\tTEST: waiting 3 seconds before signaling job manager...\n");
    sleep(3);
    printf("\tTEST: sending cancel _signal_ to job manager...\n");

    if ((rc = globus_gram_client_job_signal(job_contact,
                                         GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL,
                                         "blah blah",
                                         &job_status,
                                         &failure_code)) != 0)
    {
       printf("\tTEST: Failed to cancel job.\n");
       printf("\tTEST: gram error: %d - %s\n", 
               rc,
               globus_gram_client_error_string(rc));
       return(1);
    }
    else
    {
       printf("\tTEST: job cancel was successful.\n");
    }
#endif

#ifdef CANCEL
    sleep(3);
    printf("\tTEST: sending cancel to job manager...\n");

    if ((rc = globus_gram_client_job_cancel(job_contact)) != 0)
    {
       printf("\tTEST: Failed to cancel job.\n");
       printf("\tTEST: gram error: %d - %s\n", 
               rc,
               globus_gram_client_error_string(rc));
       return(1);
    }
    else
    {
       printf("\tTEST: job cancel was successful.\n");
    }
#endif

/* Wait until there is a callback saying there was a termination, either
 * successful or failed.  We lock the Monitor again so as to ensure that
 * no one else tampers with it. Then we wait until the condition is
 * signaled by the callback_function. When it is signaled, and
 * Monitor.done is set to GRAM_TRUE - (these two things always happen
 * in conjunction in our callback_func) Then we unlock the monitor and
 * continue the program.
 */

    globus_mutex_lock(&Monitor.mutex);
    while (!Monitor.done)
    {
       /* Within the cond_wait function, it unlocks the monitor,
        * allowing the callback_func to take the lock. When it gets a
        * cond_signal, it re-locks the monitor, and returns to this
        * program.  But DO NOT unlock the monitor yourself- use the
        * globus_gram_cond_wait function, as it insures safe
        * unlocking.
        */
        globus_cond_wait(&Monitor.cond, &Monitor.mutex);
    } /* endwhile */

    globus_mutex_unlock(&Monitor.mutex);

    /* Remove Monitor.  Given that we are done with our monitor, (it has
     * already held the program until the job completed) we can now dispose
     * of it. We destroy both the mutex and the condition.  This frees up any
     * space it may have occupied.
     */

    globus_mutex_destroy(&Monitor.mutex);
    globus_cond_destroy(&Monitor.cond);

    /* Free up the resources of the job_contact, as the job is over, and
     * the contact is now useless.
     */
    globus_gram_client_job_contact_free(job_contact);

    /* Deactivate GRAM */
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    if (Monitor.simple_install_test == 0)
    {
        printf("\tTEST: test was successful.\n");
        return(0);
    }
    else
    {
        printf("\tTEST: test was NOT successful.\n");
        return(1);
    }
}

/******************************************************************
 * This is the callback function, as per the definition. We can  write
 * whatever we want into the function, but remember that the 
 * cond_signal must be triggered and Monitor.done must also be set  to
 * true to exit the waiting loop in the main code. The function is called
 * from the job manager, which provides values for state and errorcode
 */

static void
callback_func(void * user_callback_arg,
              char * job_contact,
              int state,
              int errorcode)
{
    my_monitor_t * Monitor = (my_monitor_t *) user_callback_arg;

    switch(state)
    {
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING:
        if (!(Monitor->simple_install_test))
            printf("\tTEST: Got GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING"
                   " from job manager\n");
	break; /* Reports state change to the user */

    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE:
        if (!(Monitor->simple_install_test))
            printf("\tTEST: Got GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE"
                   " from job manager\n");
	break; /* Reports state change to the user */
   
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
        if (!(Monitor->simple_install_test))
            printf("\tTEST: Got GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED"
                   " from job manager\n");
        globus_mutex_lock(&Monitor->mutex);
        Monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&Monitor->cond);
        globus_mutex_unlock(&Monitor->mutex);
	break; /* Reports state change to the user */

    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
        if (!(Monitor->simple_install_test))
            printf("\tTEST: Got GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE"
                   " from job manager\n");
        globus_mutex_lock(&Monitor->mutex);
        Monitor->done = GLOBUS_TRUE;
        Monitor->simple_install_test = 0;
        globus_cond_signal(&Monitor->cond);
        globus_mutex_unlock(&Monitor->mutex);
	break; /* Reports state change to the user */
    }
}
