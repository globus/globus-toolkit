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

static globus_mutex_t mutex;
static globus_cond_t cond;
static volatile globus_bool_t done;

static
void
wait_func(int timeout,
	  globus_bool_t * signalled,
	  globus_bool_t * timedout);

/* Test definitions:
 * time when signal function should be called,
 * timeout for globus_cond_timed_wait()
 */

/* test1: signal before timeout */
int test1[] = {1, 5 };

/* test2: timeout before signal */
int test2[] = {5, 1 };

/*
 * test3: timeout before signal, 
 *        timeout finished before cond_wait called
 */
int test3[] = {5, -1 };

int *tests[] = { test1, test2, test3, NULL};

static
void
wakeup_func(
    void *			        arg)
{
    globus_mutex_lock(&mutex);
    done = GLOBUS_TRUE;
    globus_cond_signal(&cond);
    globus_mutex_unlock(&mutex);
}

int main()
{
    int			i;
    int			successful_tests=0;
    globus_reltime_t    delay_time;

    globus_module_activate(GLOBUS_COMMON_MODULE);

    globus_mutex_init(&mutex, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_libc_printf("Testing globus_cond_timedwait()\n\n");

    for(i = 0; tests[i] != GLOBUS_NULL; i++)
    {
	globus_bool_t signalled = GLOBUS_FALSE;
	globus_bool_t timedout = GLOBUS_FALSE;
	globus_bool_t ok;

	globus_libc_printf("Test %d: Signal at %d, timeout at %d\n",
	                   i+1,
	                   tests[i][0],
	                   tests[i][1]);

	done = GLOBUS_FALSE;

        GlobusTimeReltimeSet(delay_time, tests[i][0], 0);	
	globus_callback_register_oneshot(GLOBUS_NULL,
	                                 &delay_time,
					 wakeup_func,
					 GLOBUS_NULL);
	wait_func(tests[i][1],
		  &signalled,
		  &timedout);
	ok = GLOBUS_TRUE;
	if(((tests[i][0] < tests[i][1]) && signalled) ||
	   ((tests[i][0] > tests[i][1]) && !signalled))
	{
	    globus_libc_printf("Test %d: Signalled state as expected\n",
			       i+1);
	}
	else
	{
	    globus_libc_printf("Test %d: Signalled state not as expected\n",
			       i+1);
	    ok = GLOBUS_FALSE;
	}
	if(((tests[i][0] < tests[i][1]) && !timedout) ||
	   ((tests[i][0] > tests[i][1]) && timedout))
	{
	    globus_libc_printf("Test %d: Timedout state as expected\n",
			       i+1);
	}
	else
	{
	    globus_libc_printf("Test %d: Timedout state not as expected\n",
			       i+1);
	    ok = GLOBUS_FALSE;
	}
	globus_libc_printf("Test %d: %s\n",
	                   i+1,
	                   ok ? "SUCCESS" : "FAILED");
	if(ok)
	{
	    successful_tests++;
	}
    }

    if(successful_tests == i)
    {
        globus_libc_printf("--------------------------------\n"
	                   "ALL TESTS COMPLETED SUCCESSFULLY\n"
	                   "--------------------------------\n");
    }
    else
    {
        globus_libc_printf("-----------------------\n"
	                   "%d OF %d TESTS SUCCESSFUL\n"
	                   "-----------------------\n",
	                   successful_tests, i);
    }
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return (successful_tests == i) ? 0 : 1;
}

static
void
wait_func(int delta,
	  int * signalled,
	  int * timedout)
{
    int			save_errno = 0;
    globus_abstime_t	timeout;

    globus_mutex_lock(&mutex);

    /* Absolute timeout */
    timeout.tv_sec = time(GLOBUS_NULL) + delta;
    timeout.tv_nsec = 0;

    while(!done)
    {
	save_errno = globus_cond_timedwait(&cond,
					   &mutex,
					   &timeout);
	if(save_errno == ETIMEDOUT)
	{
	    /* time-out occurred */
	    *timedout = GLOBUS_TRUE;
	    break;
	}
    }
    *signalled = done;

    globus_mutex_unlock(&mutex);
}
