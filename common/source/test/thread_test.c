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

/**
 * @file thread_test.c
 * @brief Globus Thread Test
 */

#include "globus_common.h"
#include "globus_test_tap.h"

#include <stdio.h>

#include "globus_preload.h"

#define DEBUG_LEVEL 1

typedef struct
{
    globus_mutex_t              mutex;
    globus_cond_t               cond;
    globus_bool_t                   done;
}
prod_data_t;


int                     nproducers;
int                     nconsumers;
int                     nliveproducers;
int                     nliveconsumers;

globus_fifo_t                   queue;
globus_mutex_t                  queue_mutex;
globus_cond_t                   queue_cond;

globus_mutex_t                  common_mutex;
globus_cond_t                   common_cond;

/******************************************************************************
               Module specific functions
******************************************************************************/
long
thread_id_assign()
{
    static int                  cnt = 0;
    long                        thread_id;

    globus_mutex_lock(&common_mutex);
    {
        thread_id = cnt++;
    }
    globus_mutex_unlock(&common_mutex);
    return thread_id;
}

void
wait_for_all(long thread_id)
{
    static int                  cnt_arrived = 0;
    static int                  cnt_leaving = 0;

    globus_mutex_lock(&common_mutex);
    {
        while(cnt_leaving > 0)
        {
            if (DEBUG_LEVEL > 1)
            {
                printf("%04ld: wait_for_all() - waiting (next)\n",
                       thread_id);
            }

            globus_cond_wait(&common_cond, &common_mutex);
        }

        cnt_arrived++;

        if (cnt_arrived  < nproducers + nconsumers + 1)
        {
            if (DEBUG_LEVEL > 1)
            {
                printf("%04ld: wait_for_all() - waiting (current)\n",
                       thread_id);
            }
            
            do
            {
                globus_cond_wait(&common_cond, &common_mutex);
            }
            while(cnt_arrived % (nproducers + nconsumers + 1) != 0);

            cnt_leaving--;

            if (cnt_leaving == 0)
            {
                cnt_arrived = 0;
                
                globus_cond_broadcast(&common_cond);
                
                if (DEBUG_LEVEL > 1)
                {
                    printf("%04ld: wait_for_all() - signalling (next)\n",
                           thread_id);
                }
            }
        }
        else
        {
            if (DEBUG_LEVEL > 1)
            {
                printf("%04ld: wait_for_all() - signalling (current)\n",
                       thread_id);
            }

            cnt_leaving = nproducers + nconsumers;
            
            globus_cond_broadcast(&common_cond);
        }
    }
    globus_mutex_unlock(&common_mutex);

    if (DEBUG_LEVEL > 1)
    {
        printf("%04ld: wait_for_all() - exiting\n", thread_id);
    }
}

void *
producer(
    void *                  nitems_arg)
{
    long                        i;
    long                        nitems;
    prod_data_t                 data;
    long                        thread_id;

    nitems = (intptr_t) nitems_arg;

    globus_mutex_init(&data.mutex, (globus_mutexattr_t *) GLOBUS_NULL);
    globus_cond_init(&data.cond, (globus_condattr_t *) GLOBUS_NULL);
    data.done = GLOBUS_FALSE;

    thread_id = thread_id_assign();
    
    wait_for_all(thread_id);
    
    for (i = 0; i < nitems ; i++)
    {

        globus_mutex_lock(&queue_mutex);
        {
            globus_fifo_enqueue(&queue, &data);
            globus_cond_signal(&queue_cond);
        }
        globus_mutex_unlock(&queue_mutex);

        
        globus_mutex_lock(&data.mutex);
        {
            while(data.done == GLOBUS_FALSE)
            {
                if (DEBUG_LEVEL > 1)
                {
                    printf("%04ld: producer() - "
                           "waiting for confirmation %ld\n",
                           thread_id,
                           i);
                }

                globus_cond_wait(&data.cond, &data.mutex);
            }
            data.done = GLOBUS_FALSE;
        }
        globus_mutex_unlock(&data.mutex);
    }

    globus_cond_destroy(&data.cond);
    globus_mutex_destroy(&data.mutex);

    wait_for_all(thread_id);

    globus_mutex_lock(&common_mutex);
    nliveproducers--;
    if (nliveproducers == 0 && nliveconsumers == 0)
    {
        globus_cond_broadcast(&common_cond);
    }
    globus_mutex_unlock(&common_mutex);

    return NULL;
}

void *
consumer(
    void *                  nitems_arg)
{
    int                     i;
    long                        nitems;
    prod_data_t *               data;
    long                        thread_id;
    
    nitems = (intptr_t) nitems_arg;

    thread_id = thread_id_assign();
    
    wait_for_all(thread_id);
    
    for (i = 0; i < nitems ; i++)
    {
        globus_mutex_lock(&queue_mutex);
        {
            while(globus_fifo_empty(&queue))
            {
                if (DEBUG_LEVEL > 1)
                {
                    printf("%04ld: consumer() - waiting for data item %d\n",
                           thread_id,
                           i);
                }
            
                globus_cond_wait(&queue_cond, &queue_mutex);
            }
            data = globus_fifo_dequeue(&queue);
        }
        globus_mutex_unlock(&queue_mutex);
        
        globus_mutex_lock(&data->mutex);
        {
            data->done = GLOBUS_TRUE;

            globus_cond_broadcast(&data->cond);
        }
        globus_mutex_unlock(&data->mutex);
    }

    wait_for_all(thread_id);

    globus_mutex_lock(&common_mutex);
    nliveconsumers--;
    if (nliveproducers == 0 && nliveconsumers == 0)
    {
        globus_cond_broadcast(&common_cond);
    }
    globus_mutex_unlock(&common_mutex);
    
    return NULL;
}

/**
 * @brief Thread Consumer / Producer Test
 * @test
 * The thread_test creates a p producer threads and c consumer threads,
 * and then has the producers (combined) create n pieces of data to be
 * consumed by the consumer threads.
 *
 * This test exercises globus_mutex_lock(), globus_mutex_unlock(),
 * globus_cond_wait(), globus_cond_signal(), and globus_cond_broadcast()
 */
int
thread_test(int np, int nc, int ni)
{
    int                     i;
    int                     nitems;
    long                    thread_id;
    globus_thread_t                             thread;

    /*
     * Assign a thread id to the main thread so that it's output is uniquely
     * tagged.  Note: we do not use the return value of globus_thread_self()
     * since it could be a pointer or a structure, the latter which is
     * extremely hard to print without knowing the implementation details.
     */
    printf(" thread test begin\n");

    globus_module_activate(GLOBUS_COMMON_MODULE);

    nliveproducers = nproducers = np;
    nliveconsumers = nconsumers = nc;
    nitems = ni;

    /*
     * Initialize queue and queue concurrency control structures
     */
    globus_fifo_init(&queue);
    globus_mutex_init(&queue_mutex, (globus_mutexattr_t *) GLOBUS_NULL);
    globus_cond_init(&queue_cond, (globus_condattr_t *) GLOBUS_NULL);

    /*
     * Initialize shared (common) concurrency control structures
     */
    globus_mutex_init(&common_mutex, (globus_mutexattr_t *) GLOBUS_NULL);
    globus_cond_init(&common_cond, (globus_condattr_t *) GLOBUS_NULL);

    thread_id = thread_id_assign();

    /*
     * Start producer and consumer threads
     */
    printf(" %04ld: starting %d producer and %d consumer threads\n",
            thread_id,
            nproducers,
            nconsumers);
    
    for (i = 0 ; i < nproducers ; i ++)
    {
        int                     rc;
        intptr_t                nitems_per_thread;

        nitems_per_thread = nitems / nproducers +
            ((i < nitems % nproducers) ? 1 : 0);
        
        rc =
            globus_thread_create(
            &thread,
            NULL,
            producer,
            (void *) nitems_per_thread);
        
        if (rc != 0)
        {
            fprintf(stderr, "%04ld: main() - ERROR: "
                    "unable to create producer thread %d\n",
                    thread_id,
                    i);
            exit(1);
        }
    }
    
    for (i = 0 ; i < nconsumers ; i ++)
    {
        int                     rc;
        intptr_t                nitems_per_thread;

        nitems_per_thread = nitems / nconsumers +
            ((i < nitems % nconsumers) ? 1 : 0);
        
        rc =
            globus_thread_create(
            &thread,
            NULL,
            consumer,
            (void *) nitems_per_thread);

        if (rc != 0)
        {
            fprintf(stderr, " %04ld: main() - ERROR: "
                    "unable to create consumer thread %d\n",
                    thread_id,
                    i);
        }
    }

    /*
     * Wait for all threads to be started
     */
    wait_for_all(thread_id);

    printf(" %04ld: main() - all threads started\n",
            thread_id);
    
    /*
     * Wait for all threads to complete their work
     */
    wait_for_all(thread_id);

    printf(" %04ld: main() - all threads have completed their work\n",
            thread_id);

    globus_mutex_lock(&common_mutex);
    while (nliveconsumers > 0 || nliveproducers > 0)
    {
        globus_cond_wait(&common_cond, &common_mutex);
    }
    printf(" %04ld: main() - all threads terminated\n", thread_id);
    globus_mutex_unlock(&common_mutex);

    globus_cond_destroy(&common_cond);
    globus_mutex_destroy(&common_mutex);
    
    globus_cond_destroy(&queue_cond);
    globus_mutex_destroy(&queue_mutex);
    globus_fifo_destroy(&queue);
    
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return 0;
}

int
main(
    int                     argc,
    char *                  argv[])
{
    const char * thread_model = THREAD_MODEL;
    globus_bool_t no_threads = GLOBUS_FALSE;

    LTDL_SET_PRELOADED_SYMBOLS();
    globus_thread_set_model(thread_model);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("1..4\n");

    no_threads = (thread_model == NULL || strcmp(thread_model, "none") == 0);
    
    skip(no_threads,
        ok(thread_test(10, 5, 10) == 0, "10_producers_5_consumers_10_items"));
    skip(no_threads, 
        ok(thread_test(10, 5, 100) == 0, "10_producers_5_consumers_100_items"));
    skip(no_threads,
        ok(thread_test(5, 10, 10) == 0, "5_producers_10_consumers_10_items"));
    skip(no_threads, 
        ok(thread_test(5, 10, 100) == 0, "5_producers_10_consumers_100_items"));
    return TEST_EXIT_CODE;
}
