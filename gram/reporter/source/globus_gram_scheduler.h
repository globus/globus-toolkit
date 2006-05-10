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

/******************************************************************************
globus_gram_scheduler.h
 
Description:
    This header contains the exported interface of the GRAM scheduler.
 
CVS Information:
******************************************************************************/
 
#ifndef GLOBUS_GRAM_SCHEDULER_INCLUDE
#define GLOBUS_GRAM_SCHEDULER_INCLUDE

/******************************************************************************
                               Includes
******************************************************************************/

#include "globus_common.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/******************************************************************************
                               Type definitions
******************************************************************************/

typedef struct globus_l_gram_scheduler_s
{
    int add_entries_flag;
    int maxtime;
    int maxcputime;
    int maxcount;
    int maxrunningjobs;
    int maxjobsinqueue;
    int maxtotalmemory;
    int maxsinglememory;
    int totalnodes;
    int freenodes;
    char * queuename;
    char * whenactive;
    char * status;
    char * dispatchtype;
    char * priority;
    char * alloweduserlist; /* char * of globusUserNames */
    char * jobwait;
    char * schedulerspecific;
    globus_list_t * entry_list; /* globus_gram_scheduler_queue_entry_t */
} globus_gram_scheduler_t;

typedef struct globus_l_gram_scheduler_entry_s
{
    char * local_job_id;
    char * global_job_id;
    char * local_user_name;
    char * global_user_name;
    int count;
    char * status;
    unsigned long start_time;
    unsigned long finish_time;
    unsigned long elapsed_time;
    int requested_memory;
    int requested_time;
    char * schedulerspecific;
    char * specification;
} globus_gram_scheduler_entry_t;


/******************************************************************************
                              Function prototypes
******************************************************************************/

/*-----------------------------------------------------------------------
 * This function gets a list of the queue(s) paramters and entries managed by
 * the GRAM.
 */
extern int
globus_gram_scheduler_queue_list_get(
        char * script_cmd,
        globus_list_t ** queue_list);

/*-----------------------------------------------------------------------
 * This function free the memory from a previous
 * globus_gram_queue_list_get() call
 */
extern int
globus_gram_scheduler_queue_list_free(
        globus_list_t * queue_list);

/*-----------------------------------------------------------------------
 * This function initializes the passed in scheduler queue node
 */
extern void
globus_i_gram_q_init(
        globus_gram_scheduler_t * q_node);

/*-----------------------------------------------------------------------
 * This function initializes the passed in scheduler queue entry node
 */
extern void
globus_i_gram_q_entry_init(
        globus_gram_scheduler_entry_t * q_entry_node);

/******************************************************************************
 *                    Module Definition
 *****************************************************************************/
/*
 * #define GLOBUS_GRAM_SCHEDULER_MODULE (&globus_i_gram_scheduler_module)
 * extern globus_module_descriptor_t globus_i_gram_scheduler_module;
*/

EXTERN_C_END

#endif /* GLOBUS_GRAM_SCHEDULER_INCLUDE */
