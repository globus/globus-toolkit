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
