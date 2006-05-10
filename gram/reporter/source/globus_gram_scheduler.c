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
globus_gram_scheduler.c

Description:
    Globus Job Manager Scheduler API

CVS Information:
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/


/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"
#include "globus_gram_scheduler.h"
#include <string.h>

/******************************************************************************
                          Module specific prototypes
******************************************************************************/

static int
globus_l_gram_load_q_field(globus_gram_scheduler_t * q_node,
                           char * field_name,
                           char * field_value);

static int
globus_l_gram_load_q_entry_field(globus_gram_scheduler_entry_t * q_entry_node,
                                 char * field_name,
                                 char * field_value);

/******************************************************************************
Function:       globus_i_gram_q_init()
Description:
Parameters:
Returns:
******************************************************************************/
void
globus_i_gram_q_init(globus_gram_scheduler_t * q_node)
{
    q_node->add_entries_flag = 0;
    q_node->maxtime = 0;
    q_node->maxcputime = 0;
    q_node->maxcount = 0;
    q_node->maxrunningjobs = 0;
    q_node->maxjobsinqueue = 0;
    q_node->maxtotalmemory = 0;
    q_node->maxsinglememory = 0;
    q_node->totalnodes = 0;
    q_node->freenodes = 0;
    q_node->queuename = GLOBUS_NULL;
    q_node->whenactive = GLOBUS_NULL;
    q_node->status = GLOBUS_NULL;
    q_node->dispatchtype = GLOBUS_NULL;
    q_node->priority = GLOBUS_NULL;
    q_node->alloweduserlist = GLOBUS_NULL;
    q_node->jobwait = GLOBUS_NULL;
    q_node->schedulerspecific = GLOBUS_NULL;
    q_node->entry_list = GLOBUS_NULL;
    return;

} /* globus_i_gram_q_init() */


/******************************************************************************
Function:       globus_i_gram_q_entry_init()
Description:
Parameters:
Returns:
******************************************************************************/
void
globus_i_gram_q_entry_init(globus_gram_scheduler_entry_t * q_entry_node)
{
    q_entry_node->local_job_id = GLOBUS_NULL;
    q_entry_node->global_job_id = GLOBUS_NULL;
    q_entry_node->local_user_name = GLOBUS_NULL;
    q_entry_node->global_user_name = GLOBUS_NULL;
    q_entry_node->count = 0;
    q_entry_node->status = GLOBUS_NULL;
    q_entry_node->start_time = 0;
    q_entry_node->finish_time = 0;
    q_entry_node->elapsed_time = 0;
    q_entry_node->requested_memory = 0;
    q_entry_node->requested_time = 0;
    q_entry_node->schedulerspecific = GLOBUS_NULL;
    q_entry_node->specification = GLOBUS_NULL;
    return;

} /* globus_i_gram_q_entry_init() */


/******************************************************************************
Function:       globus_l_gram_load_q_field()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_load_q_field(globus_gram_scheduler_t * q_node,
                           char * field_name,
                           char * field_value)
{

    if ( strcasecmp(field_name, "notlistingjobentries") == 0 )
        q_node->add_entries_flag = 1;

    else if ( strcasecmp(field_name, "maxtime") == 0 )
        if (field_value)
            q_node->maxtime = atoi(field_value);
        else
            q_node->maxtime = 0;

    else if ( strcasecmp(field_name, "maxcount") == 0 )
        if (field_value)
            q_node->maxcount = atoi(field_value);
        else
            q_node->maxcount = 0;

    else if ( strcasecmp(field_name, "maxcputime") == 0 )
        if (field_value)
            q_node->maxcputime = atoi(field_value);
        else
            q_node->maxcputime = 0;

    else if ( strcasecmp(field_name, "maxrunningjobs") == 0 )
        if (field_value)
            q_node->maxrunningjobs = atoi(field_value);
        else
            q_node->maxrunningjobs = 0;

    else if ( strcasecmp(field_name, "maxjobsinqueue") == 0 )
        if (field_value)
            q_node->maxjobsinqueue = atoi(field_value);
        else
            q_node->maxjobsinqueue = 0;

    else if ( strcasecmp(field_name, "maxtotalmemory") == 0 )
        if (field_value)
            q_node->maxtotalmemory = atoi(field_value);
        else
            q_node->maxtotalmemory = 0;

    else if ( strcasecmp(field_name, "maxsinglememory") == 0 )
        if (field_value)
            q_node->maxsinglememory = atoi(field_value);
        else
            q_node->maxsinglememory = 0;

    else if ( strcasecmp(field_name, "totalnodes") == 0 )
        if (field_value)
            q_node->totalnodes = atoi(field_value);
        else
            q_node->totalnodes = 0;

    else if ( strcasecmp(field_name, "freenodes") == 0 )
        if (field_value)
            q_node->freenodes = atoi(field_value);
        else
            q_node->freenodes = 0;

    else if ( strcasecmp(field_name, "queuename") == 0 )
        q_node->queuename = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "whenactive") == 0 )
        q_node->whenactive = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "status") == 0 )
        q_node->status = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "dispatchtype") == 0 )
        q_node->dispatchtype = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "priority") == 0 )
        q_node->priority = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "alloweduserlist") == 0 )
        q_node->alloweduserlist = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "jobwait") == 0 )
        q_node->jobwait = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "schedulerspecific") == 0 )
        q_node->schedulerspecific = (char *) globus_libc_strdup(field_value);

    else
    {
        fprintf(stderr, "Notice: Unknown queue field - %s\n", field_name);
        return(1);
    }

    return(0);

} /* globus_l_gram_load_q_field() */


/******************************************************************************
Function:       globus_l_gram_load_q_entry_field()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_load_q_entry_field(globus_gram_scheduler_entry_t * q_entry_node,
                                 char * field_name,
                                 char * field_value)
{

    if ( strcasecmp(field_name, "localjobid") == 0 )
        q_entry_node->local_job_id = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "localusername") == 0 )
        q_entry_node->local_user_name=(char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "count") == 0 )
        if (field_value)
            q_entry_node->count = atoi(field_value);
        else
            q_entry_node->count = 0;

    else if ( strcasecmp(field_name, "status") == 0 )
        q_entry_node->status = (char *) globus_libc_strdup(field_value);

    else if ( strcasecmp(field_name, "starttime") == 0 )
        if (field_value)
            q_entry_node->start_time = atoi(field_value);
        else
            q_entry_node->start_time = 0;

    else if ( strcasecmp(field_name, "finishtime") == 0 )
        if (field_value)
            q_entry_node->finish_time = atoi(field_value);
        else
            q_entry_node->finish_time = 0;

    else if ( strcasecmp(field_name, "elapsedtime") == 0 )
        if (field_value)
            q_entry_node->elapsed_time = atoi(field_value);
        else
            q_entry_node->elapsed_time = 0;

    else if ( strcasecmp(field_name, "requestedmemory") == 0 )
        if (field_value)
            q_entry_node->requested_memory = atoi(field_value);
        else
       q_entry_node->requested_memory = 0;

    else if ( strcasecmp(field_name, "requestedtime") == 0 )
        if (field_value)
            q_entry_node->requested_time = atoi(field_value);
        else
       q_entry_node->requested_time = 0;

    else if ( strcasecmp(field_name, "schedulerspecific") == 0 )
       q_entry_node->schedulerspecific=(char *) globus_libc_strdup(field_value);

    else
    {
        fprintf(stderr, "Notice: Unknown queue entry field - %s\n", field_name);
        return(1);
    }

    return(0);

} /* globus_l_gram_load_q_entry_field() */


/******************************************************************************
Function:       globus_gram_scheduler_queue_list_get()
Description:
         globus_list_insert adds nodes to the front of the list, so after all
         entries are added we need to reverse the order of the entries using
         globus_list_copy_reverse().
         This is done for both the list of job entries and the list of queues.
Parameters:
Returns:
******************************************************************************/
int globus_gram_scheduler_queue_list_get( char * script_cmd,
                                          globus_list_t ** q_list )
{
    FILE *fp;
    char buf[500];
    char q_line[500];
    char q_entry[500];
    globus_gram_scheduler_t *  q_node = GLOBUS_NULL;
    globus_gram_scheduler_entry_t *  q_entry_node = GLOBUS_NULL;
    char * field_name = GLOBUS_NULL;
    char * field_value = GLOBUS_NULL;

    if ((fp = popen(script_cmd, "r")) == GLOBUS_NULL)
    {
        fprintf(stderr, "Cannot popen shell file %s\n", script_cmd);
        return(GLOBUS_FAILURE);
    }

    while (fgets(buf, sizeof(buf), fp) != GLOBUS_NULL)
    {
        buf[strlen(buf)-1] = '\0';

        if (strncmp(buf, "GRAM_SCRIPT_Q:", 14) == 0)
        {
            strcpy(q_line, &buf[14]);

            field_name = (char *) strtok(q_line, " ");

            if ( strcasecmp(field_name, "startqueue") == 0 )
            {
                if (q_node)
                    /* reverse the job entries before adding another queue
                     */
                    q_node->entry_list = (globus_list_t *)
                         globus_list_copy_reverse(q_node->entry_list);

                q_node = (globus_gram_scheduler_t *)
                     globus_libc_malloc(sizeof(globus_gram_scheduler_t));
                globus_i_gram_q_init(q_node);
            }
            else if ( strcasecmp(field_name, "endqueue") == 0 )
            {
                if (q_node)
                    globus_list_insert(q_list, (void *) q_node);
            }
            else
            {
                if (q_node)
                {
                    field_value = (char *) strtok(GLOBUS_NULL, "");

                    globus_l_gram_load_q_field(q_node,
                                               field_name,
                                               field_value);
                }
            }
        }
        else if (strncmp(buf, "GRAM_SCRIPT_QE:", 15) == 0)
        {
            strcpy(q_entry, &buf[15]);

            field_name = (char *) strtok(q_entry, " ");
            if ( strcasecmp(field_name, "startqueueentry") == 0 )
            {
                q_entry_node = (globus_gram_scheduler_entry_t *)
                     globus_libc_malloc(sizeof(globus_gram_scheduler_entry_t));

                globus_i_gram_q_entry_init(q_entry_node);
            }
            else if ( strcasecmp(field_name, "endqueueentry") == 0 )
            {
                if (q_entry_node && q_node)
                    globus_list_insert(&(q_node->entry_list), 
                        (void *) q_entry_node);
            }
            else
            {
                if ( q_entry_node )
                {
                    field_value = (char *) strtok(GLOBUS_NULL, "");

                    globus_l_gram_load_q_entry_field(q_entry_node,
                                                     field_name,
                                                     field_value);
                }
            }
        } /* if */
    } /* while */

    if (q_node)
        q_node->entry_list = (globus_list_t *) globus_list_copy_reverse(q_node->entry_list);

    if (q_list)
        *q_list = (globus_list_t *) globus_list_copy_reverse(*q_list);

    pclose(fp);

    if (globus_list_empty(*q_list))
        return(GLOBUS_FAILURE);
    else
        return(GLOBUS_SUCCESS);

} /* globus_gram_scheduler_queue_list_get() */


/******************************************************************************
Function:       globus_gram_scheduler_queue_list_free()
Description:
Parameters:
Returns:
******************************************************************************/
int globus_gram_scheduler_queue_list_free( globus_list_t * q_list )
{
    globus_list_t * q_entry_list = GLOBUS_NULL;
    globus_gram_scheduler_t *  q_node = GLOBUS_NULL;
    globus_gram_scheduler_entry_t *  q_entry_node = GLOBUS_NULL;

    if (q_list == GLOBUS_NULL)
        return GLOBUS_SUCCESS;

    while (! globus_list_empty(q_list))
    {
        q_node = (globus_gram_scheduler_t *) globus_list_first (q_list);

        q_list = globus_list_rest(q_list);
        globus_libc_free(q_node->queuename);
        globus_libc_free(q_node->whenactive);
        globus_libc_free(q_node->status);
        globus_libc_free(q_node->dispatchtype);
        globus_libc_free(q_node->priority);
        globus_libc_free(q_node->alloweduserlist);
        globus_libc_free(q_node->jobwait);
        globus_libc_free(q_node->schedulerspecific);

        q_entry_list = q_node->entry_list;

        while (! globus_list_empty(q_entry_list))
        {
            q_entry_node = (globus_gram_scheduler_entry_t *) 
                 globus_list_first (q_entry_list);
            q_entry_list = globus_list_rest(q_entry_list);

            globus_libc_free(q_entry_node->global_job_id);
            globus_libc_free(q_entry_node->global_user_name);
            globus_libc_free(q_entry_node->local_job_id);
            globus_libc_free(q_entry_node->local_user_name);
            globus_libc_free(q_entry_node->specification);
            globus_libc_free(q_entry_node->status);
            globus_libc_free(q_entry_node->schedulerspecific);
            globus_libc_free(q_entry_node);
        }
        globus_libc_free(q_node);
    }

    return GLOBUS_SUCCESS;

} /* globus_gram_scheduler_queue_list_free() */
