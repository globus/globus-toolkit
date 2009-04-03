/*
 * Copyright 1999-2009 University of Chicago
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gram_job_manager_query.c Job Manager Query Handlers
 *
 * CVS Information:
 * 
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#include "globus_gram_job_manager.h"
#include "globus_callout.h"
#include "globus_callout_constants.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_system_config_constants.h"
#include "globus_gram_jobmanager_callout_error.h"
#include <string.h>
#endif


static
globus_bool_t
globus_l_gram_job_manager_is_done(
    globus_gram_jobmanager_request_t *  request);

static
int
globus_l_gram_job_manager_cancel(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_handle_t       handle,
    globus_bool_t *                     reply);

static
int
globus_l_gram_job_manager_signal(
    globus_gram_jobmanager_request_t *  request,
    const char *                        args,
    globus_gram_protocol_handle_t       handle,
    globus_bool_t *                     reply);

static
int
globus_l_gram_job_manager_register(
    globus_gram_jobmanager_request_t *  request,
    const char *                        args);

static
int
globus_l_gram_job_manager_unregister(
    globus_gram_jobmanager_request_t *  request,
    const char *                        url,
    globus_gram_protocol_handle_t       handle);

static
int
globus_l_gram_job_manager_renew(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_handle_t       handle,
    globus_bool_t *                     reply);

static
void
globus_l_gram_job_manager_query_reply(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_handle_t       handle,
    int                                 status,
    int                                 query_failure_code,
    int                                 job_failure_code);

static
globus_bool_t
globus_l_gram_job_manager_query_valid(
    globus_gram_jobmanager_request_t *  request);

static
int
globus_l_gram_job_manager_query_stop_manager(
    globus_gram_jobmanager_request_t *  request);


void
globus_gram_job_manager_query_callback(
    void *                              arg,
    globus_gram_protocol_handle_t       handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 errorcode,
    char *                              uri)
{
    globus_gram_job_manager_t *         manager = arg;
    globus_gram_jobmanager_request_t *  request = NULL;
    char *                              query           = GLOBUS_NULL;
    char *                              rest;
    int                                 rc;
    int                                 status;
    int                                 job_failure_code;
    globus_bool_t                       reply           = GLOBUS_TRUE;
    globus_url_t                        parsed_uri;
    gss_ctx_id_t                        context;

    if (uri == NULL)
    {
        globus_gram_job_manager_request_log(
            request,
            "globus_gram_job_manager_query_callback missing uri\n");

        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;

        goto invalid_query;
    }

    rc = globus_gram_job_manager_add_reference(
            manager,
            uri,
            &request);

    if (rc != GLOBUS_SUCCESS)
    {
        memset(&parsed_uri, '\0', sizeof(globus_url_t));

        rc = globus_url_parse(uri, &parsed_uri);
        if(rc != GLOBUS_SUCCESS)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND;
            goto invalid_query;
        }

        rc = globus_gram_job_manager_add_reference(
                manager,
                parsed_uri.url_path,
                &request);

        globus_url_destroy(&parsed_uri);

        if (rc != GLOBUS_SUCCESS)
        {
            goto invalid_query;
        }
    }

    globus_mutex_lock(&request->mutex);
    status = request->status;
    job_failure_code = request->failure_code;

    rc = globus_gram_protocol_unpack_status_request(buf, nbytes, &query);

    if (rc != GLOBUS_SUCCESS)
    {
        goto unpack_failed;
    }

    globus_gram_job_manager_request_log(
        request,
        "JM : in globus_l_gram_job_manager_query_callback, query=%s\n",
        query);
    
    if ((rc = globus_gram_protocol_get_sec_context(
                handle,
                &context)) != GLOBUS_SUCCESS)
    {
        goto unpack_failed;
    }

    rc = globus_gram_job_manager_call_authz_callout(
            request->response_context,
            context,
            request->uniq_id,
            request->rsl,
            query);
    if (rc != GLOBUS_SUCCESS)
    {
        goto unpack_failed;
    }
    
    rest = strchr(query,' ');
    if (rest)
        *rest++ = '\0';

    if (strcmp(query,"cancel")==0)
    {
        rc = globus_l_gram_job_manager_cancel(request, handle, &reply);
    }
    else if (strcmp(query,"status")==0)
    {
        status = request->status;
    }
    else if (strcmp(query,"signal")==0)
    {
        rc = globus_l_gram_job_manager_signal(request, rest, handle, &reply);
    }
    else if (strcmp(query,"register")==0)
    {
        rc = globus_l_gram_job_manager_register(request, rest);
    }
    else if (strcmp(query,"unregister")==0)
    {
        rc = globus_l_gram_job_manager_unregister(request, rest, handle);
    }
    else if (strcmp(query,"renew")==0)
    {
        rc = globus_l_gram_job_manager_renew(request, handle, &reply);
    }
    else
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_QUERY;
    }

unpack_failed:
    if (rc != GLOBUS_SUCCESS)
    {
        status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        job_failure_code = 0;
    }

    globus_gram_job_manager_request_log( request,
                   "JM : reply: (status=%d failure code=%d (%s))\n",
                   status, rc, globus_gram_protocol_error_string(rc));


invalid_query:
    if(reply)
    {
        globus_l_gram_job_manager_query_reply(request, handle, status, rc,
                                              job_failure_code);

    }
    if (request)
    {
        globus_mutex_unlock(&request->mutex);
        rc = globus_gram_job_manager_remove_reference(
                request->manager,
                request->job_contact_path);

        if (rc != GLOBUS_SUCCESS)
        {
            globus_gram_job_manager_request_log(
                    request,
                    "JM : Unexpected failure removing reference to request\n");
        }
    }

    if(query)
    {
        free(query);
    }

    return;
}
/* globus_gram_job_manager_query_callback() */

void
globus_gram_job_manager_query_reply(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_job_manager_query_t *   query)
{
    if(query->type == GLOBUS_GRAM_JOB_MANAGER_CANCEL ||
       query->signal == GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL)
    {
        if(query->failure_code == GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED)
        {
            query->failure_code = GLOBUS_SUCCESS;
        }
    }
    globus_l_gram_job_manager_query_reply(request,
                                          query->handle,
                                          request->status,
                                          query->failure_code,
                                          query->failure_code
                                              ? 0
                                              : request->failure_code);
    if(query->signal_arg)
    {
        free(query->signal_arg);
    }
    free(query);
}
/* globus_gram_job_manager_query_reply() */

static
void
globus_l_gram_job_manager_query_reply(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_handle_t       handle,
    int                                 status,
    int                                 query_failure_code,
    int                                 job_failure_code)
{
    int                                 rc;
    int                                 i;
    int                                 code;
    globus_size_t                       replysize;
    globus_byte_t *                     reply             = GLOBUS_NULL;

    rc = query_failure_code;

    if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED)
    {
        rc = globus_gram_protocol_pack_status_reply(
            status,
            rc,
            job_failure_code,
            &reply,
            &replysize );
    }
    if (rc == GLOBUS_SUCCESS)
    {
        code = 200;
    }
    else
    {
        code = 400;

        free(reply);
        reply = GLOBUS_NULL;
        replysize = 0;
    }
    if (request)
    {
        globus_gram_job_manager_request_log(request,
                      "JM : sending reply:\n");
        for (i=0; i<replysize && reply[i] != 0; i++)
        {
            fprintf(request->manager->jobmanager_log_fp, "%c", reply[i]);
        }
        globus_gram_job_manager_request_log(request,
                              "-------------------\n");
    }

    globus_gram_protocol_reply(handle,
                               code,
                               reply,
                               replysize);

    if(reply)
    {
        free(reply);
    }
}
/* globus_l_gram_job_manager_query_reply() */

static
int
globus_l_gram_job_manager_cancel(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_handle_t       handle,
    globus_bool_t *                     reply)
{
    int                                 rc              = GLOBUS_SUCCESS;
    globus_result_t                     result;
    globus_gram_job_manager_query_t *   query;
    globus_reltime_t                    delay;
    globus_bool_t                       active;

    switch(request->jobmanager_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
          request->jobmanager_state
                  = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
          globus_gram_job_manager_request_set_status(request, GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED;

          return GLOBUS_SUCCESS;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
          request->jobmanager_state
                  = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
          globus_gram_job_manager_request_set_status(
                request,
                GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED;
          request->unsent_status_change = GLOBUS_TRUE;
          if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
          {
              result = globus_callback_unregister(
                  request->poll_timer,
                  NULL,
                  NULL,
                  &active);
              if(result == GLOBUS_SUCCESS && !active)
              {
                  GlobusTimeReltimeSet(delay, 0, 0);
                  globus_callback_register_oneshot(
                          &request->poll_timer,
                          &delay,
                          globus_gram_job_manager_state_machine_callback,
                          request);
              }
          }

          return GLOBUS_SUCCESS;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
          request->jobmanager_state
                  = GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED;
          globus_gram_job_manager_request_set_status(
                request,
                GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED;
          request->unsent_status_change = GLOBUS_TRUE;

          return GLOBUS_SUCCESS;

      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN:
          query = calloc(
                  1,
                  sizeof(globus_gram_job_manager_query_t));
  
          query->type = GLOBUS_GRAM_JOB_MANAGER_CANCEL;
          query->handle = handle;
          query->signal = 0;
          query->signal_arg = NULL;
  
          globus_fifo_enqueue(&request->pending_queries, query);
          *reply = GLOBUS_FALSE;
  
          if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
          {
              request->jobmanager_state =
                  GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;
              if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
              {
                  result = globus_callback_unregister(
                      request->poll_timer,
                      NULL,
                      NULL,
                      &active);
                  if(result == GLOBUS_SUCCESS && !active)
                  {
                      GlobusTimeReltimeSet(delay, 0, 0);
                      globus_callback_register_oneshot(
                              &request->poll_timer,
                              &delay,
                              globus_gram_job_manager_state_machine_callback,
                              request);
                  }
              }
              else
              {
                  GlobusTimeReltimeSet(delay, 0, 0);
                  globus_callback_register_oneshot(
                          &request->poll_timer,
                          &delay,
                          globus_gram_job_manager_state_machine_callback,
                          request);
              }
          }
          return GLOBUS_SUCCESS;
      default:
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
        *reply = GLOBUS_TRUE;
        return rc;
    }
}
/* globus_l_gram_job_manager_cancel() */

static
int
globus_l_gram_job_manager_register(
    globus_gram_jobmanager_request_t *  request,
    const char *                        args)
{
    int                                 rc = GLOBUS_SUCCESS;
    char *                              url = NULL;
    int                                 mask;

    url = malloc(strlen(args));

    if (globus_l_gram_job_manager_is_done(request))
    {
       rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
    }
    else if(sscanf(args, "%d %s", &mask, url) != 2)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
    }
    else
    {
        rc = globus_gram_job_manager_contact_add(request, url, mask);

    }
    free(url);

    return rc;
}
/* globus_l_gram_job_manager_register() */

static
int
globus_l_gram_job_manager_unregister(
    globus_gram_jobmanager_request_t *  request,
    const char *                        url,
    globus_gram_protocol_handle_t       handle)

{
    int rc;

    if (globus_l_gram_job_manager_is_done(request))
    {
       rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
    }
    else if (!url || strlen(url) == 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
    }
    else
    {
        rc = globus_gram_job_manager_contact_remove(request, url);

        /* Incase we unregister the last callback and we're waiting
         * for TWO_PHASE_END commit, fake the COMMIT_END signal
         */

        if (!request->client_contacts &&
             request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END)
        {
            globus_bool_t reply=GLOBUS_TRUE;
            char buf[32];

            snprintf(buf,sizeof(buf),"%d",GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END);
            globus_l_gram_job_manager_signal(request,buf,handle,&reply);
            globus_assert(reply == GLOBUS_TRUE);
        }
    }
    return rc;
}
/* globus_l_gram_job_manager_unregister() */

static
int
globus_l_gram_job_manager_renew(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_handle_t       handle,
    globus_bool_t *                     reply)
{
    globus_result_t                     result;
    globus_bool_t                       active;
    globus_gram_job_manager_query_t *   query;
    int                                 rc = 0;
    globus_reltime_t                    delay;
    globus_bool_t                       doit = GLOBUS_FALSE;

    if(!globus_l_gram_job_manager_query_valid(request))
    {
       rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
       goto error_exit;
    }

    query = calloc(1, sizeof(globus_gram_job_manager_query_t));

    if(query == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
        goto error_exit;
    }

    query->type = GLOBUS_GRAM_JOB_MANAGER_PROXY_REFRESH;
    query->handle = handle;

    globus_fifo_enqueue(&request->pending_queries, query);
    *reply = GLOBUS_FALSE;

    if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
    {
        request->jobmanager_state =
            GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;
        doit = GLOBUS_TRUE;

    } else if (request->jobmanager_state ==
            GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE)
    {
        request->jobmanager_state =
            GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1;
        doit = GLOBUS_TRUE;
    }

    if(doit && request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
    {
        result = globus_callback_unregister(
            request->poll_timer,
            NULL,
            NULL,
            &active);

        if(result == GLOBUS_SUCCESS && !active)
        {
            GlobusTimeReltimeSet(delay, 0, 0);
            globus_callback_register_oneshot(
                    &request->poll_timer,
                    &delay,
                    globus_gram_job_manager_state_machine_callback,
                    request);
        }
        /* ignore this failure... the callback will happen anyway. */
        rc = GLOBUS_SUCCESS;
    }

error_exit:
    if(rc != GLOBUS_SUCCESS)
    {
        *reply = GLOBUS_TRUE;
    }

    return rc;
}
/* globus_l_gram_job_manager_renew() */

static
int
globus_l_gram_job_manager_signal(
    globus_gram_jobmanager_request_t *  request,
    const char *                        args,
    globus_gram_protocol_handle_t       handle,
    globus_bool_t *                     reply)
{
    int                                 rc = GLOBUS_SUCCESS;
    int                                 signal;
    char *                              after_signal;
    globus_off_t                        out_size = -1;
    globus_off_t                        err_size = -1;
    globus_reltime_t                    delay;
    globus_gram_job_manager_query_t *   query;
    globus_result_t                     result;
    globus_bool_t                       active;

    *reply = GLOBUS_TRUE;
    if(args == NULL || sscanf(args, "%d", &signal) != 1)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
    }
    after_signal = strchr(args,' ');
    if (after_signal)
        *after_signal++ = '\0';

    switch(signal)
    {
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_SUSPEND:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_RESUME:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_PRIORITY:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_UPDATE:
        if(!after_signal || strlen(after_signal) == 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
            break;
        }
        query = calloc(1, sizeof(globus_gram_job_manager_query_t));

        query->type = GLOBUS_GRAM_JOB_MANAGER_SIGNAL;
        query->handle = handle;
        query->signal = signal;
        if(after_signal)
        {
            query->signal_arg = strdup(after_signal);
        }

        if(!globus_l_gram_job_manager_query_valid(request))
        {
            if(query->signal_arg)
            {
                free(query->signal_arg);
            }
            free(query);

            rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
            break;
        }

        globus_fifo_enqueue(&request->pending_queries, query);
        *reply = GLOBUS_FALSE;

        if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1;

        }
        else if (request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1;
        }
        else
        {
            break;
        }
        if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
        {
            result = globus_callback_unregister(
                request->poll_timer,
                NULL,
                NULL,
                &active);

            if(result == GLOBUS_SUCCESS && !active)
            {
                GlobusTimeReltimeSet(delay, 0, 0);
                globus_callback_register_oneshot(
                        &request->poll_timer,
                        &delay,
                        globus_gram_job_manager_state_machine_callback,
                        request);
            }
        }
        break;

    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_REQUEST:
    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END:
        if(request->two_phase_commit == 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COMMIT;

            break;
        }
        else if(request->jobmanager_state ==
                    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED;
        }
        else if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED;
        }
        else if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE)
        {
            request->jobmanager_state =
            GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED;
        }
        else if(request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1 ||
                request->jobmanager_state ==
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2)
        {
            request->jobmanager_state =
                GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED;
        }
        else
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;

            break;
        }
        if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
        {
            result = globus_callback_unregister(
                    request->poll_timer,
                    NULL,
                    NULL,
                    &active);
            if(result == GLOBUS_SUCCESS && !active)
            {
                /* 
                 * Cancelled callback before it ran--schedule the
                 * state machine to run after the query handler exits.
                 */
                request->poll_timer = GLOBUS_HANDLE_TABLE_NO_HANDLE;
                GlobusTimeReltimeSet(delay, 0, 0);
                globus_callback_register_oneshot(
                        &request->poll_timer,
                        &delay,
                        globus_gram_job_manager_state_machine_callback,
                        request);
            }
        }
        break;

    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_EXTEND:
        if ((!after_signal) || (strlen(after_signal) == 0))
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
        }
        else if(request->two_phase_commit == 0)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COMMIT;
        }
        else if((request->jobmanager_state ==
                 GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE) ||
                (request->jobmanager_state ==
                 GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END) ||
                (request->jobmanager_state ==
                 GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE) ||
                (request->jobmanager_state ==
                 GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1) ||
                (request->jobmanager_state ==
                 GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2))
        {
            request->commit_extend += atoi(after_signal);
        }
        break;

    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STDIO_SIZE:
        if (after_signal &&
                sscanf(after_signal,
                       "%"GLOBUS_OFF_T_FORMAT" %"GLOBUS_OFF_T_FORMAT,
                       &out_size, &err_size) > 0)
        {
            struct stat st;
            globus_off_t local_size_stdout = 0;
            globus_off_t local_size_stderr = 0;
            const char * local_stdout;
            const char * local_stderr;

            rc = globus_gram_job_manager_rsl_attribute_get_string_value(
                request->rsl,
                GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM,
                &local_stdout);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_QUERY;
                break;
            }
            rc = globus_gram_job_manager_rsl_attribute_get_string_value(
                request->rsl,
                GLOBUS_GRAM_PROTOCOL_STDERR_PARAM,
                &local_stderr);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_QUERY;
                break;
            }
            if (!globus_list_empty(request->stage_out_todo))
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_STILL_STREAMING;
                break;
            }
            if (strcmp(local_stdout, request->cached_stdout) == 0)
            {
                /* fakestreaming is likely to happen */
                rc = stat(local_stdout, &st);
                if (rc < 0)
                {
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_QUERY;
                    break;
                }
                local_size_stdout = st.st_size;
            }

            if (strcmp(local_stderr, request->cached_stderr) == 0)
            {
                /* fakestreaming is likely to happen */
                rc = stat(local_stderr, &st);
                if (rc < 0)
                {
                    rc = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_QUERY;
                    break;
                }
                local_size_stderr = st.st_size;
            }
            else if (out_size >= 0 && out_size != local_size_stdout)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_STDIO_SIZE;
            }
            else if (err_size >= 0 && err_size != local_size_stderr)
            {
                rc = GLOBUS_GRAM_PROTOCOL_ERROR_STDIO_SIZE;
            }
            else
            {
                rc = GLOBUS_SUCCESS;
            }
        }
        else
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
        }
        break;

    case GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STOP_MANAGER:
        rc = globus_l_gram_job_manager_query_stop_manager(request);

        break;
    default:
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_UNKNOWN_SIGNAL_TYPE;
    }
    return rc;
}
/* globus_l_gram_job_manager_signal() */

/**
 * Handle a STOP_MANAGER signal.
 *
 * This signal causes the job manager to stop monitoring the job and exit,
 * without killing the job. We want this stop to happen pretty quickly, so
 * we'll unregister any poll_timer events (either the intra-poll delay or
 * the two_phase_commit delay) and reregister as a oneshot.
 */
static
int
globus_l_gram_job_manager_query_stop_manager(
    globus_gram_jobmanager_request_t *  request)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_result_t                     result;
    globus_bool_t                       active;
    globus_gram_jobmanager_state_t      state;
    globus_reltime_t                    delay;

    state = request->jobmanager_state;

    if(state == GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2)
    {
        if(request->poll_timer != GLOBUS_HANDLE_TABLE_NO_HANDLE)
        {
            result = globus_callback_unregister(
                request->poll_timer,
                NULL,
                NULL,
                &active);

            if(result == GLOBUS_SUCCESS && !active)
            {
                GlobusTimeReltimeSet(delay, 0, 0);
                globus_callback_register_oneshot(
                        &request->poll_timer,
                        &delay,
                        globus_gram_job_manager_state_machine_callback,
                        request);
            }
        }
        else
        {
            GlobusTimeReltimeSet(delay, 0, 0);
            globus_callback_register_oneshot(
                    &request->poll_timer,
                    &delay,
                    globus_gram_job_manager_state_machine_callback,
                    request);
        }
    }

    switch(state)
    {
        case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP:
          globus_gram_job_manager_request_set_status(
                request,
                GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
          request->unsent_status_change = GLOBUS_TRUE;
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;
          request->jobmanager_state = GLOBUS_GRAM_JOB_MANAGER_STATE_STOP;
          break;
        case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT:
          globus_gram_job_manager_request_set_status(
                request,
                GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
          request->unsent_status_change = GLOBUS_TRUE;
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;
          request->jobmanager_state =
              GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
          break;
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
          globus_gram_job_manager_request_set_status(
                request,
                GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
          request->unsent_status_change = GLOBUS_TRUE;
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;
          request->jobmanager_state =
              GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT;
          break;
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED:
          globus_gram_job_manager_request_set_status(
                request,
                GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED);
          request->unsent_status_change = GLOBUS_TRUE;
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED;
          request->jobmanager_state =
              GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE;
          break;
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_DONE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP:
        case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
          rc = GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL;
          break;
    }
    return rc;
}
/* globus_l_gram_job_manager_query_stop_manager() */

static
globus_bool_t
globus_l_gram_job_manager_is_done(
    globus_gram_jobmanager_request_t *  request)
{
    if(request->jobmanager_state == GLOBUS_GRAM_JOB_MANAGER_STATE_DONE ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE ||
       request->jobmanager_state
           == GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE)
    {
        globus_gram_job_manager_request_log(
                request,
                "JM: job manager request handling is done, "
                "request will be denied\n");

        return GLOBUS_TRUE;
    }
    globus_gram_job_manager_request_log(
            request,
            "JM: job manager request handling is not done yet, "
                "request will be processed\n");
    return GLOBUS_FALSE;
}
/* globus_l_gram_job_manager_is_done() */

static
globus_bool_t
globus_l_gram_job_manager_query_valid(
    globus_gram_jobmanager_request_t *  request)
{
    switch(request->jobmanager_state)
    {
      case GLOBUS_GRAM_JOB_MANAGER_STATE_START:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN:
          return GLOBUS_TRUE;
      case GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT:
      case GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE:
          return GLOBUS_FALSE;
    }
    return GLOBUS_FALSE;
}
/* globus_l_gram_job_manager_query_valid() */


void
globus_gram_job_manager_query_delegation_callback(
    void *                              arg,
    globus_gram_protocol_handle_t       handle,
    gss_cred_id_t                       credential,
    int                                 error_code)
{
    globus_gram_job_manager_query_t *   query;
    globus_gram_jobmanager_request_t *  request;
    request = arg;

    globus_mutex_lock(&request->mutex);

    query = globus_fifo_peek(&request->pending_queries);

    query->delegated_credential = credential;

    while(!globus_gram_job_manager_state_machine(request));
    globus_mutex_unlock(&request->mutex);
}
/* globus_l_gram_job_manager_delegation_callback() */
