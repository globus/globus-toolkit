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



#include "globus_gram_job_manager.h"
#include "globus_usage.h"
#include "version.h"

globus_list_t *                         globus_l_gram_usage_handle_list = NULL;


#define GLOBUS_L_GRAM_JM_USAGE_ID          20
#define GLOBUS_L_GRAM_JM_USAGE_VER         0

#define GLOBUS_L_GRAM_JOB_USAGE_ID          20
#define GLOBUS_L_GRAM_JOB_USAGE_VER         1

#define GLOBUS_L_GRAM_DEFAULT_SESSION_TAGLIST "ABCDEFGIKLMNOPQRSTUVWX"
#define GLOBUS_L_GRAM_DEFAULT_JOB_TAGLIST "Babcdefghijklmnopqrstuvwxyz01234YZH"
#define GLOBUS_L_GRAM_PRIVATE_SESSION_TAGLIST ""
#define GLOBUS_L_GRAM_PRIVATE_JOB_TAGLIST "6789"
#define GLOBUS_L_GRAM_MAX_TAGCOUNT 40

typedef enum globus_l_gram_usage_tag_e
{
    /* per session tags */
    GLOBUS_L_GRAM_USAGE_JM_STARTTIME                        = 'A',
    GLOBUS_L_GRAM_USAGE_SESSION_ID                          = 'B',
    GLOBUS_L_GRAM_USAGE_STATUS__TIME                        = 'C',
    GLOBUS_L_GRAM_USAGE_VERSION                             = 'D',
    GLOBUS_L_GRAM_USAGE_LRM                                 = 'E',
    GLOBUS_L_GRAM_USAGE_POLL_USED                           = 'F',
    GLOBUS_L_GRAM_USAGE_AUDIT_USED                          = 'G',
    GLOBUS_L_GRAM_USAGE_RESTARTED_JOB_COUNT                 = 'I',
    GLOBUS_L_GRAM_USAGE_TOTAL_JOB_COUNT                     = 'K',
    GLOBUS_L_GRAM_USAGE_TOTAL_FAILED_COUNT                  = 'L',
    GLOBUS_L_GRAM_USAGE_TOTAL_CANCELED_COUNT                = 'M',
    GLOBUS_L_GRAM_USAGE_TOTAL_DONE_COUNT                    = 'N',
    GLOBUS_L_GRAM_USAGE_TOTAL_DRYRUN_COUNT                  = 'O',
    GLOBUS_L_GRAM_USAGE_PEAK_JOB_COUNT                      = 'P',
    GLOBUS_L_GRAM_USAGE_CURRENT_JOB_COUNT                   = 'Q',
    GLOBUS_L_GRAM_USAGE_UNSUBMITTED_JOB_COUNT               = 'R',
    GLOBUS_L_GRAM_USAGE_STAGE_IN_JOB_COUNT                  = 'S',
    GLOBUS_L_GRAM_USAGE_PENDING_JOB_COUNT                   = 'T',
    GLOBUS_L_GRAM_USAGE_ACTIVE_JOB_COUNT                    = 'U',
    GLOBUS_L_GRAM_USAGE_STAGE_OUT_JOB_COUNT                 = 'V',
    GLOBUS_L_GRAM_USAGE_FAILED_JOB_COUNT                    = 'W',
    GLOBUS_L_GRAM_USAGE_DONE_JOB_COUNT                      = 'X',

    /* per job tags */

    /* GLOBUS_L_GRAM_USAGE_SESSION_ID */                     
    GLOBUS_L_GRAM_USAGE_DRYRUN                              = 'a',
    GLOBUS_L_GRAM_USAGE_HOST_COUNT                          = 'b',
    GLOBUS_L_GRAM_USAGE_UNSUBMITTED_TS                      = 'c',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_TS                    = 'd',
    GLOBUS_L_GRAM_USAGE_PENDING_TS                          = 'e',
    GLOBUS_L_GRAM_USAGE_ACTIVE_TS                           = 'f',
    GLOBUS_L_GRAM_USAGE_FAILED_TS                           = 'g',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_TS                   = 'h',
    GLOBUS_L_GRAM_USAGE_DONE_TS                             = 'i',
    GLOBUS_L_GRAM_USAGE_FAILURE_CODE                        = 'j',
    GLOBUS_L_GRAM_USAGE_STATUS_COUNT                        = 'k',
    GLOBUS_L_GRAM_USAGE_REGISTER_COUNT                      = 'l',
    GLOBUS_L_GRAM_USAGE_SIGNAL_COUNT                        = 'm',
    GLOBUS_L_GRAM_USAGE_REFRESH_COUNT                       = 'n',
    GLOBUS_L_GRAM_USAGE_FILE_CLEAN_UP_COUNT                 = 'o',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_HTTP_COUNT            = 'p',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_HTTPS_COUNT           = 'q',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_FTP_COUNT             = 'r',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_GSIFTP_COUNT          = 's',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_SHARED_HTTP_COUNT     = 't',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_SHARED_HTTPS_COUNT    = 'u',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_SHARED_FTP_COUNT      = 'v',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_SHARED_GSIFTP_COUNT   = 'w',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_HTTP_COUNT           = 'x',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_HTTPS_COUNT          = 'y',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_FTP_COUNT            = 'z',
    GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_GSIFTP_COUNT         = '0',
    GLOBUS_L_GRAM_USAGE_RSL_BITMASK                         = '1',
    GLOBUS_L_GRAM_USAGE_UNREGISTER_COUNT                    = '2',
    GLOBUS_L_GRAM_USAGE_COUNT                               = '3',
    GLOBUS_L_GRAM_USAGE_RSL_ATTRIBUTES                      = '4',
    GLOBUS_L_GRAM_USAGE_RESTART_COUNT                       = 'Y',
    GLOBUS_L_GRAM_USAGE_CALLBACK_COUNT                      = 'Z',
    GLOBUS_L_GRAM_USAGE_JOBTYPE                             = 'H',

    GLOBUS_L_GRAM_USAGE_EXEC_NAME       /* */               = '6',
    GLOBUS_L_GRAM_USAGE_EXEC_ARGS       /* */               = '7',
    GLOBUS_L_GRAM_USAGE_CLIENT_IP       /* */               = '8',
    GLOBUS_L_GRAM_USAGE_USER_DN         /* */               = '9',

    /* !! ADD to ALL_TAGLIST above when adding here */
} globus_l_gram_usage_tag_t;

const char *                            globus_l_gram_rsl_attribute_ids[] =
{
    /* Order must match the SQL definition (begins at 1) */
    NULL,
    GLOBUS_GRAM_PROTOCOL_DIR_PARAM,
    GLOBUS_GRAM_PROTOCOL_EXECUTABLE_PARAM,
    GLOBUS_GRAM_PROTOCOL_ARGUMENTS_PARAM,
    GLOBUS_GRAM_PROTOCOL_STDIN_PARAM,
    GLOBUS_GRAM_PROTOCOL_STDOUT_PARAM,
    GLOBUS_GRAM_PROTOCOL_STDERR_PARAM,
    GLOBUS_GRAM_PROTOCOL_COUNT_PARAM,
    GLOBUS_GRAM_PROTOCOL_ENVIRONMENT_PARAM,
    GLOBUS_GRAM_PROTOCOL_MAX_TIME_PARAM,
    GLOBUS_GRAM_PROTOCOL_MAX_WALL_TIME_PARAM,
    GLOBUS_GRAM_PROTOCOL_MAX_CPU_TIME_PARAM,
    GLOBUS_GRAM_PROTOCOL_JOB_TYPE_PARAM,
    GLOBUS_GRAM_PROTOCOL_MYJOB_PARAM,
    GLOBUS_GRAM_PROTOCOL_QUEUE_PARAM,
    GLOBUS_GRAM_PROTOCOL_PROJECT_PARAM,
    GLOBUS_GRAM_PROTOCOL_HOST_COUNT_PARAM,
    GLOBUS_GRAM_PROTOCOL_DRY_RUN_PARAM,
    GLOBUS_GRAM_PROTOCOL_MIN_MEMORY_PARAM,
    GLOBUS_GRAM_PROTOCOL_MAX_MEMORY_PARAM,
    GLOBUS_GRAM_PROTOCOL_SAVE_STATE_PARAM,
    GLOBUS_GRAM_PROTOCOL_TWO_PHASE_COMMIT_PARAM,
    GLOBUS_GRAM_PROTOCOL_REMOTE_IO_URL_PARAM,
    GLOBUS_GRAM_PROTOCOL_SCRATCHDIR_PARAM,
    "rslsubstitution",
    GLOBUS_GRAM_PROTOCOL_RESTART_PARAM,
    GLOBUS_GRAM_PROTOCOL_STDOUT_POSITION_PARAM,
    GLOBUS_GRAM_PROTOCOL_STDERR_POSITION_PARAM,
    GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_PARAM,
    GLOBUS_GRAM_PROTOCOL_FILE_STAGE_IN_SHARED_PARAM,
    GLOBUS_GRAM_PROTOCOL_FILE_STAGE_OUT_PARAM,
    GLOBUS_GRAM_PROTOCOL_FILE_CLEANUP_PARAM,
    GLOBUS_GRAM_PROTOCOL_GASS_CACHE_PARAM,
    GLOBUS_GRAM_PROTOCOL_PROXY_TIMEOUT_PARAM,
    "librarypath",
    GLOBUS_GRAM_PROTOCOL_USER_NAME
};

#define GLOBUS_L_GRAM_TOTAL_ATTRS \
    (sizeof(globus_l_gram_rsl_attribute_ids) / \
    sizeof(globus_l_gram_rsl_attribute_ids[0]))

typedef struct globus_l_gram_usage_ent_s
{
    globus_usage_stats_handle_t         jm_handle;
    globus_usage_stats_handle_t         job_handle;
    char *                              target;
    char *                              job_taglist;
    char *                              session_taglist;
} globus_l_gram_usage_ent_t;

void
globus_i_gram_send_job_failure_stats(
    globus_gram_job_manager_t *         manager,
    int                                 rc)
{
    globus_gram_jobmanager_request_t    request;
    /* Make something that looks kinda like a request */
    memset(&request, 0, sizeof(globus_gram_jobmanager_request_t));
    request.status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    request.config = manager->config;
    request.manager = manager;
    request.failure_code = rc;
    GlobusTimeAbstimeGetCurrent(request.job_stats.failed_timestamp);

    globus_i_gram_send_job_stats(&request);
}

void
globus_i_gram_send_job_stats(
    globus_gram_jobmanager_request_t *  request)
{
    globus_result_t                     result;
    globus_list_t *                     list;
    globus_l_gram_usage_ent_t *         usage_ent;
    char *                              keys[GLOBUS_L_GRAM_MAX_TAGCOUNT];
    char *                              values[GLOBUS_L_GRAM_MAX_TAGCOUNT];
    char *                              ptr;
    char *                              key;
    char                                keystr[2];
    char                                valstr[2048];
    char *                              value;
    int                                 i = 0;
    char *                              save_taglist = NULL;
    const char *                        rsl_str;
    char *                              p;
    globus_list_t *                     attributes;
    int                                 rc;
    uint64_t                            rsl_attributes_bitfield;
    int                                 attrindex;
    
    if(globus_l_gram_usage_handle_list == NULL)
    {
        return;
    }

    for(list = globus_l_gram_usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (globus_l_gram_usage_ent_t *) globus_list_first(list);

        if(!usage_ent || usage_ent->job_handle == NULL)
        {
            continue;
        }
        
        if(save_taglist == NULL || 
            strcmp(save_taglist, usage_ent->job_taglist) != 0)
        {
            save_taglist = usage_ent->job_taglist;
            
            keystr[1] = 0;
            ptr = usage_ent->job_taglist;
            if (i > 0)
            {
                for (--i; i >= 0; i--)
                {
                    if (keys[i] != NULL)
                    {
                        free(keys[i]);
                        keys[i] = NULL;
                    }
                    if (values[i] != NULL)
                    {
                        free(values[i]);
                        values[i] = NULL;
                    }
                }
            }
            i = 0;
            while(ptr && *ptr)
            {
                value = NULL;
                switch(*ptr)
                {
                  case GLOBUS_L_GRAM_USAGE_SESSION_ID:
                    keystr[0] = *ptr;
                    key = keystr;
                    value = request->manager->usagetracker->jm_id;
                    break;
                  case GLOBUS_L_GRAM_USAGE_EXEC_NAME:
                    rc = globus_gram_job_manager_rsl_attribute_get_string_value(
                        request->rsl, "executable", &rsl_str);
                    if(rc == 0)
                    {
                        value = (char *) rsl_str;
                    }
                    keystr[0] = *ptr;
                    key = keystr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_RSL_BITMASK:
                    keystr[0] = *ptr;
                    key = keystr;
                    rsl_attributes_bitfield = 0;
                    for (attrindex = 1;
                         attrindex < GLOBUS_L_GRAM_TOTAL_ATTRS;
                         attrindex++)
                    {
                        if (globus_gram_job_manager_rsl_attribute_exists(
                                    request->rsl,
                                    globus_l_gram_rsl_attribute_ids[attrindex]))
                        {
                            rsl_attributes_bitfield |= (1 << attrindex);
                        }
                    }
                    snprintf(valstr,
                            sizeof(valstr), "%"PRIu64, rsl_attributes_bitfield);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_RSL_ATTRIBUTES:
                    keystr[0] = *ptr;
                    key = keystr;
                    attributes = globus_rsl_boolean_get_operand_list(
                            request->rsl);
                    p = valstr;
                    p[0] = 0;
                    while (!globus_list_empty(attributes))
                    {
                        globus_rsl_t *  attr;
                        char *          attr_name;

                        attr = globus_list_first(attributes);
                        attributes = globus_list_rest(attributes);

                        if (!globus_rsl_is_relation(attr))
                        {
                            continue;
                        }
                        attr_name = globus_rsl_relation_get_attribute(attr);
                        for (attrindex = 1; 
                             attrindex < GLOBUS_L_GRAM_TOTAL_ATTRS;
                             attrindex++)
                        {
                            if (strcmp(attr_name,
                                    globus_l_gram_rsl_attribute_ids[attrindex])
                                == 0)
                            {
                                break;
                            }
                        }
                        if (attrindex == GLOBUS_L_GRAM_TOTAL_ATTRS)
                        {
                            /* Skip internal RSL hooks */
                            if (strcmp(attr_name, "filestreamout") == 0 ||
                                strcmp(attr_name, "restartcontacts") == 0)
                            {
                                continue;
                            }
                            p += snprintf(p, sizeof(valstr) - (p - valstr),
                                    "%s,", attr_name);
                        }
                    }
                    if (p > valstr)
                    {
                        *(--p) = 0;
                    }
                    value = valstr;
                    if (*value == 0)
                    {
                        value = 0;
                    }
                    break;
                  case GLOBUS_L_GRAM_USAGE_EXEC_ARGS:
                    attributes = globus_rsl_boolean_get_operand_list(
                            request->rsl);
                    while (!globus_list_empty(attributes))
                    {
                        globus_rsl_t *  attr;
                        char *          attr_name;

                        attr = globus_list_first(attributes);
                        attributes = globus_list_rest(attributes);

                        if (!globus_rsl_is_relation(attr))
                        {
                            continue;
                        }
                        attr_name = globus_rsl_relation_get_attribute(attr);
                        if (strcmp(
                                attr_name,
                                GLOBUS_GRAM_PROTOCOL_ARGUMENTS_PARAM) == 0)
                        {
                            value = globus_rsl_value_unparse(
                                globus_rsl_relation_get_value_sequence(attr));
                            strncpy(valstr, value, sizeof(valstr));
                            free(value);
                            value = valstr;
                            break;
                        }
                    }
                    keystr[0] = *ptr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_CLIENT_IP:
                    keystr[0] = *ptr;
                    key = keystr;
                    value = request->job_stats.client_address;
                    break;
                  case GLOBUS_L_GRAM_USAGE_USER_DN:
                    keystr[0] = *ptr;
                    key = keystr;
                    value = request->job_stats.user_dn;
                    break;
                  case GLOBUS_L_GRAM_USAGE_DRYRUN:
                    keystr[0] = *ptr;
                    key = keystr;
                    value = request->dry_run ? "1" : "0";
                    break;
                  case GLOBUS_L_GRAM_USAGE_COUNT:
                    globus_gram_job_manager_rsl_attribute_get_string_value(
                        request->rsl, "count", &rsl_str);
                    if(rc == 0)
                    {
                        value = (char *) rsl_str;
                    }
                    keystr[0] = *ptr;
                    key = keystr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_HOST_COUNT:
                    rc = globus_gram_job_manager_rsl_attribute_get_string_value(
                        request->rsl, "hostcount", &rsl_str);
                    if(rc == 0)
                    {
                        value = (char *) rsl_str;
                    }
                    keystr[0] = *ptr;
                    key = keystr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_UNSUBMITTED_TS:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%ld.%09ld",
                            request->job_stats.unsubmitted_timestamp.tv_sec,
                            request->job_stats.unsubmitted_timestamp.tv_nsec);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_TS:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%ld.%09ld",
                            request->job_stats.file_stage_in_timestamp.tv_sec,
                            request->job_stats.file_stage_in_timestamp.tv_nsec);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_PENDING_TS:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%ld.%09ld",
                            request->job_stats.pending_timestamp.tv_sec,
                            request->job_stats.pending_timestamp.tv_nsec);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_ACTIVE_TS:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%ld.%09ld",
                            request->job_stats.active_timestamp.tv_sec,
                            request->job_stats.active_timestamp.tv_nsec);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FAILED_TS:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%ld.%09ld",
                            request->job_stats.failed_timestamp.tv_sec,
                            request->job_stats.failed_timestamp.tv_nsec);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_TS:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%ld.%09ld",
                            request->job_stats.file_stage_out_timestamp.tv_sec,
                            request->
                                job_stats.file_stage_out_timestamp.tv_nsec);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_DONE_TS:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%ld.%09ld",
                            request->job_stats.done_timestamp.tv_sec,
                            request->
                                job_stats.done_timestamp.tv_nsec);
                    value = valstr;

                    break;
                  case GLOBUS_L_GRAM_USAGE_FAILURE_CODE:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        request->failure_code);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;

                  case GLOBUS_L_GRAM_USAGE_STATUS_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.status_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_REGISTER_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.register_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_UNREGISTER_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.unregister_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_SIGNAL_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.signal_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_REFRESH_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.refresh_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_CLEAN_UP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.file_clean_up_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_HTTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.file_stage_in_http_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_HTTPS_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.file_stage_in_https_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_FTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.file_stage_in_ftp_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_GSIFTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.file_stage_in_gsiftp_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_SHARED_HTTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->job_stats.file_stage_in_shared_http_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_SHARED_HTTPS_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.file_stage_in_shared_https_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_SHARED_FTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.file_stage_in_shared_ftp_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_IN_SHARED_GSIFTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.file_stage_in_shared_gsiftp_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_HTTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.file_stage_out_http_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_HTTPS_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.file_stage_out_https_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_FTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.file_stage_out_ftp_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FILE_STAGE_OUT_GSIFTP_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.file_stage_out_gsiftp_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_RESTART_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.restart_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_CALLBACK_COUNT:
                    keystr[0] = *ptr;
                    key = keystr;
                    snprintf(valstr,
                            sizeof(valstr), "%d",
                            request->
                                job_stats.callback_count);
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_JOBTYPE:
                    rc = globus_gram_job_manager_rsl_attribute_get_string_value(
                        request->rsl, "jobtype", &rsl_str);
                    if(rc == 0)
                    {
                        value = (char *) rsl_str;
                    }
                    keystr[0] = *ptr;
                    key = keystr;
                    break;
                  default:
                    key = NULL;
                    value = NULL;
                    break;
                }
                
                if(key != NULL && value != NULL)
                {
                    keys[i] = strdup(key);
                    values[i] = strdup(value);
                    i++;
                }

                ptr++;
            }
        }
        
        result = globus_usage_stats_send_array(
            usage_ent->job_handle, i, keys, values);
    }
    if (i > 0)
    {
        for (--i; i >= 0; i--)
        {
            if (keys[i] != NULL)
            {
                free(keys[i]);
                keys[i] = NULL;
            }
            if (values[i] != NULL)
            {
                free(values[i]);
                values[i] = NULL;
            }
        }
    }
    
    return;
}


void
globus_i_gram_send_session_stats(
    globus_gram_job_manager_t *      manager)
{
    globus_result_t                     result;
    globus_list_t *                     list;
    globus_l_gram_usage_ent_t *         usage_ent;
    char *                              keys[GLOBUS_L_GRAM_MAX_TAGCOUNT];
    char *                              values[GLOBUS_L_GRAM_MAX_TAGCOUNT];
    char *                              ptr;
    char *                              key;
    char                                keystr[2];
    char                                valstr[2048];
    char *                              value;
    int                                 i = 0;
    char *                              save_taglist = NULL;
    int                                 rc;
    globus_abstime_t                    now;
    static globus_abstime_t             last_report = {0, 0};
    globus_i_gram_usage_tracker_t *     tracker;
    int                                 count_pending = 0;
    int                                 count_active = 0;
    int                                 count_failed = 0;
    int                                 count_done = 0;
    int                                 count_unsubmitted = 0;
    int                                 count_stage_in = 0;
    int                                 count_stage_out = 0;
    globus_gram_job_manager_ref_t *     ref;
    
    GlobusTimeAbstimeGetCurrent(now);
    tracker = manager->usagetracker;
    
    if(globus_l_gram_usage_handle_list == NULL)
    {
        return;
    }
    
    if(tracker->jm_id == NULL)
    {
        globus_uuid_t                   uuid;

        rc = globus_uuid_create(&uuid);
        if(rc == GLOBUS_SUCCESS)
        {
            tracker->jm_id = strdup(uuid.text);
        }
    }

    if (last_report.tv_sec >= now.tv_sec)
    {
        /* Too soon! */
        return;
    }
    last_report.tv_sec = now.tv_sec;
    last_report.tv_nsec = now.tv_nsec;

    for (ref = globus_hashtable_first(&manager->request_hash);
         ref != NULL;
         ref = globus_hashtable_next(&manager->request_hash))
    {
        switch(ref->job_state)
        {
          case GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING:
            count_pending++;
            break;
          case GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE:
            count_active++;
            break;
          case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
            count_failed++;
            break;
          case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
            count_done++;
            break;
          case GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED:
            count_unsubmitted++;
            break;
          case GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN:
            count_stage_in++;
            break;
          case GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT:
            count_stage_out++;
            break;
          default:
            break;
        }
    }

    for(list = globus_l_gram_usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (globus_l_gram_usage_ent_t *) globus_list_first(list);

        if(!usage_ent || usage_ent->jm_handle == NULL)
        {
            continue;
        }
        
        if(save_taglist == NULL || 
            strcmp(save_taglist, usage_ent->session_taglist) != 0)
        {
            save_taglist = usage_ent->session_taglist;
            
            keystr[1] = 0;
            ptr = usage_ent->session_taglist;

            if (i > 0)
            {
                for (--i; i >= 0; i--)
                {
                    if (keys[i])
                    {
                        free(keys[i]);
                        keys[i] = NULL;
                    }
                    if (values[i])
                    {
                        free(values[i]);
                        values[i] = NULL;
                    }
                }
            }
            i = 0;
            while(ptr && *ptr)
            {
                switch(*ptr)
                {
                  case GLOBUS_L_GRAM_USAGE_SESSION_ID:
                    keystr[0] = *ptr;
                    key = keystr;
                    value = tracker->jm_id;
                    break;
                  case GLOBUS_L_GRAM_USAGE_JM_STARTTIME:
                    snprintf(valstr, sizeof(valstr), "%ld.%06ld", 
                        tracker->jm_start_time.tv_sec, 
                        tracker->jm_start_time.tv_nsec/1000);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_STATUS__TIME:
                    snprintf(valstr, sizeof(valstr), "%ld.%06ld",
                            now.tv_sec,
                            now.tv_nsec/1000);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_VERSION:
                    keystr[0] = *ptr;
                    key = keystr;
#ifndef GLOBUS_FLAVOR_NAME
#define GLOBUS_FLAVOR_NAME "unknown"
#endif
                    snprintf(valstr, sizeof(valstr), "%d.%d (%s, %lu-%d) [%s]",
                            local_version.major,
                            local_version.minor,
                            GLOBUS_FLAVOR_NAME,
                            local_version.timestamp,
                            local_version.branch_id,
                            manager->config->globus_version
                                ? manager->config->globus_version
                                : "unknown");
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_LRM:
                    keystr[0] = *ptr;
                    key = keystr;
                    value = manager->config->jobmanager_type;
                    break;
                  case GLOBUS_L_GRAM_USAGE_POLL_USED:
                    keystr[0] = *ptr;
                    key = keystr;
                    value = manager->config->seg_module ? "0" : "1" ;
                    break;
                  case GLOBUS_L_GRAM_USAGE_AUDIT_USED:
                    keystr[0] = *ptr;
                    key = keystr;
                    value = manager->config->auditing_dir ? "1" : "0";
                    break;
                  case GLOBUS_L_GRAM_USAGE_RESTARTED_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        tracker->count_restarted);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_TOTAL_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        tracker->count_total_failed + tracker->count_total_done);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_TOTAL_FAILED_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        tracker->count_total_failed);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_TOTAL_CANCELED_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        tracker->count_total_canceled);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_TOTAL_DONE_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        tracker->count_total_done);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_TOTAL_DRYRUN_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        tracker->count_dryrun);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                 case GLOBUS_L_GRAM_USAGE_PEAK_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        tracker->count_peak_jobs);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_CURRENT_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", 
                        tracker->count_current_jobs);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_UNSUBMITTED_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", count_unsubmitted);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_STAGE_IN_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", count_stage_in);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_PENDING_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", count_pending);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_ACTIVE_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", count_active);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_STAGE_OUT_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", count_stage_out);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_FAILED_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", count_failed);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;
                  case GLOBUS_L_GRAM_USAGE_DONE_JOB_COUNT:
                    snprintf(valstr, sizeof(valstr), "%d", count_done);
                    keystr[0] = *ptr;
                    key = keystr;
                    value = valstr;
                    break;

                  default:
                    key = NULL;
                    value = NULL;
                    break;
                }
                
                if(key != NULL && value != NULL)
                {
                    keys[i] = strdup(key);
                    values[i] = strdup(value);
                    i++;
                }
                
                ptr++;
            }
        }
        
        result = globus_usage_stats_send_array(
            usage_ent->jm_handle, i, keys, values);
    }
    if (i > 0)
    {
        for (--i; i >= 0; i--)
        {
            if (keys[i])
            {
                free(keys[i]);
                keys[i] = NULL;
            }
            if (values[i])
            {
                free(values[i]);
                values[i] = NULL;
            }
        }
    }
    return;
}
/* globus_i_gram_send_session_stats() */

static
void
globus_l_gram_usage_parse_target(
    char *                              target)
{
    char *                              ptr;
    globus_l_gram_usage_ent_t *         usage_ent;
    char *                              entry = NULL;
    char *                              conf_taglist = NULL;
       
    usage_ent = (globus_l_gram_usage_ent_t *)
        globus_malloc(sizeof(globus_l_gram_usage_ent_t));

    if(target && *target)
    {
        entry = globus_libc_strdup(target);
    }

    if(entry && (ptr = strchr(entry, '!')) != NULL)
    {
        *ptr = '\0';
        conf_taglist = ptr + 1;
    }

    if(conf_taglist == NULL || 
        strcasecmp(conf_taglist, "default") == 0)
    {
        usage_ent->job_taglist =
            globus_libc_strdup(GLOBUS_L_GRAM_DEFAULT_JOB_TAGLIST);
        usage_ent->session_taglist =
            globus_libc_strdup(GLOBUS_L_GRAM_DEFAULT_SESSION_TAGLIST);
    }
    else if(strcasecmp(conf_taglist, "all") == 0)
    {
        usage_ent->job_taglist = globus_libc_strdup(
            GLOBUS_L_GRAM_DEFAULT_JOB_TAGLIST
            GLOBUS_L_GRAM_PRIVATE_JOB_TAGLIST);
        usage_ent->session_taglist = globus_libc_strdup(
            GLOBUS_L_GRAM_DEFAULT_SESSION_TAGLIST
            GLOBUS_L_GRAM_PRIVATE_SESSION_TAGLIST);
    }
    else
    {
        usage_ent->job_taglist = globus_libc_strdup(conf_taglist);
        usage_ent->session_taglist = globus_libc_strdup(conf_taglist);
    }
        
    usage_ent->target = entry;

    globus_list_insert(&globus_l_gram_usage_handle_list, usage_ent);
        
    return;
}
   

globus_result_t
globus_i_gram_usage_stats_destroy(
    globus_gram_job_manager_t *         manager)
{
    return GLOBUS_SUCCESS;
}


globus_result_t
globus_i_gram_usage_stats_init(
    globus_gram_job_manager_t *         manager)
{
    globus_result_t                     result;
    char *                              target_str;
    char *                              ptr;
    char *                              target;
    globus_list_t *                     list;
    globus_l_gram_usage_ent_t *         usage_ent;

    if(manager->config->usage_disabled)
    {
        return GLOBUS_SUCCESS;
    }

    globus_module_activate(GLOBUS_USAGE_MODULE);
    
    target_str = globus_libc_strdup(manager->config->usage_targets);

    target = target_str;
    ptr = NULL;
    while(target != NULL && (ptr = strchr(target, ',')) != NULL)
    {
        *ptr = '\0';
        globus_l_gram_usage_parse_target(target);
        target = ptr + 1;
    }
    
    if(ptr == NULL)
    {
        globus_l_gram_usage_parse_target(target);
    }


    for(list = globus_l_gram_usage_handle_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        usage_ent = (globus_l_gram_usage_ent_t *) globus_list_first(list);

        usage_ent->jm_handle = NULL;
        usage_ent->job_handle = NULL;
        result = globus_usage_stats_handle_init(
            &usage_ent->jm_handle,
            GLOBUS_L_GRAM_JM_USAGE_ID,
            GLOBUS_L_GRAM_JM_USAGE_VER,
            usage_ent->target);
        result = globus_usage_stats_handle_init(
            &usage_ent->job_handle,
            GLOBUS_L_GRAM_JOB_USAGE_ID,
            GLOBUS_L_GRAM_JOB_USAGE_VER,
            usage_ent->target);
    }

    if(target_str)
    {
        globus_free(target_str);
    }
    
    return result;
}
/* globus_i_gram_usage_stats_init() */


/**
 * Periodic usage stats callback implementation
 *
 * @param user_arg
 *     Job manager state cast to void *.
 *
 * @return
 *     void
 */
static
void
globus_l_gram_kickout_session_stats(
    void *                              user_arg)
{
    globus_i_gram_send_session_stats(
        (globus_gram_job_manager_t *) user_arg);
}
/* globus_l_gram_kickout_session_stats() */


/**
 * Start sending periodic job manager session statistics to the usage stats
 * service
 *
 * @param manager
 *     Job manager state.
 *
 * @return
 *     Result of registering a callback handler to periodically send
 *     usage stats reports.
 */
globus_result_t
globus_i_gram_usage_start_session_stats(
    globus_gram_job_manager_t *         manager)
{
    globus_result_t                     result;
    globus_reltime_t                    delay;

    if(manager->config->usage_disabled)
    {
        return GLOBUS_SUCCESS;
    }

    globus_i_gram_send_session_stats(manager);
    
    GlobusTimeReltimeSet(delay, 60*60, 0);
    result = globus_callback_register_periodic(
            &manager->usagetracker->session_timer_handle,
            &delay,
            &delay,
            globus_l_gram_kickout_session_stats,
            manager);

    return result;
}
/* globus_i_gram_usage_start_session_stats() */

/**
 * Unregister the job status callbacks and send a final callback
 *
 * @param manager
 *     Job manager state.
 *
 * @return
 *     Result of unregistering the callback handle associated the 
 *     periodic job manager usage stats reports.
 */
globus_result_t
globus_i_gram_usage_end_session_stats(
    globus_gram_job_manager_t *         manager)
{
    globus_result_t                     result;

    if(manager->config->usage_disabled)
    {
        return GLOBUS_SUCCESS;
    }
    result = globus_callback_unregister(
        manager->usagetracker->session_timer_handle, NULL, NULL, NULL);
    
    globus_i_gram_send_session_stats(manager);
    
    return result;
}
/* globus_i_gram_usage_end_session_stats() */
