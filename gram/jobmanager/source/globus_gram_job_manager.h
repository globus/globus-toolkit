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
 * Description:
 *   This header contains the exported interface of the Job Management.
 *
 * CVS Information:
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#ifndef GLOBUS_GRAM_JOB_MANAGER_INCLUDE
#define GLOBUS_GRAM_JOB_MANAGER_INCLUDE

/* Includes */
#include "globus_common.h"
#include "globus_gram_protocol.h"
#include "globus_rsl.h"
#include "globus_gass_cache.h"

/* Defines */

#define GLOBUS_GRAM_AUTHZ_CALLOUT_TYPE "globus_gram_jobmanager_authz"

EXTERN_C_BEGIN

/* Type definitions */
typedef enum
{
    GLOBUS_GRAM_JOB_MANAGER_DONT_SAVE,
    GLOBUS_GRAM_JOB_MANAGER_SAVE_ALWAYS,
    GLOBUS_GRAM_JOB_MANAGER_SAVE_ON_ERROR
}
globus_gram_job_manager_logfile_flag_t;

typedef enum
{
    GLOBUS_GRAM_JOB_MANAGER_STATE_START,
    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE,
    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_COMMITTED,
    GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_IN,
    GLOBUS_GRAM_JOB_MANAGER_STATE_SUBMIT,
    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL1,
    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL2,
    GLOBUS_GRAM_JOB_MANAGER_STATE_CLOSE_OUTPUT,
    GLOBUS_GRAM_JOB_MANAGER_STATE_STAGE_OUT,
    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END,
    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_END_COMMITTED,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FILE_CLEAN_UP,
    GLOBUS_GRAM_JOB_MANAGER_STATE_SCRATCH_CLEAN_UP,
    GLOBUS_GRAM_JOB_MANAGER_STATE_CACHE_CLEAN_UP,
    GLOBUS_GRAM_JOB_MANAGER_STATE_DONE,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CLOSE_OUTPUT,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_TWO_PHASE_COMMITTED,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_FILE_CLEAN_UP,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_SCRATCH_CLEAN_UP,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_CACHE_CLEAN_UP,
    GLOBUS_GRAM_JOB_MANAGER_STATE_FAILED_DONE,
    GLOBUS_GRAM_JOB_MANAGER_STATE_STOP,
    GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_CLOSE_OUTPUT,
    GLOBUS_GRAM_JOB_MANAGER_STATE_STOP_DONE,
    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY1,
    GLOBUS_GRAM_JOB_MANAGER_STATE_POLL_QUERY2,
    GLOBUS_GRAM_JOB_MANAGER_STATE_PROXY_REFRESH,
    GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_CLOSE,
    GLOBUS_GRAM_JOB_MANAGER_STATE_STDIO_UPDATE_OPEN,
    GLOBUS_GRAM_JOB_MANAGER_STATE_PRE_CLOSE_OUTPUT,
    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY1,
    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_QUERY2,
    GLOBUS_GRAM_JOB_MANAGER_STATE_TWO_PHASE_PROXY_REFRESH
}
globus_gram_jobmanager_state_t;

typedef enum
{
    GLOBUS_GRAM_JOB_MANAGER_STAGE_IN,
    GLOBUS_GRAM_JOB_MANAGER_STAGE_IN_SHARED,
    GLOBUS_GRAM_JOB_MANAGER_STAGE_OUT
}
globus_gram_job_manager_staging_type_t;

typedef enum
{
    GLOBUS_GRAM_JOB_MANAGER_SIGNAL,
    GLOBUS_GRAM_JOB_MANAGER_CANCEL,
    GLOBUS_GRAM_JOB_MANAGER_PROXY_REFRESH
}
globus_gram_job_manager_query_type_t;

typedef struct
{
    globus_gram_job_manager_staging_type_t
                                        type;
    globus_rsl_value_t *                from;
    char *                              evaled_from;
    globus_rsl_value_t *                to;
    char *                              evaled_to;
}
globus_gram_job_manager_staging_info_t;

typedef struct
{
    /**
     * Query type
     */
    globus_gram_job_manager_query_type_t
                                        type;
    /**
     * Connection handle
     *
     * Handle to send the script response to.
     */
    globus_gram_protocol_handle_t       handle;
    /**
     * Signal
     *
     * Type of signal to process.
     */
    globus_gram_protocol_job_signal_t   signal;

    /**
     * Signal-specific data
     *
     * If a priority change maybe something like high, medium, low. see
     * the documentation on signals in the globus_gram_protocol library.
     */
    char *                              signal_arg;
    /**
     * Query-specific RSL tree 
     *
     * If the query is a stdio update signal, then the arg is an RSL
     * string which may contain replacement values for
     * stdout, stderr, stdout_position, stderr_position, and remoteio_url.
     * This will be merged with the request's tree as the signal is handled.
     */
    globus_rsl_t *                      rsl;

    globus_gram_protocol_error_t        failure_code;

    /* When doing a proxy refresh, the newly delegated credential */
    gss_cred_id_t                       delegated_credential;
}
globus_gram_job_manager_query_t;

/**
 * Command-line configuration for a LRM instance. All of these items are
 * read from command-line or startup environment and do not change while
 * the job manager is running.
 */
typedef struct
{
    /*
     * -------------------------------------------------------------------
     * Values derived from command-line options and configuration file
     * -------------------------------------------------------------------
     */
    /**
     * Flag denoting the disposition of the log file once the job manager
     * completes monitoring this job.
     */
    globus_gram_job_manager_logfile_flag_t
                                        logfile_flag;
    /** True if we are using kerberos for security instead of X.509
     * certificates.
     */
    globus_bool_t                       kerberos;
    /**
     * Path to globus installation.
     */
    char *                              globus_location;
    /**
     * GLOBUS_LOCATION which can be used on the target execution nodes.
     */
    char *                              target_globus_location;
    /**
     * Job Manager Type
     *
     * Identifies the scheduler which will be used to process this job
     * request. Possible values are fork, loadleveler, lsf, easymcs, pbs,
     * and others.
     */ 
    char *                              jobmanager_type;
    /**
     * Directory to store job state history information
     */
    char *                              job_history_dir;
    /**
     * Default cache path (may contain RSL substitutions)
     */
    char *                              cache_location;
    /**
     * Scratch directory root
     *
     * If the client requests a scratch directory with a relative path,
     * this base directory is prepended to it. It defaults to $(HOME),
     * but can be overridden on the job manager command line or configuration
     * file.
     */
    char *                              scratch_dir_base;
    /**
     * Condor Architecture
     *
     * Used only when type=condor.  Must match one of the archetecture values
     * as defined by condor
     */
    char *                              condor_arch;
    /**
     * Condor Operating System
     *
     * Used only when type=condor.  Must match one of the opsys values as
     * defined by condor
     */ 
    char *                              condor_os;
    /** gatekeeper host RSL substitution */
    char *                              globus_gatekeeper_host;
    /** gatekeeper port RSL substitution */
    char *                              globus_gatekeeper_port;
    /** gatekeeper subject RSL substitution */
    char *                              globus_gatekeeper_subject;
    /** host manufacturer RSL substitution */
    char *                              globus_host_manufacturer;
    /** host cputype RSL substitution */
    char *                              globus_host_cputype;
    /** host OS name RSL substitution */
    char *                              globus_host_osname;
    /** host OS version RSL substitution */
    char *                              globus_host_osversion;
    /**
     * Firewall-friendly range of TCP ports that will be used for network
     * traffic.
     */
    char *                              tcp_port_range;
    /** Directory to store job_state files */
    char *                              job_state_file_dir;
    /**
     * Site-wide trusted certificate path.
     */
    char *                              x509_cert_dir;
    /**
     * Extra site-wide environment variables to add to the job environment.
     */
    char *                              extra_envvars;
    /**
     * SEG module to use instead of polling.
     */
    char *                              seg_module;
    /**
     * Path to job auditing directory.
     */
    char *                              auditing_dir;
    /** Globus Toolkit version */
    char *                              globus_version;
    /**
     * Streaming
     *
     * streaming_disabled is set from the config option -disable-streaming.
     * The default is false.
     * This is passed to the batch system script to decide whether to allow the
     * job. This lets admins disable streaming for most jobs, but allow it for
     * certain ones (e.g. the grid monitor).
     */
    globus_bool_t                       streaming_disabled;
    /**
     * Minimum proxy lifetime (in seconds) to allow. Once it is noticed that
     * the proxy will expire before that time, the job manager will go into the
     * STOP state.
     */
    int                                 proxy_timeout;
    /**
     * Use the single job manager per user / jobmanager type feature
     */
    globus_bool_t                       single;
    /*
     * -------------------------------------------------------------------
     * Values derived from job manager environment
     * -------------------------------------------------------------------
     */
    /** GSI Subject name */
    char *                              subject;
    /** User home directory */
    char *                              home;
    /** Username */
    char *                              logname;
    /** GRAM host */
    char *                              hostname;
}
globus_gram_job_manager_config_t;

/**
 * Runtime state for a LRM instance. All of these items are
 * computed from the configuration state above and may change during the
 * lifetime of the job manager.
 */
typedef struct globus_gram_job_manager_s
{
    /** Link to the static job manager configuration */
    globus_gram_job_manager_config_t *  config;
    /**
     * set to GLOBUS_TRUE when the seg monitoring has begun
     */
    globus_bool_t                       seg_started;

    /**
     * Timestamp of the last SEG event we've completely processed. Initially
     * set to the time of the job submission.
     */
    time_t                              seg_last_timestamp;
    /**
     * Callback handle for fork SEG-like polling
     */
    globus_callback_handle_t            fork_callback_handle;
    /**
     * Log File Name
     *
     * A path to a file to append logging information to.
     */
    char *                              jobmanager_logfile;
    /**
     * Log File Pointer
     *
     * A stdio FILE pointer used for logging. NULL if no logging is requested.
     */
    FILE *                              jobmanager_log_fp;
    /** Scheduler-specific set of validation records */
    globus_list_t *                     validation_records;
    /** GRAM job manager listener contact string */
    char *                              url_base;
    /** Timer tracking until the proxy expiration callback causes the job
     * manager to stop.
     */
    globus_callback_handle_t            proxy_expiration_timer;
    /** Hashtable mapping request->job_contact_path to request */
    globus_hashtable_t                  request_hash;
    /** Hashtable mapping job id->job_contact_path */
    globus_hashtable_t                  job_id_hash;
    /** Lock for thread-safety */
    globus_mutex_t                      mutex;
    /** Condition for noting when all jobs are done */
    globus_cond_t                       cond;
    /** Unix domain socket for receiving new job requests from other job
     * managers */
    int                                 socket_fd;
    /** XIO Handle for socket_fd so we can use XIO's select() loop */
    globus_xio_handle_t                 active_job_manager_handle;
    /** Lock file related to the socket_fd */
    int                                 lock_fd;
    /** Lock file path */
    char *                              lock_path;
    /** Fifo of script contexts ready to run */
    globus_fifo_t                       script_fifo;
    /** Number of script slots available for running scripts */
    int                                 script_slots_available;
    /** Fifo of job state callback contexts to run */
    globus_fifo_t                       state_callback_fifo;
    /** Number of job state contact slots available */
    int                                 state_callback_slots;
}
globus_gram_job_manager_t;

/**
 * Job Manager Request
 */
typedef struct
{
    /** Link to LRM-specific configuration */
    globus_gram_job_manager_config_t *  config;
    /** Link to LRM-specific runtime state */
    globus_gram_job_manager_t *         manager;
    /**
     * Job State
     *
     * The state of the job. This corresponds to the job state machine
     * described in the GRAM documentation.
     *
     * Use globus_gram_job_manager_request_set_status() to change.
     *
     * @todo add link 
     */ 
    globus_gram_protocol_job_state_t    status;

    /**
     * Last time status was changed
     *
     * The time that the status member was last changed.
     * Automatically set by globus_gram_job_manager_request_set_status().
     */
    time_t                              status_update_time;

    /**
     * Job Failure Reason
     *
     * If the state is GLOBUS_GRAM_STATE_FAILED, then this
     * is an integer code that defines the failure. It is one of
     * GLOBUS_GRAM_PROTOCOL_ERROR_*.
     */
    int                                 failure_code;
    
    /**
     * Job identifier string
     *
     * String representation of the LRM job id. May be a comma-separated
     * string of uniquely-pollable ID values. This value is filled in when the
     * request is submitted.
     */
    char *                              job_id_string;
    
    /**
     * Poll Frequency
     *
     * How often should a check of the job status and output files be done.
     */
    unsigned int                        poll_frequency;

    /**
     * Dry Run
     *
     * If this is GLOBUS_TRUE, do not actually submit the job to the scheduler,
     * just verify the job parameters.
     */
    globus_bool_t                       dry_run;


    /**
     *
     * Two-phase commit.
     *
     * Non-zero if request should be confirmed via another signal.
     *
     * The value is how many seconds to wait before timing out.
     */
    int                                 two_phase_commit;

    /**
     * Value to extend the two-phase commit wait time by if a commit extend
     * signal arrives.
     */
    int                                 commit_extend;

    /**
     * Save Job Manager State
     *
     * Generate a state file for possibly restarting the job manager
     * at a later time after a failure or signal.
     */
    globus_bool_t                       save_state;

    /** Time when job manager process is first begun */
    time_t                              creation_time;
    /** Time when job manager gets jobid from scheduler */
    time_t                              queued_time;
    /** Job-specific GASS cache tag. */
    char *                              cache_tag;
    /** RSL substitution symbol table */
    globus_symboltable_t                symbol_table;
    /** Parsed RSL values */
    globus_rsl_t *                      rsl;
    /** Canonical RSL document */
    char *                              rsl_spec;
    /**
     * Previous Job Manager Contact 
     *
     * If we're restarting from a terminated Job Manager, this will specify
     * the old job contact so we can locate the Job Manager state file.
     */
    char *                              jm_restart;
    /**
     * Unique job identifier
     *
     * Unique id for this job that will be consistent
     * across jobmanager restarts/recoveries.
     */
    char *                              uniq_id;
    /** Job contact string */
    char *                              job_contact;
    /** Unique job contact suffix */
    char *                              job_contact_path;
    /** Job-specific persistence file */
    char *                              job_state_file;
    /** Job-specific persistence lock file */
    char *                              job_state_lock_file;
    /** Job-specific scratch directory after RSL evaluation */
    char *                              scratch_dir_base;
    /**
     * Job scratch directory.
     *
     * Scratch subdirectory created for this job. It will be removed
     * when the job completes. This is a subdirectory of scratch_dir_base.
     */
    char *                              scratchdir;
    /** remote_io_url value */
    char *                              remote_io_url;
    /** file to write remote_io_url to */
    char *                              remote_io_url_file;
    /** Job-specific proxy file */
    char *                              x509_user_proxy;
    /** Job-specific persistence lock descriptor */
    int                                 job_state_lock_fd;
    /** Thread safety */
    globus_mutex_t                      mutex;
    /** Thread safety */
    globus_cond_t                       cond;
    /** Clients registered for job state changes */
    globus_list_t *                     client_contacts;
    /** List of file_stage_in values which haven't yet been processed */
    globus_list_t *                     stage_in_todo;
    /** List of file_stage_in_shared values which haven't yet been processed */
    globus_list_t *                     stage_in_shared_todo;
    /** List of file_stage_out values which haven't yet been processed */
    globus_list_t *                     stage_out_todo;
    /** Current state machine state */
    globus_gram_jobmanager_state_t      jobmanager_state;
    /** State to resume from in the case of a restart */
    globus_gram_jobmanager_state_t      restart_state;
    /**
     * True if a job state change hasn't been sent to the callbacks registered
     * with it
     */
    globus_bool_t                       unsent_status_change;
    /** Timer tracking until the next job poll */
    globus_callback_handle_t            poll_timer;
    /**
     * Queue of job-specific operations (signals, cancel, etc) sent via the job
     * interface.
     */
    globus_fifo_t                       pending_queries;
    /** Directory for temporary job-specific files. */
    char *                              job_dir;
    /**
     * streaming_requested is set to true if there's at least one remote
     * destination for stdout or stderr. Otherwise, it's false.
     */
    globus_bool_t                       streaming_requested;
    /** Job-specific cache path after RSL evaluation */
    char *                              cache_location;
    /** Handle to add/remove files from the GASS cache */
    globus_gass_cache_t                 cache_handle;
    /** Path to job history file */
    char *                              job_history_file;
    /** Last job state stored in the job history file */
    int                                 job_history_status;
     /**
      * Value of the GLOBUS_CACHED_STDOUT RSL substitution
      */
    char *                              cached_stdout;
     /**
      * Value of the GLOBUS_CACHED_STDERR RSL substitution
      */
    char *                              cached_stderr;
    /** Security context used to submit job */
    gss_ctx_id_t                        response_context;
    /** Job Contact of this job when being handled by another process */
    char *                              old_job_contact;
    /**
     * Queue of pending SEG events
     */
    globus_fifo_t                       seg_event_queue;
}
globus_gram_jobmanager_request_t;

/* globus_gram_job_manager_config.c */
int
globus_gram_job_manager_config_init(
    globus_gram_job_manager_config_t *  config,
    int                                 argc,
    char **                             argv,
    char **                             rsl);

void
globus_gram_job_manager_config_destroy(
    globus_gram_job_manager_config_t *  config);

/* globus_gram_job_manager_request.c */
int
globus_gram_job_manager_request_init(
    globus_gram_jobmanager_request_t ** request,
    globus_gram_job_manager_t *         manager,
    char *                              rsl,
    gss_cred_id_t                       delegated_credential,
    gss_ctx_id_t                        response_ctx);

void
globus_gram_job_manager_request_destroy(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_request_set_status(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_job_state_t    status);

int
globus_gram_job_manager_request_set_status_time(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_job_state_t    status,
        time_t valid_time);

int
globus_gram_job_manager_request_log(
    globus_gram_jobmanager_request_t *  request,
    const char *                        format,
    ...);

int
globus_gram_job_manager_request_acct(
    globus_gram_jobmanager_request_t *  request,
    const char *                        format,
    ...);

int
globus_gram_job_manager_symbol_table_populate(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_history_file_set(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_history_file_create(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_request_load(
    globus_gram_job_manager_t *         manager,
    int                                 http_body_fd,
    int                                 context_fd,
    gss_cred_id_t                       credential,
    globus_gram_jobmanager_request_t ** request,
    gss_ctx_id_t *                      context,
    char **                             contact,
    int *                               job_state_mask);

int
globus_gram_job_manager_request_start(
    globus_gram_job_manager_t *         manager,
    globus_gram_jobmanager_request_t *  request,
    int                                 response_fd,
    const char *                        client_contact,
    int                                 job_state_mask);

void
globus_gram_job_manager_destroy_directory(
    globus_gram_jobmanager_request_t *  request,
    const char *                        directory);


/* globus_gram_job_manager_validate.c */

/**
 * Select when an RSL parameter is valid or required.
 * @ingroup globus_gram_job_manager_rsl_validation 
 */
typedef enum
{
    GLOBUS_GRAM_VALIDATE_JOB_SUBMIT = 1,
    GLOBUS_GRAM_VALIDATE_JOB_MANAGER_RESTART = 2,
    GLOBUS_GRAM_VALIDATE_STDIO_UPDATE = 4
}
globus_gram_job_manager_validation_when_t;

extern
int
globus_gram_job_manager_validation_init(
    globus_gram_job_manager_t *         config);

extern
int
globus_gram_job_manager_validation_destroy(
    globus_list_t *                     validation_records);

extern
int
globus_gram_job_manager_validate_rsl(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_job_manager_validation_when_t
                                        when);

/* globus_gram_job_manager_contact.c */
int
globus_gram_job_manager_contact_add(
    globus_gram_jobmanager_request_t *  request,
    const char *                        contact,
    int                                 job_state_mask);

int
globus_gram_job_manager_contact_remove(
    globus_gram_jobmanager_request_t *  request,
    const char *                        contact);
int
globus_gram_job_manager_contact_list_free(
    globus_gram_jobmanager_request_t *  request);

void
globus_gram_job_manager_contact_state_callback(
    globus_gram_jobmanager_request_t *  request);

/* globus_gram_job_manager_state.c */
void
globus_gram_job_manager_state_machine_callback(
    void *                              arg);

globus_bool_t
globus_gram_job_manager_state_machine(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_read_request(
    globus_gram_job_manager_t *         manager,
    int                                 fd,
    char **                             rsl,
    char **                             client_contact,
    int *                               job_state_mask);

int
globus_gram_job_manager_reply(
    globus_gram_jobmanager_request_t *  request,
    int                                 response_code,
    const char *                        job_contact,
    int                                 response_fd,
    gss_ctx_id_t                        response_context);

int
globus_gram_job_manager_validate_username(
    globus_gram_jobmanager_request_t *  request);

/* globus_gram_job_manager_gsi.c */
int
globus_gram_job_manager_import_sec_context(
    globus_gram_job_manager_t *         manager,
    int                                 context_fd,
    gss_ctx_id_t *                      response_contextp);

globus_bool_t
globus_gram_job_manager_gsi_used(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_gsi_register_proxy_timeout(
    globus_gram_job_manager_t *         manager,
    gss_cred_id_t                       cred,
    int                                 timeout,
    globus_callback_handle_t *          callback_handle);

int
globus_gram_job_manager_gsi_get_subject(
    char **                             subject_name);

int
globus_gram_job_manager_gsi_update_credential(
    globus_gram_jobmanager_request_t *  request,
    gss_cred_id_t                       credential);

int
globus_gram_job_manager_gsi_update_proxy_timeout(
    globus_gram_job_manager_t *         manager,
    gss_cred_id_t                       cred,
    int                                 timeout,
    globus_callback_handle_t *          callback_handle);

int
globus_gram_job_manager_gsi_relocate_proxy(
    globus_gram_jobmanager_request_t *  request,
    const char *                        new_proxy);

int
globus_gram_job_manager_call_authz_callout(
    gss_ctx_id_t                        request_context,
    gss_ctx_id_t                        authz_context,
    const char *                        uniq_id,
    const globus_rsl_t *                rsl,
    const char *                        auth_type);

/* globus_gram_job_manager_query.c */
void
globus_gram_job_manager_query_callback(
    void *                              arg,
    globus_gram_protocol_handle_t       handle,
    globus_byte_t *                     buf,
    globus_size_t                       nbytes,
    int                                 errorcode,
    char *                              uri);

void
globus_gram_job_manager_query_delegation_callback(
    void *                              arg,
    globus_gram_protocol_handle_t       handle,
    gss_cred_id_t                       credential,
    int                                 error_code);

void
globus_gram_job_manager_query_reply(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_job_manager_query_t *   query);

/* globus_gram_job_manager_staging.c */
int
globus_gram_job_manager_staging_create_list(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_staging_remove(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_job_manager_staging_type_t
                                        type,
    char *                              from,
    char *                              to);

int
globus_gram_job_manager_staging_write_state(
    globus_gram_jobmanager_request_t *  request,
    FILE *                              fp);
int
globus_gram_job_manager_staging_read_state(
    globus_gram_jobmanager_request_t *  request,
    FILE *                              fp);

void
globus_gram_job_manager_staging_free_all(
    globus_gram_jobmanager_request_t *  request);

/* globus_gram_job_manager_rsl.c */
globus_rsl_t *
globus_gram_job_manager_rsl_merge(
    globus_rsl_t *                      base_rsl,
    globus_rsl_t *                      override_rsl);

globus_bool_t
globus_gram_job_manager_rsl_attribute_exists(
    globus_rsl_t *                      rsl,
    const char *                        attribute);

globus_bool_t
globus_gram_job_manager_rsl_need_stage_in(
    globus_gram_jobmanager_request_t *  request);

globus_bool_t
globus_gram_job_manager_rsl_need_stage_out(
    globus_gram_jobmanager_request_t *  request);

globus_bool_t
globus_gram_job_manager_rsl_need_file_cleanup(
    globus_gram_jobmanager_request_t *  request);

globus_bool_t
globus_gram_job_manager_rsl_need_scratchdir(
    globus_gram_jobmanager_request_t *  request);

globus_bool_t
globus_gram_job_manager_rsl_need_restart(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_rsl_env_add(
    globus_rsl_t *                      ast_node,
    const char *                        var,
    const char *                        value);

int
globus_gram_job_manager_rsl_eval_one_attribute(
    globus_gram_jobmanager_request_t *  request,
    char *                              attribute,
    char **                             value);

int
globus_gram_job_manager_rsl_remove_attribute(
    globus_gram_jobmanager_request_t *  request,
    char *                              attribute);

globus_rsl_t *
globus_gram_job_manager_rsl_extract_relation(
    globus_rsl_t *                      rsl,
    const char *                        attribute);

int
globus_gram_job_manager_rsl_add_relation(
    globus_rsl_t *                      rsl,
    globus_rsl_t *                      relation);

int
globus_gram_job_manager_rsl_parse_value(
    globus_gram_jobmanager_request_t *  request,
    char *                              value_string,
    globus_rsl_value_t **               rsl_value);

int
globus_gram_job_manager_rsl_evaluate_value(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_value_t *                value,
    char **                             value_string);

int
globus_gram_job_manager_rsl_eval_string(
    globus_gram_jobmanager_request_t *  request,
    char *                              string,
    char **                             value_string);

int
globus_gram_job_manager_rsl_attribute_get_string_value(
    globus_rsl_t *                      rsl,
    const char *                        attribute,
    const char **                       value_ptr);

int
globus_gram_job_manager_rsl_attribute_get_boolean_value(
    globus_rsl_t *                      rsl,
    const char *                        attribute,
    globus_bool_t *                     value_ptr);

int
globus_gram_job_manager_rsl_attribute_get_int_value(
    globus_rsl_t *                      rsl,
    const char *                        attribute,
    int *                               value_ptr);

int
globus_gram_rsl_add_output(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_t *                      rsl,
    const char *                        attribute,
    const char *                        value);

int
globus_gram_rsl_add_stage_out(
    globus_gram_jobmanager_request_t *  request,
    globus_rsl_t *                      rsl,
    const char *                        source,
    const char *                        destination);

/* globus_gram_job_manager_state_file.c */
int
globus_gram_job_manager_state_file_set(
    globus_gram_jobmanager_request_t *  request,
    char **                             state_file,
    char **                             state_lock_file);

int
globus_gram_job_manager_file_lock(
    int                                 fd);

int
globus_gram_job_manager_state_file_read(
    globus_gram_jobmanager_request_t *  request);
int
globus_gram_job_manager_state_file_write(
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_state_file_register_update(
    globus_gram_jobmanager_request_t *  request);

/* globus_gram_job_manager_script.c */
int 
globus_gram_job_manager_script_stage_in(
    globus_gram_jobmanager_request_t *  request);
int 
globus_gram_job_manager_script_stage_out(
    globus_gram_jobmanager_request_t *  request);
int 
globus_gram_job_manager_script_submit(
    globus_gram_jobmanager_request_t *  request);
int 
globus_gram_job_manager_script_poll(
    globus_gram_jobmanager_request_t *  request);
int
globus_gram_job_manager_script_signal(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_job_manager_query_t *   query);
int
globus_gram_job_manager_script_cancel(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_job_manager_query_t *   query);

globus_bool_t
globus_i_gram_job_manager_script_valid_state_change(
    globus_gram_jobmanager_request_t *  request,
    globus_gram_protocol_job_state_t    new_state);

extern globus_xio_driver_t              globus_i_gram_job_manager_popen_driver;
extern globus_xio_stack_t               globus_i_gram_job_manager_popen_stack;

/* globus_gram_job_manager_seg.c */
globus_result_t
globus_gram_job_manager_init_seg(
    globus_gram_job_manager_t *         request);

globus_result_t
globus_gram_job_manager_shutdown_seg(
    const char *                        seg_module);

void
globus_gram_job_manager_seg_handle_event(
    globus_gram_jobmanager_request_t *  request);

/* globus_gram_job_manager_auditing.c */
int
globus_gram_job_manager_auditing_file_write(
    globus_gram_jobmanager_request_t *  request);

/* globus_gram_job_manager.c */
int
globus_gram_job_manager_init(
    globus_gram_job_manager_t *         manager,
    gss_cred_id_t                       cred,
    globus_gram_job_manager_config_t *  config);

void
globus_gram_job_manager_destroy(
    globus_gram_job_manager_t *         manager);

int
globus_gram_job_manager_read_rsl(
    globus_gram_job_manager_t *         manager,
    char **                             rsl,
    char **                             contact,
    int *                               job_state_mask);

int
globus_gram_job_manager_log(
    globus_gram_job_manager_t *         manager,
    const char *                        format,
    ...);

int
globus_gram_job_manager_add_request(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_add_reference(
    globus_gram_job_manager_t *         manager,
    const char *                        key,
    globus_gram_jobmanager_request_t ** request);

int
globus_gram_job_manager_remove_reference(
    globus_gram_job_manager_t *         manager,
    const char *                        key);

int
globus_gram_job_manager_register_job_id(
    globus_gram_job_manager_t *         manager,
    char *                              job_id,
    globus_gram_jobmanager_request_t *  request);

int
globus_gram_job_manager_unregister_job_id(
    globus_gram_job_manager_t *         manager,
    char *                              job_id);

int
globus_gram_job_manager_add_reference_by_jobid(
    globus_gram_job_manager_t *         manager,
    const char *                        jobid,
    globus_gram_jobmanager_request_t ** request);

int
globus_gram_job_manager_get_job_id_list(
    globus_gram_job_manager_t *         manager,
    globus_list_t **                    job_id_list);

globus_bool_t
globus_gram_job_manager_request_exists(
    globus_gram_job_manager_t *         manager,
    const char *                        key);

/* startup_socket.c */
int
globus_gram_job_manager_startup_socket_init(
    globus_gram_job_manager_t *         manager,
    globus_xio_handle_t *               handle,
    int *                               socket_fd,
    int *                               lock_fd);

int
globus_gram_job_manager_starter_send(
    globus_gram_job_manager_t *         manager,
    int                                 http_body_fd,
    int                                 context_fd,
    int                                 response_fd,
    gss_cred_id_t                       cred);

extern globus_xio_driver_t              globus_i_gram_job_manager_file_driver;
extern globus_xio_stack_t               globus_i_gram_job_manager_file_stack;

EXTERN_C_END

#endif /* GLOBUS_GRAM_JOB_MANAGER_INCLUDE */
#endif /* ! GLOBUS_DONT_DOCUMENT_INTERNAL */
