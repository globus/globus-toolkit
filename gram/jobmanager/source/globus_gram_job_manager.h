#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/******************************************************************************
globus_gram_job_manager.h
 
Description:
    This header contains the exported interface of the Job Management.
 
CVS Information:
******************************************************************************/
 
#ifndef GLOBUS_GRAM_JOB_MANAGER_INCLUDE
#define GLOBUS_GRAM_JOB_MANAGER_INCLUDE

/******************************************************************************
                               Includes
******************************************************************************/

#include "globus_common.h"
#include "globus_gram_protocol.h"
#include "globus_rsl.h"
#include "globus_gass_cache.h"

EXTERN_C_BEGIN

/******************************************************************************
                               Type definitions
******************************************************************************/

enum
{
    GLOBUS_GRAM_JOBMANAGER_STATUS_UNCHANGED = 0,
    GLOBUS_GRAM_JOBMANAGER_STATUS_CHANGED = 1,
    GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED = 2
};

/**
 * Job Manager Request
 */
typedef struct
{
    /**
     * Job State
     *
     * The state of the job:
     * - GLOBUS_GRAM_STATE_UNSUBMITTED
     * - GLOBUS_GRAM_STATE_PENDING
     * - GLOBUS_GRAM_STATE_ACTIVE
     * - GLOBUS_GRAM_STATE_FAILED 
     * - GLOBUS_GRAM_STATE_DONE
     * - GLOBUS_GRAM_STATE_SUSPENDED
     */ 
    int					status;

    /**
     * Job Failure Reason
     *
     * If the state is GLOBUS_GRAM_STATE_FAILED, then this
     * is an integer code that defines the failure. It is one of
     * GLOBUS_GRAM_PROTOCOL_ERROR_*.
     */
    int					failure_code;

    /**
     * User data
     *
     * A pointer that can be used by the user for
     * any purpose.
     */ 
    void *				user_pointer;
    
    /**
     * Job identifier
     *
     * Underlying queueing system job id for this job.
     * This value is filled in when the request is submitted.
     */
    char *				job_id;

    /**
     * Unique job identifier
     *
     * Unique id for this job that will be consistent
     * across jobmanager restarts/recoveries.
     */
    char *				uniq_id;

    /**
     * Poll Frequency
     *
     * How often should a check of the job status and output files be done.
     */
    unsigned int			poll_frequency;


    /*
     * The rest of these can be optionally filled in by the user,
     * to define the request. All of these values should be
     * allocated using globus_libc_malloc().
     * The globus_gram_jobmanager_request_destroy() function
     * will free all of these values using globus_libc_free().
     */

    /**
     * Job Manager Type
     *
     * Identifies the scheduler which will be used to process this job
     * request. Possible values are fork, loadleveler, lsf, easymcs, pbs,
     * and others.
     */ 
    char *				jobmanager_type;

    /**
     * Job Manager Script Directory
     *
     * The path to the directory containing the Job Manager's scheduler
     * interface scripts. Usually $GLOBUS_LOCATION/libexec
     */
    char *				jobmanager_libexecdir;

    /**
     * Log File Name
     *
     * A path to a file to append logging information to.
     */
    char *				jobmanager_logfile;

    /**
     * Log File Pointer
     *
     * A stdio FILE pointer used for logging. NULL if no logging is requested.
     */
    FILE *				jobmanager_log_fp;

     /**
      * Standard Output File Name
      *
      * Absolute path to a file to be used as standard output for the
      * executable.
      */
    char *				local_stdout;

    /**
     * Standard Error File Name
     *
     * Absolute path to a file to be used as standard error for the
     * executable.
     */
    char *				local_stderr;

    /**
     * Condor Architecture
     *
     * Used only when type=condor.  Must match one of the archetecture values
     * as defined by condor
     */
    char *				condor_arch;

    /**
     * Condor Operating System
     *
     * Used only when type=condor.  Must match one of the opsys values as
     * defined by condor
     */ 
    char *				condor_os;

    /**
     * Relative distinguished name
     *
     * Nickname of the job manager in the MDS.
     */
    char *				rdn;

    /**
     * Distinguished name of the host the job manager is running on.
     */
    char *				host_dn;

    char *				org_dn;

    /**
     * Name of the host running the gatekeeper which spawned this job manager.
     */
    char *				gate_host;

    /**
     * Port on which the gatekeeper which spawned this job manager is running.
     */
    char *				gate_port;
    /**
     * Gatekeeper's security subject name.
     */
    char *				gate_subject;
    /**
     * Host operating system name
     */
    char *				host_osname;
    /**
     * Host operating system version
     */
    char *				host_osversion;
    /**
     * Host CPU type
     */
    char *				host_cputype;
    /**
     * Host manufacturer
     */
    char *				host_manufacturer;

    /**
     * Dry Run
     *
     * If this is GLOBUS_TRUE, do not actually submit the job to the scheduler,
     * just verify the job parameters.
     */
    globus_bool_t			dry_run;

    /**
     * Signal
     *
     * Type of signal to process.
     */
    globus_gram_protocol_job_signal_t	signal;

    /**
     * Signal-specific data
     *
     * If a priority change maybe something like high, medium, low. see
     * the documentation on signals in the globus_gram_protocol library.
     */
    char *				signal_arg;

    /**
     *
     * Two-phase commit.
     *
     * Non-zero if request should be confirmed via another signal.
     *
     * The value is how many seconds to wait before timing out.
     */
    int					two_phase_commit;

    /**
     * Save Job Manager State
     *
     * Generate a state file for possibly restarting the job manager
     * at a later time after a failure or signal.
     */
    globus_bool_t			save_state;

    /**
     * Previous Job Manager Contact 
     *
     * If we're restarting from a terminated Job Manager, this will specify the
     * old job contact so we can locate the Job Manager state file.
     */
    char *				jm_restart;


    char *				scratch_dir_base;
    char *				scratchdir;

    struct globus_l_gram_job_manager_output_info_t *
					output;
    globus_gass_cache_t			cache_handle;
    char *				cache_tag;

    globus_rsl_t *			rsl;
    int					ttl_limit;

    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_bool_t			in_handler;
    globus_list_t *			validation_records;
}
globus_gram_jobmanager_request_t;

/**
 * RSL Validation Record
 * @ingroup globus_gram_job_manager_rsl_validation
 *
 * Contains Information parsed from the validation file about a single
 * RSL parameter.
 */
typedef struct
{
    /** The name of the RSL attribute this record refers to. */
    char *				attribute;
    /**
     * A textual description of the RSL parameter. This is not
     * used other than for debugging the parser.
     */
    char *				description;
    /**
     * Default value of the parameter to be inserted in the RSL
     * if the parameter is not present.
     */
    char *				default_value;
    /**
     * String containing an enumeration of legal values for the
     * RSL parameter. For example, for the grammyjob parameter, this
     * would be "collective independent".
     */
    char *				enumerated_values;

    /**
     * Bitwise or of values of the
     * globus_i_gram_job_manager_validation_when_t values, indicated
     * when, if ever, this RSL parameter is required.
     */
    int					required_when;

    /**
     * Bitwise or of values of the
     * globus_i_gram_job_manager_validation_when_t values, indicated
     * when, if ever, this RSL parameter's default value should be
     * inserted into the RSL.
     */
    int					default_when;
    /**
     * Bitwise or of values of the
     * globus_i_gram_job_manager_validation_when_t values, indicated
     * when, if ever, this RSL parameter is valid.
     */
    int					valid_when;
}
globus_gram_job_manager_validation_record_t;

/******************************************************************************
                              Function prototypes
******************************************************************************/

/* Initialize the request structure to its default values.
 */
extern
int
globus_jobmanager_request_init(
    globus_gram_jobmanager_request_t **	request);

/*-----------------------------------------------------------------------
 * Destroy the request structure, and free any associated memory.
 * This function does NOT cancel the job request
 */
extern
int 
globus_jobmanager_request_destroy(
    globus_gram_jobmanager_request_t *	request);

/*-----------------------------------------------------------------------
 * This function makes a request for resources to the local scheduler.
 * It returns GLOBUS_SUCCESS if the job request was able to be executed,
 * otherwise it returns GLOBUS_FAILURE, with the request->failure_code
 * set to GLOBUS_GRAM_ERROR_*.
 */
extern
int 
globus_jobmanager_request(
    globus_gram_jobmanager_request_t *	request);

/*-----------------------------------------------------------------------
 * This function cancels a job regardless of the job's current state.
 * It returns GLOBUS_SUCCESS if the job was successfully cancelled,
 * otherwise it returns GLOBUS_FAILURE.
 */
extern
int 
globus_jobmanager_request_cancel(
    globus_gram_jobmanager_request_t *	request);

/*-----------------------------------------------------------------------
 * This function checks the job's current status, and updates the request
 * structure appropriately.
 * It returns GLOBUS_GRAM_JOBMANAGER_STATE_UNCHANGED if the job status has
 * not changed since the last check, or GLOBUS_GRAM_JOBMANAGER_STATE_CHANGED
 * if the job status has changed
 */
extern
int 
globus_jobmanager_request_check(
    globus_gram_jobmanager_request_t *	request);

extern
int 
globus_jobmanager_request_signal(
    globus_gram_jobmanager_request_t *	request);

extern
int
globus_jobmanager_request_scratchdir(
    globus_gram_jobmanager_request_t *	request);

extern
int
globus_jobmanager_request_rm_scratchdir(
    globus_gram_jobmanager_request_t *	request);

extern
int
globus_jobmanager_log(
    FILE *				log_fp,
    const char *			format,
    ...);

/* globus_gram_job_manager_validate.c */

/**
 * @defgroup globus_gram_job_manager_rsl_validation RSL Validation
 * RSL Validation
 *
 * Validates that a request's RSL contains only valid parameters, and that
 * all required parameters are defined.
 *
 * RSL Validation operates on an RSL, and one or more validation files.
 * The format of the validation files is defined in the
 * @ref globus_gram_job_manager_rsl_validation_file
 * section of the manual.
 */

/**
 * Select when an RSL parameter is valid or required.
 * @ingroup globus_gram_job_manager_rsl_validation 
 */
typedef enum
{
    GLOBUS_GRAM_VALIDATE_JOB_SUBMIT = 1,
    GLOBUS_GRAM_VALIDATE_JOB_MANAGER_RESTART = 2
}
globus_i_gram_job_manager_validation_when_t;

extern
int
globus_i_gram_job_manager_validation_init(
    globus_gram_jobmanager_request_t *  request);

extern
int
globus_gram_job_manager_validate_rsl(
    globus_gram_jobmanager_request_t *  request,
    globus_i_gram_job_manager_validation_when_t
    					when);

/* globus_gram_job_manager_output.c */
extern
int
globus_i_gram_job_manager_output_init(
    globus_gram_jobmanager_request_t *	request);

extern
int
globus_i_gram_job_manager_output_set_urls(
    globus_gram_jobmanager_request_t *	request,
    const char *			type,
    globus_list_t *			url_list,
    globus_list_t *			position_list);

extern
char *
globus_i_gram_job_manager_output_get_cache_name(
    globus_gram_jobmanager_request_t *	request,
    const char *			type);
extern
char *
globus_i_gram_job_manager_output_local_name(
    globus_gram_jobmanager_request_t *	request,
    const char *			type);

extern
int
globus_i_gram_job_manager_output_open(
    globus_gram_jobmanager_request_t *	request);

extern
int
globus_i_gram_job_manager_output_close(
    globus_gram_jobmanager_request_t *	request);

extern
int
globus_i_gram_job_manager_output_write_state(
    globus_gram_jobmanager_request_t *	request,
    FILE *				fp);

extern
int
globus_i_gram_job_manager_output_read_state(
    globus_gram_jobmanager_request_t *	request,
    FILE *				fp);

EXTERN_C_END

#endif /* GLOBUS_GRAM_JOB_MANAGER_INCLUDE */
#endif /* ! GLOBUS_DONT_DOCUMENT_INTERNAL */
