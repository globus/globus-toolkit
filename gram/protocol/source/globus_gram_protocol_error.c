#include "globus_gram_client.h"

static char *
globus_l_gram_client_error_strings[] =
{
  /* these error strings are phrased to fit grammatically into 
   * a sentence of the form "the job failed because <string>"
   */

    "Success",
    "one of the RSL parameters is not supported",
    "the RSL lentgh is greater than the maximum allowed",
    "of an unused NO_RESOURCES",  /* NEEDS EDITING */
    "unable to set default to the directory requested",  /* NEEDS EDITING */
    "the executable does not exist",
    "of an unused INSUFFICIENT_FUNDS",   /* NEEDS EDITING */
    "authentication with the remote server failed",
    "of an unused USER_CANCELLED",  /* NEEDS EDITING */
    "of an unused SYSTEM_CANCELLED",  /* NEEDS EDITING */
    "data transfer to the server failed",
    "the stdin file does not exist",
    "the connection to the server failed (check host and port)",  /* NEEDS EDITING */
    "the provided RSL 'maxtime' value is not an integer",
    "the provided RSL 'count' value is not an integer",
    "the job manager received an invalid RSL",
    "the job manager failed in allowing others to make contact",  /* NEEDS EDITING */
    "the job failed when the job manager attempted to run it",
    "an invalid paradyn was specified",  /* NEEDS EDITING */
    "the provided RSL 'jobtype' value is invalid",
    "the provided RSL 'myjob' value is invalid",
    "the job manager failed to locate an internal script argument file",
    "the job manager failed to create an internal script argument file",
    "the job manager detected an invalid job state",
    "the job manager detected an invalid script response",
    "the job manager detected an invalid job state",
    "the provided RSL 'jobtype' value is not supported by this job manager",
    "unused ERROR_UNIMPLEMENTED",  /* NEEDS EDITING */
    "the job manager failed to create an internal script submission file",
    "the job manager cannot find the user proxy",
    "the job manager failed to open the user proxy",
    "the job manager failed to cancel the job as requested",
    "system memory allocation failed",
    "the interprocess job communication initialization failed",
    "the interprocess job communication setup failed",  /* REDUNDANT? */
    "the provided RSL 'host count' value is invalid",  /* REDUNDANT? */
    "one of the provided RSL parameters is unsupported",
    "the provided RSL 'queue' parameter is invalid",
    "the provided RSL 'project' parameter is invalid",
    "the provided RSL string includes variables that could not be identified",
    "the provided RSL 'environment' parameter is invalid",
    "the provided RSL 'dryrun' parameter is invalid",
    "the provided RSL is invalid (an empty string)",
    "the job manager failed to stage the executable",
    "the job manager failed to stage the stdin file",
    "the requested job manager type is invalid",
    "the provided RSL 'arguments' parameter is invalid",
    "the gatekeeper failed to run the job manager",
    "the provided RSL could not be properly parsed",
    "there is a version mismatch between GRAM components",
    "the provided RSL 'arguments' parameter is invalid",
    "the provided RSL 'count' parameter is invalid",
    "the provided RSL 'directory' parameter is invalid",
    "the provided RSL 'dryrun' parameter is invalid",
    "the provided RSL 'environment' parameter is invalid",
    "the provided RSL 'executable' parameter is invalid",
    "the provided RSL 'host_count' parameter is invalid",
    "the provided RSL 'jobtype' parameter is invalid",
    "the provided RSL 'maxtime' parameter is invalid",
    "the provided RSL 'myjob' parameter is invalid",
    "the provided RSL 'paradyn' parameter is invalid",
    "the provided RSL 'project' parameter is invalid",
    "the provided RSL 'queue' parameter is invalid",
    "the provided RSL 'stderr' parameter is invalid",
    "the provided RSL 'stdin' parameter is invalid",
    "the provided RSL 'stdout' parameter is invalid",
    "the job manager failed to locate an internal script",
    "the job manager failed on the system call pipe()",
    "the job manager failed on the system call fcntl()",
    "the job manager failed to create the temporary stdout filename",
    "the job manager failed to create the temporary stderr filename",
    "the job manager failed on the system call fork()",
    "the executable file permissions do not allow execution",
    "the job manager failed to open stdout",
    "the job manager failed to open stderr",
    "the cache file could not be opened in order to relocate the user proxy",  /* NEEDS EDITING */
    "the job manager failed to open the cache",  /* NEEDS EDITING */
    "the job manager failed to insert the contact in the client contact list",
    "the contact was not found in the job manager's client contact list",
    "connecting to the job manager failed.  Possible reasons: job terminated, invalid job contact, network problems, ...",
    "the syntax of the job contact is invalid",
    "the executable parameter in the RSL is undefined",
    "the job manager service is misconfigured.  condor arch undefined",
    "the job manager service is misconfigured.  condor os undefined",
    "the provided RSL 'min_memory' parameter is invalid",
    "the provided RSL 'max_memory' parameter is invalid",
    "the RSL 'min_memory' value is not zero or greater",
    "the RSL 'max_memory' value is not zero or greater",
    "the creation of a HTTP message failed",
    "parsing incoming HTTP message failed",
    "the packing of information into a HTTP message failed"
    "an incoming HTTP message did not include the necessary information"
    "the job manager was unable the service the client request"
};

const char *
globus_gram_client_error_string(int error_code)
{
    if (error_code < 0 || error_code >= GRAM_ERROR_LAST)
        return("Invalid error code");
    return(globus_l_gram_client_error_strings[error_code]);
} /* globus_gram_client_error_string() */
