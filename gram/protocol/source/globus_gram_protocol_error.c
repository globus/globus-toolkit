#include "globus_gram_client.h"

static char *
globus_l_gram_client_error_strings[GLOBUS_GRAM_CLIENT_ERROR_LAST] =
{
  /* 
   * these error strings are phrased to fit grammatically into 
   * a sentence of the form "the job failed because <string>"
   */

/*   0 */     "Success",
/*   1 */     "one of the RSL parameters is not supported",
/*   2 */     "the RSL lentgh is greater than the maximum allowed",
/*   3 */     "of an unused NO_RESOURCES",  /* NEEDS EDITING */
/*   4 */     "jobmanager unable to set default to the directory requested",
/*   5 */     "the executable does not exist",
/*   6 */     "of an unused INSUFFICIENT_FUNDS",   /* NEEDS EDITING */
/*   7 */     "authentication with the remote server failed",
/*   8 */     "of an unused USER_CANCELLED",  /* NEEDS EDITING */
/*   9 */     "of an unused SYSTEM_CANCELLED",  /* NEEDS EDITING */
/*  10 */     "data transfer to the server failed",
/*  11 */     "the stdin file does not exist",
/*  12 */     "the connection to the server failed (check host and port)",
/*  13 */     "the provided RSL 'maxtime' value is not an integer",
/*  14 */     "the provided RSL 'count' value is not an integer",
/*  15 */     "the job manager received an invalid RSL",
/*  16 */     "the job manager failed in allowing others to make contact",
/*  17 */     "the job failed when the job manager attempted to run it",
/*  18 */     "an invalid paradyn was specified",  /* NEEDS EDITING */
/*  19 */     "the provided RSL 'jobtype' value is invalid",
/*  20 */     "the provided RSL 'myjob' value is invalid",
/*  21 */     "the job manager failed to locate an internal script argument file",
/*  22 */     "the job manager failed to create an internal script argument file",
/*  23 */     "the job manager detected an invalid job state",
/*  24 */     "the job manager detected an invalid script response",
/*  25 */     "the job manager detected an invalid job state",
/*  26 */     "the provided RSL 'jobtype' value is not supported by this job manager",
/*  27 */     "unused ERROR_UNIMPLEMENTED",  /* NEEDS EDITING */
/*  28 */     "the job manager failed to create an internal script submission file",
/*  29 */     "the job manager cannot find the user proxy",
/*  30 */     "the job manager failed to open the user proxy",
/*  31 */     "the job manager failed to cancel the job as requested",
/*  32 */     "system memory allocation failed",
/*  33 */     "the interprocess job communication initialization failed",
/*  34 */     "the interprocess job communication setup failed",  /* REDUNDANT? */
/*  35 */     "the provided RSL 'host count' value is invalid",  /* REDUNDANT? */
/*  36 */     "one of the provided RSL parameters is unsupported",
/*  37 */     "the provided RSL 'queue' parameter is invalid",
/*  38 */     "the provided RSL 'project' parameter is invalid",
/*  39 */     "the provided RSL string includes variables that could not be identified",
/*  40 */     "the provided RSL 'environment' parameter is invalid",
/*  41 */     "the provided RSL 'dryrun' parameter is invalid",
/*  42 */     "the provided RSL is invalid (an empty string)",
/*  43 */     "the job manager failed to stage the executable",
/*  44 */     "the job manager failed to stage the stdin file",
/*  45 */     "the requested job manager type is invalid",
/*  46 */     "the provided RSL 'arguments' parameter is invalid",
/*  47 */     "the gatekeeper failed to run the job manager",
/*  48 */     "the provided RSL could not be properly parsed",
/*  49 */     "there is a version mismatch between GRAM components",
/*  50 */     "the provided RSL 'arguments' parameter is invalid",
/*  51 */     "the provided RSL 'count' parameter is invalid",
/*  52 */     "the provided RSL 'directory' parameter is invalid",
/*  53 */     "the provided RSL 'dryrun' parameter is invalid",
/*  54 */     "the provided RSL 'environment' parameter is invalid",
/*  55 */     "the provided RSL 'executable' parameter is invalid",
/*  56 */     "the provided RSL 'host_count' parameter is invalid",
/*  57 */     "the provided RSL 'jobtype' parameter is invalid",
/*  58 */     "the provided RSL 'maxtime' parameter is invalid",
/*  59 */     "the provided RSL 'myjob' parameter is invalid",
/*  60 */     "the provided RSL 'paradyn' parameter is invalid",
/*  61 */     "the provided RSL 'project' parameter is invalid",
/*  62 */     "the provided RSL 'queue' parameter is invalid",
/*  63 */     "the provided RSL 'stderr' parameter is invalid",
/*  64 */     "the provided RSL 'stdin' parameter is invalid",
/*  65 */     "the provided RSL 'stdout' parameter is invalid",
/*  66 */     "the job manager failed to locate an internal script",
/*  67 */     "the job manager failed on the system call pipe()",
/*  68 */     "the job manager failed on the system call fcntl()",
/*  69 */     "the job manager failed to create the temporary stdout filename",
/*  70 */     "the job manager failed to create the temporary stderr filename",
/*  71 */     "the job manager failed on the system call fork()",
/*  72 */     "the executable file permissions do not allow execution",
/*  73 */     "the job manager failed to open stdout",
/*  74 */     "the job manager failed to open stderr",
/*  75 */     "the cache file could not be opened in order to relocate the user proxy",  /* NEEDS EDITING */
/*  76 */     "the job manager failed to open the cache",  /* NEEDS EDITING */
/*  77 */     "the job manager failed to insert the contact in the client contact list",
/*  78 */     "the contact was not found in the job manager's client contact list",
/*  79 */     "connecting to the job manager failed.  Possible reasons: job terminated, invalid job contact, network problems, ...",
/*  80 */     "the syntax of the job contact is invalid",
/*  81 */     "the executable parameter in the RSL is undefined",
/*  82 */     "the job manager service is misconfigured.  condor arch undefined",
/*  83 */     "the job manager service is misconfigured.  condor os undefined",
/*  84 */     "the provided RSL 'min_memory' parameter is invalid",
/*  85 */     "the provided RSL 'max_memory' parameter is invalid",
/*  86 */     "the RSL 'min_memory' value is not zero or greater",
/*  87 */     "the RSL 'max_memory' value is not zero or greater",
/*  88 */     "the creation of a HTTP message failed",
/*  89 */     "parsing incoming HTTP message failed",
/*  90 */     "the packing of information into a HTTP message failed",
/*  91 */     "an incoming HTTP message did not contain the expected information",
/*  92 */     "the job manager does not support the service that the client requested",
/*  93 */     "the gatekeeper failed to find the requested service",
/*  94 */     "the jobmanager does not accept any new requests (shutting down)",
/*  95 */     "the client failed to close the listener associated with the callback URL"
};

const char *
globus_gram_client_error_string(int error_code)
{
    if (error_code < 0 || error_code >= GRAM_ERROR_LAST)
        return("Invalid error code");
    return(globus_l_gram_client_error_strings[error_code]);
} /* globus_gram_client_error_string() */
