/*
 * globus_i_rsl_assist.h
 *
 * Description:
 *
 *   This header contains the interface prototypes for some internal function
 *   from globus_rsl_assist.a. Those function are kept internal because they 
 *   should be moved in the future in a new "mds_assist" library. 
 *   
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#ifndef _GLOBUS_I_RSL_ASSIST_INCLUDE_GLOBUS_RSL_ASSIST_H_
#define _GLOBUS_I_RSL_ASSIST_INCLUDE_GLOBUS_RSL_ASSIST_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

/*
 * globus_rsl_assist_get_rm_contact()
 *
 *     Return the resourceManagerContact corresponding to 
 *     the resourceManagerName given as argument, by querying the MDS. 
 *
 * Parameters:
 *    resourceManagerName - String containing the Name of the Resource Manager
 *
 * Returns:
 *    Pointer to a newly allocated string containing the Resource
 *    Manager Contact. This string MUST be freed by the user.
 *    OR
 *    GLOBUS_NULL in case of failure.
 */
char*
globus_i_rsl_assist_get_rm_contact(char* resourceManagerName);

/*
 * Structure: job_listing_entry_t
 *
 * This structure is used by the function
 * globus_rsl_assist_get_job_contact_list() to return a list of job contact,
 * job rsl and job status
 */

/*
  typedef struct
{
    char *    job_contact;
    char *    rsl_string;
    char *    status;
} globus_i_rsl_assist_job_listing_entry_t;
*/

typedef char * globus_i_rsl_assist_job_listing_entry_t;

/*
 * globus_rsl_assist_get_job_contact_list()
 *
 *     By querying the MDS, return the list of job contact currently
 *     registerd in the MDS, the rsl for each job and the status of the job.
 *     The user code must free each string of the structure and string
 *     itself when it is not usefull anymore.
 *     
 *
 * Parameters:
 *     None; Remarq: It uses the "globus environment variable" defining
 *     the MDS host and port to contact.
 *    
 *
 * Returns:
 *    A pointer to the head of a list of  
 *    globus_i_rsl_assist_job_listing_entry_t defined above.
 *    OR
 *    GLOBUS_NULL in case of failure.
 */
int
globus_i_rsl_assist_get_job_contact_list(globus_list_t ** job_contact_list);

#endif


