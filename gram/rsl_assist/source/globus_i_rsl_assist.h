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
 * globus_i_rsl_assist_get_rm_contact()
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
 * globus_i_rsl_assist_get_scheduledjob_list()
 *
 *     By querying the MDS, return the list of "scheduledjobs" currently
 *     registerd in the MDS.
 *     The user code must free each string of the list and the list
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
 *    string containing the rsl of the job.
 *    OR
 *    GLOBUS_NULL in case of failure.
 */
int
globus_i_rsl_assist_get_scheduledjob_list(globus_list_t ** job_list);

/*
 * Function: globus_i_rsl_assist_extract_attribute()
 *
 * Parse the RSL rsl and return a string corresponding to the 
 * first attribute "attribute" found in the rsl.
 * Because this function returns only the first string of the first attribute
 * found in the RSL, it is meant to be used with -not-compound-RSLs
 * (e.g.: the RSLs stored in the MDS entries "scheduledjobs",
 * and for attribute with single literal values.
 *
 * Parameters:
 *     rsl -            rsl to parse
 *     attribute -      Attribute to search
 *     value -          the string (char *) corresponding to the values
 *                      of the attribute. (GOBUSS_NULL if none)
 * 
 * Returns:
 *     GLOBUS_SUCCESS or 
 *     error code
 */ 
int
globus_i_rsl_assist_extract_attribute(globus_rsl_t * rsl,
				   char * attribute,
				   char ** value);
#endif


