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

#endif


