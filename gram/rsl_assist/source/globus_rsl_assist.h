/*
 * globus_rsl_assist.h
 *
 * Description:
 *
 *   This header contains the interface prototypes for the rsl_assist library.
 *   
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#ifndef _GLOBUS_RSL_ASSIST_INCLUDE_GLOBUS_RSL_ASSIST_H_
#define _GLOBUS_RSL_ASSIST_INCLUDE_GLOBUS_RSL_ASSIST_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_common.h"
#include "globus_rsl.h"

#define GLOBUS_RSL_ASSIST_ERROR_GETTING_MANAGER_CONTACT     -1
#define GLOBUS_RSL_ASSIST_ERROR_RSL_INVALID                 -2
#define GLOBUS_RSL_ASSIST_ERROR_MANAGER_NAME_IS_NOT_LITERAL -3

/*
 * Function: globus_rsl_assist_replace_manager_name()
 *
 * Uses the Globus RSL library and the UMich LDAP
 * library to modify an RSL specification, changing instances of
 *
 * resourceManagerName=x
 *
 * with
 *
 * resourceManagerContact=y
 *
 * where y is obtained by querying the MDS ldap server, searching
 * for an object which matches the following filter
 *
 *   (&(objectclass=GlobusResourceManager)(cn=x))
 *
 * and extracting the contact value for that object.
 * 
 * Parameters: 
 *     rsl - Poiter to the RSL structure in which you want to replace the
 *     manager Name by its Contact
 * Returns:
 *     GLOBUS_SUCCESS or
 *     Error code: GLOBUS_RSL_ASSIST_ERROR_GETTING_MANAGER_CONTACT,
 *                 GLOBUS_RSL_ASSIST_ERROR_RSL_INVALID or  
 *                 GLOBUS_RSL_ASSIST_ERROR_MANAGER_NAME_IS_NOT_LITERAL
 *     
 */
int
globus_rsl_assist_replace_manager_name(globus_rsl_t * rsl);

#endif


