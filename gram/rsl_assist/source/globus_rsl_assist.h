/*
 * Copyright 1999-2006 University of Chicago
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
 *     rsl - Pointer to the RSL structure in which you want to
 *           replace the manager Name by its Contact.
 *
 *     NOTE: The RSL MUST have been created using globus_rsl_parse, because
 *     the rsl might be reallocated by this function !! (required when
 *     the rsl is only a simple relation equal : resourceManagerName=x
 *
 * Returns:
 *     Pointer to the new RSL (Might be equal to the original one) or
 *     GLOBUS_NULL in case of failure
 *     
 */
globus_rsl_t *
globus_rsl_assist_replace_manager_name(globus_rsl_t * rsl);


/*
 * Function: globus_rsl_assist_string_canonicalize()
 *
 * Canonizing a string in this implementation means to remove any
 * underscores and moving all characters to lowercase.
 *
 * For example, the string contents "Max_Time" will be altered to be "maxtime".
 *
 * Returns: void
 */
void
globus_rsl_assist_string_canonicalize(char * ptr);


/*
 * Function: globus_rsl_assist_attributes_canonicalize()
 *
 * Given an RSL tree (parsed RSL), walk the tree finding all attributes of
 * RSL relations (i.e. (var=value) pairs) and canonicalize them by calling the
 * ..._string_canonicalize function.
 *
 * Returns:
 *     GLOBUS_SUCCESS or GLOBUS_FAILURE.  If GLOBUS_SUCCESS is returned then
 * any and all attributes contained in the passed in RSL tree will have been
 * canonicalized.
 */
int
globus_rsl_assist_attributes_canonicalize(globus_rsl_t * rsl);


#endif


