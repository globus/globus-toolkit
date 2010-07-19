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

/**********************************************************************
 oldgaa_policy_evaluator.h:

Description:
	This header file used internally by the oldgaa routines
**********************************************************************/
#ifndef _OLDGAA_POLICY_EVALUATOR_H
#define _OLDGAA_POLICY_EVALUATOR_H

/**********************************************************************
                             Include header files
**********************************************************************/

#include <stdio.h> /* for FILE */

/**********************************************************************
                               Define constants
**********************************************************************/

void
oldgaa_handle_error(char               **errstring,
                 const char * const  message); 

oldgaa_policy_ptr    
oldgaa_find_matching_entry(uint32             *minor_status, 
                        oldgaa_principals_ptr  ptr, 
                        oldgaa_policy_ptr      policy);

oldgaa_error_code
oldgaa_check_access_rights(oldgaa_sec_context_ptr sc,
                        oldgaa_rights_ptr      requested_rights,
                        oldgaa_rights_ptr      rights,
                        oldgaa_answer_ptr      detailed_answer,
                        oldgaa_options_ptr     options);


oldgaa_error_code
oldgaa_get_authorized_principals(oldgaa_sec_attrb_ptr *attributes,
                              oldgaa_policy_ptr     policy,
                              oldgaa_principals_ptr principal,
                              oldgaa_rights_ptr     rights);

/**********************************************************************
             Condition Evaluation Functions         
 **********************************************************************/

oldgaa_error_code
oldgaa_evaluate_regex_cond(oldgaa_conditions_ptr condition, 
                        oldgaa_options_ptr    options);

oldgaa_error_code 
oldgaa_evaluate_conditions(oldgaa_sec_context_ptr    sc, 
                        oldgaa_cond_bindings_ptr  conditions,
                        oldgaa_options_ptr        options);

oldgaa_error_code
oldgaa_evaluate_day_cond(oldgaa_conditions_ptr condition, 
                      oldgaa_options_ptr    options);

oldgaa_error_code
oldgaa_evaluate_time_cond(oldgaa_conditions_ptr condition, 
                       oldgaa_options_ptr    options);

oldgaa_error_code
oldgaa_evaluate_sech_mech_cond(oldgaa_principals_ptr  principal,
                        oldgaa_conditions_ptr  condition, 
                        oldgaa_options_ptr     options);



#endif /* _OLDGAA_POLICY_EVALUATOR_H */
