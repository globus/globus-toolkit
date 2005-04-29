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


/**********************************************************************
             Helpers Static Functions         
 **********************************************************************/

static
oldgaa_error_code
evaluate_condition(oldgaa_sec_context_ptr sc, 
                   oldgaa_conditions_ptr  condition,
                   oldgaa_options_ptr     options);

static
char *
get_day();

static
char *
get_hr_24();

static
char *
get_hr_12();

static
char *
get_minutes();

static
char *
get_seconds();

static
char *
get_am_pm();

static
int
day_to_val(char *str);

static
int
check_day(char *str1, char *str2, char *day);

static
char*
get_value(int *jj, const char *cond, const char delimiter);


#endif /* _OLDGAA_POLICY_EVALUATOR_H */
