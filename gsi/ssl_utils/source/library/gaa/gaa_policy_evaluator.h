/**********************************************************************
 gaa_policy_evaluator.h:

Description:
	This header file used internally by the gaa routines
**********************************************************************/
#ifndef _GAA_POLICY_EVALUATOR_H
#define _GAA_POLICY_EVALUATOR_H

/**********************************************************************
                             Include header files
**********************************************************************/

#include <stdio.h> /* for FILE */

/**********************************************************************
                               Define constants
**********************************************************************/

void
gaa_handle_error(char               **errstring,
                 const char * const  message); 

gaa_policy_ptr    
gaa_find_matching_entry(uint32             *minor_status, 
                        gaa_principals_ptr  ptr, 
                        gaa_policy_ptr      policy);

gaa_error_code
gaa_check_access_rights(gaa_sec_context_ptr sc,
                        gaa_rights_ptr      requested_rights,
                        gaa_rights_ptr      rights,
                        gaa_answer_ptr      detailed_answer,
                        gaa_options_ptr     options);


gaa_error_code
gaa_get_authorized_principals(gaa_sec_attrb_ptr *attributes,
                              gaa_policy_ptr     policy,
                              gaa_principals_ptr principal,
                              gaa_rights_ptr     rights);

/**********************************************************************
             Condition Evaluation Functions         
 **********************************************************************/

gaa_error_code
gaa_evaluate_regex_cond(gaa_conditions_ptr condition, 
                        gaa_options_ptr    options);

gaa_error_code 
gaa_evaluate_conditions(gaa_sec_context_ptr    sc, 
                        gaa_cond_bindings_ptr  conditions,
                        gaa_options_ptr        options);

gaa_error_code
gaa_evaluate_day_cond(gaa_conditions_ptr condition, 
                      gaa_options_ptr    options);

gaa_error_code
gaa_evaluate_time_cond(gaa_conditions_ptr condition, 
                       gaa_options_ptr    options);

gaa_error_code
gaa_evaluate_sech_mech_cond(gaa_principals_ptr  principal,
                        gaa_conditions_ptr  condition, 
                        gaa_options_ptr     options);


/**********************************************************************
             Helpers Static Functions         
 **********************************************************************/

static
gaa_error_code
evaluate_condition(gaa_sec_context_ptr sc, 
                   gaa_conditions_ptr  condition,
                   gaa_options_ptr     options);

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


#endif /* _GAA_POLICY_EVALUATOR_H */
