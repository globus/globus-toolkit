
/**********************************************************************
 gaa_utils.h:

Description:
	This header file used internally by the gaa routines
**********************************************************************/
#ifndef _GAA_UTILS_H
#define _GAA_UTILS_H_
#define MAX_STRING_SIZE  1024
#define QUOTING	         '\"'
#define WHITESPACE       ' '
#define TAB              '\t'

/**********************************************************************
 *
 * Function Prototypes
 *
 **********************************************************************/

/**********************************************************************
  String Handling
 **********************************************************************/

int 
gaa_strings_match(const char *string1,
		  const char *string2);
char *
gaa_strcopy(const char *s, char *r);


/**********************************************************************
  Compare elements
 **********************************************************************/
int
gaa_compare_principals(gaa_principals_ptr element, gaa_principals_ptr new);

int
gaa_compare_rights(gaa_rights_ptr element, gaa_rights_ptr new);

int
gaa_compare_conditions(gaa_conditions_ptr element, gaa_conditions_ptr new);

int
gaa_compare_sec_attrbs(gaa_sec_attrb_ptr element, 
                       gaa_sec_attrb_ptr new);

/**********************************************************************
  Add new element to a list
 **********************************************************************/

gaa_principals_ptr
gaa_add_principal(gaa_policy_ptr *list, gaa_principals_ptr new);

gaa_rights_ptr
gaa_add_rights(gaa_rights_ptr *list, gaa_rights_ptr new);

gaa_cond_bindings_ptr
gaa_add_cond_binding(gaa_cond_bindings_ptr* list, gaa_cond_bindings_ptr new);

gaa_conditions_ptr
gaa_add_condition(gaa_conditions_ptr* list, gaa_conditions_ptr new);

gaa_sec_attrb_ptr
gaa_add_attribute(gaa_sec_attrb_ptr *list, gaa_sec_attrb_ptr new);

/**********************************************************************
  Bindings
 **********************************************************************/

int
gaa_bind_rights_to_principals(gaa_principals_ptr start, gaa_rights_ptr rights);

void
gaa_bind_rights_to_conditions(gaa_rights_ptr start, gaa_cond_bindings_ptr cond_bind);


/**********************************************************************
  Regex Handling Functions
 **********************************************************************/

int
gaa_check_reg_expr(char  *reg_expr, 
                  char **reg_expr_list);
int
gaa_regex_matches_string(const char * const  string,
                         const char * const  regex);

char **
gaa_parse_regex(char * str);

static
char *
gaa_to_regex(const char * const glob_regex);


#endif /* _GAA_UTILS_H_ */
