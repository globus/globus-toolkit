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

#ifndef _GLOBUS_INCLUDE_GLOBUS_RSL_H
#define _GLOBUS_INCLUDE_GLOBUS_RSL_H

#include "globus_list.h"
#include "globus_symboltable.h"
#include "globus_hashtable.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

#define GLOBUS_RSL_BOOLEAN  1
#define GLOBUS_RSL_RELATION 2

#define GLOBUS_RSL_EQ             1 
#define GLOBUS_RSL_NEQ            2 
#define GLOBUS_RSL_GT             3 
#define GLOBUS_RSL_GTEQ           4 
#define GLOBUS_RSL_LT             5 
#define GLOBUS_RSL_LTEQ           6 
#define GLOBUS_RSL_AND            8
#define GLOBUS_RSL_OR             9
#define GLOBUS_RSL_MULTIREQ      10

#define GLOBUS_RSL_VALUE_LITERAL       1
#define GLOBUS_RSL_VALUE_SEQUENCE      2
#define GLOBUS_RSL_VALUE_VARIABLE      3
#define GLOBUS_RSL_VALUE_CONCATENATION 4

#define GLOBUS_RSL_PARAM_SINGLE_LITERAL 1
#define GLOBUS_RSL_PARAM_MULTI_LITERAL  2
#define GLOBUS_RSL_PARAM_SEQUENCE       3

/**********************************************************************
 *
 *  Module activation structure
 *
 **********************************************************************
*/
extern globus_module_descriptor_t       globus_i_rsl_module;

#define GLOBUS_RSL_MODULE (&globus_i_rsl_module)

/***********************************************************************/


typedef struct _globus_rsl_value_t globus_rsl_value_t;

struct _globus_rsl_value_t
{
  int type;

  union
  {
    struct
    {
      char * string;
    } literal;

    struct
    {
      globus_list_t * value_list;
    } sequence;

    struct
    {
      globus_rsl_value_t * sequence;
    } variable;

    struct
    {
      globus_rsl_value_t * left_value;
      globus_rsl_value_t * right_value;
    } concatenation;

  } value;
};

typedef struct _globus_rsl_t globus_rsl_t;

struct _globus_rsl_t
{
  int type; /* GLOBUS_RSL_BOOLEAN || GLOBUS_RSL_RELATION */
  union
  {
    struct
    {
      /* bison reserves "operator" hence my_operator */
      int my_operator;
      /* each element of the list has type globus_rsl_t *... 
       */
      globus_list_t *operand_list;
    } boolean;

    struct
    {
      int my_operator;
      char * attribute_name;
      globus_rsl_value_t * value_sequence;
    } relation;
  } req;
};

/*************************************************************************
 *                   is functions
 *
 ************************************************************************/

int 
globus_rsl_is_relation (globus_rsl_t *ast);

int
globus_rsl_is_boolean (globus_rsl_t *ast);

int 
globus_rsl_is_relation_eq (globus_rsl_t *ast);

/* return true only for relations w/ the specific operator */
int 
globus_rsl_is_relation_lessthan (globus_rsl_t *ast);

/* return true if relation attribute is equal to attribute arg */
int
globus_rsl_is_relation_attribute_equal (globus_rsl_t *ast, char * attribute);

/* return true only for booleans w/ the specific operator */
int
globus_rsl_is_boolean_and (globus_rsl_t *ast);

/* return true only for booleans w/ the specific operator */
int
globus_rsl_is_boolean_or (globus_rsl_t *ast);

int
globus_rsl_is_boolean_multi (globus_rsl_t *ast);

int
globus_rsl_value_is_literal (globus_rsl_value_t *ast);

int
globus_rsl_value_is_sequence (globus_rsl_value_t *ast);

int
globus_rsl_value_is_variable (globus_rsl_value_t *ast);

int
globus_rsl_value_is_concatenation (globus_rsl_value_t *ast);


/*************************************************************************
 *                   constructor functions
 *
 ************************************************************************/

globus_rsl_t *
globus_rsl_make_boolean (int my_operator,
                       globus_list_t *children);

globus_rsl_t *
globus_rsl_make_relation (int my_operator,
                        char *attributename,
                        globus_rsl_value_t *value_sequence);

globus_rsl_value_t *
globus_rsl_value_make_literal (char *string);

globus_rsl_value_t *
globus_rsl_value_make_sequence (globus_list_t * value_list);

globus_rsl_value_t *
globus_rsl_value_make_variable (globus_rsl_value_t * sequence);

globus_rsl_value_t *
globus_rsl_value_make_concatenation (globus_rsl_value_t *left_value,
                                   globus_rsl_value_t *right_value);

/* copy the entire rsl tree */
globus_rsl_t *
globus_rsl_copy_recursive(globus_rsl_t * globus_rsl_ptr);

/* copy the entire rsl value list */
globus_rsl_value_t *
globus_rsl_value_copy_recursive(globus_rsl_value_t * globus_rsl_value_ptr);

/*************************************************************************
 *                   accessor functions
 *
 ************************************************************************/

/*                   booleans                   */

/*     return non-zero on error    */

int
globus_rsl_boolean_get_operator (globus_rsl_t *ast_node);

/*
 *
 */
globus_list_t *
globus_rsl_boolean_get_operand_list (globus_rsl_t *ast_node);

globus_list_t **
globus_rsl_boolean_get_operand_list_ref (globus_rsl_t *boolean_node);


/*                   relations                   */

char *
globus_rsl_relation_get_attribute (globus_rsl_t *ast_node);

int
globus_rsl_relation_get_operator (globus_rsl_t *ast_node);

globus_rsl_value_t *
globus_rsl_relation_get_value_sequence (globus_rsl_t *ast_node);

/* NULL unless the relation has a simple 1-element value sequence */
globus_rsl_value_t *
globus_rsl_relation_get_single_value (globus_rsl_t *ast_node);

/*                   value lists                   */

/* extract the literal node's string
 * NULL if not called on a node tagged as a literal
 */
char *
globus_rsl_value_literal_get_string (globus_rsl_value_t *literal_node);

/* extract the list of nodes under the sequence node
 * NULL if not called on a node tagges as a sequence
 */
globus_list_t *
globus_rsl_value_sequence_get_value_list (globus_rsl_value_t *sequence_node);

/*
 *
 */
globus_rsl_value_t *
globus_rsl_value_variable_get_sequence (globus_rsl_value_t * variable_node);

/* extract the name of the referenced variable
 * NULL if not called on a node tagged as a variable
 */
char *
globus_rsl_value_variable_get_name (globus_rsl_value_t *variable_node);

/* extract the optional value for the variable reference
 * NULL if no optional value specified
 * NULL if not called on a node tagged as a variable
 */
char *
globus_rsl_value_variable_get_default (globus_rsl_value_t *variable_node);

/* extract the left-hand value of a concatenation
 * NULL if not called on a node tagged as a variable
 */
globus_rsl_value_t *
globus_rsl_value_concatenation_get_left (globus_rsl_value_t *concatenation_node);

/* extract the right-hand value of a concatenation
 * NULL if not called on a node tagged as a variable
 */
globus_rsl_value_t *
globus_rsl_value_concatenation_get_right (globus_rsl_value_t *concatenation_node);

globus_list_t **
globus_rsl_value_sequence_get_list_ref (globus_rsl_value_t *sequence_node);


/*************************************************************************
 *                   set functions
 *
 ************************************************************************/

/* set the left-hand value of a concatenation to a new value
 * return non-zero on error */
int
globus_rsl_value_concatenation_set_left (globus_rsl_value_t *concatenate_node,
                                         globus_rsl_value_t *new_left_node);

/* set the right-hand value of a concatenation to a new value
 * return non-zero on error */
int
globus_rsl_value_concatenation_set_right (globus_rsl_value_t *concatenate_node,
                                          globus_rsl_value_t *new_right_node);

/*************************************************************************
 *                   eval functions
 *
 ************************************************************************/

int
globus_rsl_value_eval(globus_rsl_value_t * ast_node,
                      globus_symboltable_t * symbol_table,
                      char ** string_value,
                      int rsl_substitute_flag);

int
globus_rsl_eval (globus_rsl_t *ast_node,
                 globus_symboltable_t * symbol_table);

/*************************************************************************
 *                   free functions
 *
 ************************************************************************/


/*** all freeing is done through globus_free() ***/

/* free any storage allocated by the globus_rsl*_make_*() routine
 * for this type of node
 */
int
globus_rsl_value_free (globus_rsl_value_t *val);

int
globus_rsl_free (globus_rsl_t *ast_node);

/* like globus_rsl*_free () but recursively free subtrees too.
 * Assumes: 1.) no nodes in the tree are shared,
 *          2.) everything was allocated with globus_malloc
 */
int
globus_rsl_value_free_recursive (globus_rsl_value_t * globus_rsl_value_ptr);

int
globus_rsl_free_recursive (globus_rsl_t *ast_node);

int
globus_rsl_value_print_recursive (globus_rsl_value_t * globus_rsl_value_ptr);

int
globus_rsl_print_recursive (globus_rsl_t *ast_node);

#define GLOBUS_SPECIFICATION_PARSE_ERROR_MESSAGE_LENGTH 1024
typedef struct globus_parse_error_s
{
    int         code;
    int         line;
    int         position;
    char        message[GLOBUS_SPECIFICATION_PARSE_ERROR_MESSAGE_LENGTH];
} globus_rsl_parse_error_t;

/******************************************************************************
                              Function prototypes
******************************************************************************/

/* extract the name of the referenced variable
 * NULL if not called on a node tagged as a variable
 */
int
globus_rsl_value_variable_get_size (globus_rsl_value_t *variable_node);

globus_list_t *
globus_list_copy_reverse (globus_list_t * orig);

int
globus_rsl_value_list_literal_replace(globus_list_t * value_list,
                                     char * string_value);

globus_list_t *
globus_rsl_operand_list_copy_recursive(globus_list_t * orig);

globus_list_t *
globus_rsl_value_sequence_list_copy_recursive(globus_list_t * orig);

int
globus_rsl_value_list_param_get(globus_list_t * ast_node_list,
                     int required_type,
                     char *** value,
                     int * value_ctr);

int
globus_rsl_param_get(globus_rsl_t * ast_node,
                     int required_type,
                     char * param,
                     char *** values);

globus_list_t *
globus_rsl_param_get_values(globus_rsl_t * ast_node,
			    char * param);

globus_rsl_t *
globus_rsl_parse(char * rsl_spec);

char *
globus_rsl_unparse (globus_rsl_t *rsl_spec);

char *
globus_rsl_value_unparse (globus_rsl_value_t * rsl_value);

EXTERN_C_END

#endif /* _GLOBUS_INCLUDE_GLOBUS_RSL_H */
