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

#include "globus_common.h"
#include <stdio.h>
#include "globus_rsl.h"
#include <strings.h>
#include "version.h"

static int
globus_i_rsl_value_unparse_to_fifo (globus_rsl_value_t * ast,
                                    globus_fifo_t      * bufferp);

static int
globus_i_rsl_unparse_to_fifo (globus_rsl_t  * ast,
                            globus_fifo_t * bufferp);

static int
globus_i_rsl_unparse_operator_to_fifo (int             operator,
                                       globus_fifo_t * bufferp);

static int
globus_i_rsl_unparse_string_literal_to_fifo (const char    * string,
                                             globus_fifo_t * bufferp);


/***************************************************************************
 *
 *
 *                        Module activation structure
 *
 *
 ****************************************************************************
 */
static int
globus_l_rsl_activate(void);

static int
globus_l_rsl_deactivate(void);

globus_module_descriptor_t              globus_i_rsl_module =
{
    "globus_rsl",
    globus_l_rsl_activate,
    globus_l_rsl_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


/***************************************************************************
 *
 *                 globus_rsl module activation functions
 *
 ****************************************************************************
 */

static int
globus_l_rsl_activate(void)
{
    if( globus_module_activate(GLOBUS_COMMON_MODULE) != GLOBUS_SUCCESS )
    {
	return GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;
}

static int
globus_l_rsl_deactivate(void)
{
    int  rc = GLOBUS_SUCCESS;

    if( globus_module_deactivate(GLOBUS_COMMON_MODULE) != GLOBUS_SUCCESS )
    {
	rc = GLOBUS_FAILURE;
    }

    return rc;
}



/*************************************************************************
 *                   is functions
 *
 ************************************************************************/

int 
globus_rsl_is_relation (globus_rsl_t *ast)
{
    if (ast==NULL) return(0);

    if (ast->type == GLOBUS_RSL_RELATION)
       return(1);
    else
       return(0);
}

int
globus_rsl_is_boolean (globus_rsl_t *ast)
{
    if (ast==NULL) return(0);

    if (ast->type == GLOBUS_RSL_BOOLEAN)
       return(1);
    else
       return(0);
}

int 
globus_rsl_is_relation_eq (globus_rsl_t *ast)
{
    if (! globus_rsl_is_relation(ast)) return(0);

    if (ast->req.relation.my_operator == GLOBUS_RSL_EQ)
       return(1);
    else
       return(0);
}

/* return true only for relations w/ the specific operator */
int 
globus_rsl_is_relation_lessthan (globus_rsl_t *ast)
{
    if (! globus_rsl_is_relation(ast)) return(0);

    if (ast->req.relation.my_operator == GLOBUS_RSL_LT)
       return(1);
    else
       return(0);
}

/* comparison is case insensitive */
int 
globus_rsl_is_relation_attribute_equal (globus_rsl_t *ast, char * attribute)
{
    if (! globus_rsl_is_relation(ast)) return(0);

    if (strcasecmp(globus_rsl_relation_get_attribute(ast), attribute) == 0)
       return(1);
    else
       return(0);
}

/* return true only for booleans w/ the specific operator */
int
globus_rsl_is_boolean_and (globus_rsl_t *ast)
{
    if (! globus_rsl_is_boolean(ast)) return(0);

    if (ast->req.boolean.my_operator == GLOBUS_RSL_AND)
       return(1);
    else
       return(0);
}

/* return true only for booleans w/ the specific operator */
int
globus_rsl_is_boolean_or (globus_rsl_t *ast)
{
    if (! globus_rsl_is_boolean(ast)) return(0);

    if (ast->req.boolean.my_operator == GLOBUS_RSL_OR)
       return(1);
    else
       return(0);
}

int
globus_rsl_is_boolean_multi (globus_rsl_t *ast)
{
    if (! globus_rsl_is_boolean(ast)) return(0);

    if (ast->req.boolean.my_operator == GLOBUS_RSL_MULTIREQ)
       return(1);
    else
       return(0);
}

int
globus_rsl_value_is_literal (globus_rsl_value_t *ast)
{
    if (ast==NULL) return(0);

    if (ast->type == GLOBUS_RSL_VALUE_LITERAL)
       return(1);
    else
       return(0);
}

int
globus_rsl_value_is_sequence (globus_rsl_value_t *ast)
{
    if (ast==NULL) return(0);

    if (ast->type == GLOBUS_RSL_VALUE_SEQUENCE)
       return(1);
    else
       return(0);
}

int
globus_rsl_value_is_variable (globus_rsl_value_t *ast)
{
    if (ast==NULL) return(0);

    if (ast->type == GLOBUS_RSL_VALUE_VARIABLE)
       return(1);
    else
       return(0);
}

int
globus_rsl_value_is_concatenation (globus_rsl_value_t *ast)
{
    if (ast==NULL) return(0);

    if (ast->type == GLOBUS_RSL_VALUE_CONCATENATION)
       return(1);
    else
       return(0);
}

/*************************************************************************
 *                   constructor functions
 *
 ************************************************************************/

globus_rsl_t *
globus_rsl_make_boolean (int operator,
                       globus_list_t *children)
{
    globus_rsl_t * tmp_rsl;

    tmp_rsl = (globus_rsl_t *) globus_malloc (sizeof(globus_rsl_t));
    if (tmp_rsl != NULL)
    {
        tmp_rsl->type = GLOBUS_RSL_BOOLEAN;
        tmp_rsl->req.boolean.my_operator = operator;
        tmp_rsl->req.boolean.operand_list = children;
    }

    return(tmp_rsl);
}

globus_rsl_t *
globus_rsl_make_relation (int operator,
                        char *attributename,
                        globus_rsl_value_t *value_sequence)
{
    globus_rsl_t * tmp_rsl;

    tmp_rsl = (globus_rsl_t *) globus_malloc (sizeof(globus_rsl_t));
    if (tmp_rsl != NULL)
    {
        tmp_rsl->type = GLOBUS_RSL_RELATION;
        tmp_rsl->req.relation.my_operator = operator;
        tmp_rsl->req.relation.value_sequence = value_sequence;
        tmp_rsl->req.relation.attribute_name = attributename;
    }

    return(tmp_rsl);
}

globus_rsl_value_t *
globus_rsl_value_make_literal (char *string)
{
    globus_rsl_value_t * tmp_rsl_value;

    tmp_rsl_value = (globus_rsl_value_t *) 
                     globus_malloc (sizeof(globus_rsl_value_t));
    if (tmp_rsl_value != NULL)
    {
        tmp_rsl_value->type = GLOBUS_RSL_VALUE_LITERAL;
        tmp_rsl_value->value.literal.string = string;
    }

    return(tmp_rsl_value);
}

globus_rsl_value_t *
globus_rsl_value_make_sequence (globus_list_t * value_list)
{
    globus_rsl_value_t * tmp_rsl_value;

    tmp_rsl_value = (globus_rsl_value_t *) 
                     globus_malloc (sizeof(globus_rsl_value_t));
    if (tmp_rsl_value != NULL)
    {
        tmp_rsl_value->type = GLOBUS_RSL_VALUE_SEQUENCE;
        tmp_rsl_value->value.sequence.value_list = value_list;
    }

    return(tmp_rsl_value);
}

globus_rsl_value_t *
globus_rsl_value_make_variable (globus_rsl_value_t * sequence)
{
    globus_rsl_value_t * tmp_rsl_value;

    tmp_rsl_value = (globus_rsl_value_t *) 
                     globus_malloc (sizeof(globus_rsl_value_t));
    if (tmp_rsl_value != NULL)
    {
        tmp_rsl_value->type = GLOBUS_RSL_VALUE_VARIABLE;
        tmp_rsl_value->value.variable.sequence = sequence;
    }

    return(tmp_rsl_value);
}

globus_rsl_value_t *
globus_rsl_value_make_concatenation (globus_rsl_value_t *left_value,
                                   globus_rsl_value_t *right_value)
{
    globus_rsl_value_t * tmp_rsl_value;

    tmp_rsl_value = (globus_rsl_value_t *) globus_malloc 
                    (sizeof(globus_rsl_value_t));
    if (tmp_rsl_value != NULL)
    {
        tmp_rsl_value->type = GLOBUS_RSL_VALUE_CONCATENATION;
        tmp_rsl_value->value.concatenation.left_value = left_value;
        tmp_rsl_value->value.concatenation.right_value = right_value;
    }

    return(tmp_rsl_value);
}


globus_rsl_t *
globus_rsl_copy_recursive(globus_rsl_t * ast_node)
{
    globus_rsl_t *       tmp_rsl_ptr;
    globus_rsl_t *       new_rsl_ptr;
    globus_list_t *      tmp_rsl_list;
    globus_list_t *      new_rsl_list;
    globus_rsl_value_t * tmp_rsl_value_ptr;
    globus_rsl_value_t * new_rsl_value_ptr;
    globus_list_t *      tmp_value_list;
    globus_list_t *      new_value_list;
    char *               tmp_string;

    if (ast_node==NULL) return(NULL);

    switch (ast_node->type)
    {
        case GLOBUS_RSL_BOOLEAN:
            
            tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);

            new_rsl_list = NULL;

            while (! globus_list_empty(tmp_rsl_list))
            {
                tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                     (tmp_rsl_list);

                new_rsl_ptr = globus_rsl_copy_recursive(tmp_rsl_ptr);

                globus_list_insert(&new_rsl_list, (void *) new_rsl_ptr);

                tmp_rsl_list = globus_list_rest(tmp_rsl_list);
            }

            new_rsl_list = globus_list_copy_reverse(new_rsl_list);

            return(globus_rsl_make_boolean
                       (globus_rsl_boolean_get_operator(ast_node),
                       new_rsl_list));

        case GLOBUS_RSL_RELATION:

            tmp_value_list = globus_rsl_value_sequence_get_value_list(
                             globus_rsl_relation_get_value_sequence(ast_node));

            new_value_list = NULL;

            while (! globus_list_empty(tmp_value_list))
            {
                tmp_rsl_value_ptr = (globus_rsl_value_t *) globus_list_first
                     (tmp_value_list);

                new_rsl_value_ptr = globus_rsl_value_copy_recursive
                                        (tmp_rsl_value_ptr);
                globus_list_insert(&new_value_list, (void *) new_rsl_value_ptr);

                tmp_value_list = globus_list_rest(tmp_value_list);
            }

            new_value_list = globus_list_copy_reverse(new_value_list);

            tmp_string = (char *) globus_malloc
                 (strlen(globus_rsl_relation_get_attribute(ast_node)) + 1);
            strcpy(tmp_string, 
                 globus_rsl_relation_get_attribute(ast_node));

            return(globus_rsl_make_relation
                       (globus_rsl_relation_get_operator(ast_node),
                       tmp_string,
                       globus_rsl_value_make_sequence(new_value_list)));

        default:
            return(NULL);
    }
}

globus_rsl_value_t *
globus_rsl_value_copy_recursive(globus_rsl_value_t * globus_rsl_value_ptr)
{
    globus_rsl_value_t * tmp_rsl_value_ptr;
    globus_rsl_value_t * new_rsl_value_ptr;
    globus_rsl_value_t * new_rsl_value_seq;
    globus_rsl_value_t * new_rsl_value_left;
    globus_rsl_value_t * new_rsl_value_right;
    globus_list_t *      tmp_value_list;
    globus_list_t *      new_value_list;
    char *               tmp_string;
    char *               literal_ptr;

    if (globus_rsl_value_ptr==NULL) return(NULL);

    switch (globus_rsl_value_ptr->type)
    {
        case GLOBUS_RSL_VALUE_LITERAL:

            literal_ptr = 
                globus_rsl_value_literal_get_string(globus_rsl_value_ptr);

            if (literal_ptr == NULL)
            {
                globus_rsl_value_make_literal(NULL);
            }
            else
            {
                tmp_string = (char *) globus_malloc 
                       (strlen(literal_ptr) + 1);
                strcpy(tmp_string, literal_ptr);

                return(globus_rsl_value_make_literal(tmp_string));
            }

            break;

        case GLOBUS_RSL_VALUE_SEQUENCE:

            tmp_value_list =
                globus_rsl_value_sequence_get_value_list(globus_rsl_value_ptr);
 
            new_value_list = NULL;

            while (! globus_list_empty(tmp_value_list))
            {
                tmp_rsl_value_ptr = (globus_rsl_value_t *) globus_list_first
                     (tmp_value_list);

                new_rsl_value_ptr = globus_rsl_value_copy_recursive
                                        (tmp_rsl_value_ptr);

                globus_list_insert(&new_value_list, (void *) new_rsl_value_ptr);

                tmp_value_list = globus_list_rest(tmp_value_list);
            }

            new_value_list = globus_list_copy_reverse(new_value_list);
            
            return(globus_rsl_value_make_sequence(new_value_list));

        case GLOBUS_RSL_VALUE_VARIABLE:

            new_rsl_value_seq = globus_rsl_value_copy_recursive(
                (globus_rsl_value_variable_get_sequence
                     (globus_rsl_value_ptr)));

            return(globus_rsl_value_make_variable(new_rsl_value_seq));

        case GLOBUS_RSL_VALUE_CONCATENATION:
            new_rsl_value_left = globus_rsl_value_copy_recursive
                   (globus_rsl_value_concatenation_get_left
                        (globus_rsl_value_ptr));

            new_rsl_value_right = globus_rsl_value_copy_recursive
                   (globus_rsl_value_concatenation_get_right
                        (globus_rsl_value_ptr));

            return(globus_rsl_value_make_concatenation
                   (new_rsl_value_left,
                    new_rsl_value_right));

        default:
            return(NULL);
    }
    return(NULL);
}


/*************************************************************************
 *                   accessor functions
 *
 ************************************************************************/

/*                   booleans                   */

/*     return non-zero on error    */

int
globus_rsl_boolean_get_operator (globus_rsl_t *ast_node)
{
    if (ast_node==NULL) return(-1);
    if (! globus_rsl_is_boolean(ast_node)) return(-1);

    return(ast_node->req.boolean.my_operator);
}

/*
 *
 */
globus_list_t *
globus_rsl_boolean_get_operand_list (globus_rsl_t *ast_node)
{
    if (ast_node==NULL) return(NULL);
    if (! globus_rsl_is_boolean(ast_node)) return(NULL);

    return(ast_node->req.boolean.operand_list);
}

globus_list_t **
globus_rsl_boolean_get_operand_list_ref (globus_rsl_t *boolean_node)
{
  if (boolean_node==NULL) return NULL;
  if (! globus_rsl_is_boolean(boolean_node)) return NULL;

  return &(boolean_node->req.boolean.operand_list);
}


/*                   relations                   */

char *
globus_rsl_relation_get_attribute (globus_rsl_t *ast_node)
{
    if (ast_node==NULL) return NULL;
    if (! globus_rsl_is_relation(ast_node)) return NULL;

    return(ast_node->req.relation.attribute_name);
}

int
globus_rsl_relation_get_operator (globus_rsl_t *ast_node)
{
    if (ast_node==NULL) return(-1);
    if (! globus_rsl_is_relation(ast_node)) return(-1);

    return(ast_node->req.relation.my_operator);
}

globus_rsl_value_t *
globus_rsl_relation_get_value_sequence (globus_rsl_t *ast_node)
{
    if (ast_node==NULL) return(NULL);
    if (! globus_rsl_is_relation(ast_node)) return(NULL);

    return(ast_node->req.relation.value_sequence);
}


/* NULL unless the relation has a simple 1-element value sequence */
globus_rsl_value_t *
globus_rsl_relation_get_single_value (globus_rsl_t *ast_node)
{
    if ( ast_node == NULL ) return NULL;
    if ( ! globus_rsl_is_relation (ast_node) ) return NULL;

    if ( globus_list_size (
                 globus_rsl_value_sequence_get_value_list (
                           globus_rsl_relation_get_value_sequence (ast_node)))
       == 1)
    {
        return ((globus_rsl_value_t *)
            globus_list_first (
               globus_rsl_value_sequence_get_value_list (
                           globus_rsl_relation_get_value_sequence (ast_node))));
    }
    else
    {
        return NULL;
    }
}

/*                   value lists                   */

/* extract the literal node's string
 * NULL if not called on a node tagged as a literal
 */
char *
globus_rsl_value_literal_get_string (globus_rsl_value_t *literal_node)
{
    if ( literal_node == NULL ) return NULL;
    if ( ! globus_rsl_value_is_literal (literal_node) ) return NULL;

    return(literal_node->value.literal.string);
}

/* extract the list of nodes under the sequence node
 * NULL if not called on a node tagges as a sequence
 */
globus_list_t *
globus_rsl_value_sequence_get_value_list (globus_rsl_value_t *sequence_node)
{
    if ( sequence_node == NULL ) return NULL;
    if ( ! globus_rsl_value_is_sequence (sequence_node) ) return NULL;

    return(sequence_node->value.sequence.value_list);
}

/*
 *
 */
globus_rsl_value_t *
globus_rsl_value_variable_get_sequence (globus_rsl_value_t * variable_node)
{
    if ( variable_node == NULL ) return(NULL);
    if ( ! globus_rsl_value_is_variable (variable_node) ) return(NULL);

    return(variable_node->value.variable.sequence);
}

/* extract the name of the referenced variable
 * NULL if not called on a node tagged as a variable
 */
char *
globus_rsl_value_variable_get_name (globus_rsl_value_t *variable_node)
{
    globus_rsl_value_t * x;
    char * y;

    if ( variable_node == NULL ) return(NULL);
    if ( ! globus_rsl_value_is_variable (variable_node) ) return(NULL);

    x = (globus_rsl_value_t *) globus_list_first (
            globus_rsl_value_sequence_get_value_list (
               globus_rsl_value_variable_get_sequence(variable_node)));

    y = globus_rsl_value_literal_get_string(x);

    return (y);
}


/* extract the optional value for the variable reference
 * NULL if no optional value specified
 * NULL if not called on a node tagged as a variable
 */
char *
globus_rsl_value_variable_get_default (globus_rsl_value_t *variable_node)
{
    if (variable_node==NULL) return NULL;
    if ( ! globus_rsl_value_is_variable (variable_node) ) return(NULL);
    
    if ( globus_rsl_value_variable_get_size(variable_node) > 1 )
    {
        return  (
          globus_rsl_value_literal_get_string( (globus_rsl_value_t *)
            globus_list_first (globus_list_rest (
              globus_rsl_value_sequence_get_value_list (
                globus_rsl_value_variable_get_sequence(variable_node))))));
    }
    else
    {
        return NULL;
    }
}

/* extract the name of the referenced variable
 * NULL if not called on a node tagged as a variable
 */
int
globus_rsl_value_variable_get_size (globus_rsl_value_t *variable_node)
{
    if ( variable_node == NULL ) return(-1);
    if ( ! globus_rsl_value_is_variable (variable_node) ) return(-1);

    return( globus_list_size (
            globus_rsl_value_sequence_get_value_list (
               globus_rsl_value_variable_get_sequence(variable_node))));
}

/* extract the left-hand value of a concatenation
 * NULL if not called on a node tagged as a variable
 */
globus_rsl_value_t *
globus_rsl_value_concatenation_get_left (globus_rsl_value_t *concatenation_node)
{
    if (concatenation_node==NULL) return NULL;
    if ( ! globus_rsl_value_is_concatenation (concatenation_node) ) return(NULL);

    return(concatenation_node->value.concatenation.left_value);
}

/* extract the right-hand value of a concatenation
 * NULL if not called on a node tagged as a variable
 */
globus_rsl_value_t *
globus_rsl_value_concatenation_get_right (globus_rsl_value_t *concatenation_node)
{
    if (concatenation_node==NULL) return NULL;
    if (! globus_rsl_value_is_concatenation (concatenation_node)) return(NULL);

    return(concatenation_node->value.concatenation.right_value);
}

globus_list_t **
globus_rsl_value_sequence_get_list_ref (globus_rsl_value_t *sequence_node)
{
  if (sequence_node==NULL) return NULL;
  if (! globus_rsl_value_is_sequence (sequence_node)) return NULL;

  return &(sequence_node->value.sequence.value_list);
}


/*************************************************************************
 *                   set functions
 *
 ************************************************************************/

/* set the left-hand value of a concatenation to a new value
 * return non-zero on error */
int
globus_rsl_value_concatenation_set_left (globus_rsl_value_t *concatenation_node,
                                       globus_rsl_value_t *new_left_node)
{
    if (concatenation_node==NULL) return(-1);
    if (new_left_node==NULL) return(-1);
    if (! globus_rsl_value_is_concatenation (concatenation_node)) return(-1);

    concatenation_node->value.concatenation.left_value = new_left_node;

    return(0);
}

/* set the right-hand value of a concatenation to a new value
 * return non-zero on error */
int
globus_rsl_value_concatenation_set_right (globus_rsl_value_t *concatenation_node,
                                        globus_rsl_value_t *new_right_node)
{
    if (concatenation_node==NULL) return(-1);
    if (new_right_node==NULL) return(-1);
    if (! globus_rsl_value_is_concatenation (concatenation_node)) return(-1);

    concatenation_node->value.concatenation.right_value = new_right_node;

    return(0);
}

/*******************
 *    list function
 *******************/
globus_list_t *
globus_list_copy_reverse (globus_list_t * orig)
{
  globus_list_t *new_list = NULL;

  while ( orig != NULL ) {
    globus_list_insert ( &new_list,
                         globus_list_first (orig) );
    orig = globus_list_rest (orig);
  }

  return new_list;
}


/*************************************************************************
 *                   free functions
 *
 ************************************************************************/


/*** all freeing is done through globus_free() ***/

/* free any storage allocated by the globus_rsl*_make_*() routine
 * for this type of node
 */
int
globus_rsl_value_free (globus_rsl_value_t *val)
{
    globus_free(val);
    return(0);
}

int
globus_rsl_free (globus_rsl_t *ast_node)
{
    globus_free(ast_node);
    return(0);
}

/* like globus_rsl*_free () but recursively free subtrees too.
 * Assumes: 1.) no nodes in the tree are shared,
 *          2.) everything was allocated with globus_malloc
 */
int
globus_rsl_value_free_recursive (globus_rsl_value_t * globus_rsl_value_ptr)
{
    globus_rsl_value_t * tmp_rsl_value_ptr;
    globus_list_t * tmp_rsl_list;

    if (globus_rsl_value_ptr==NULL) return(0);

    switch (globus_rsl_value_ptr->type)
    {
        case GLOBUS_RSL_VALUE_LITERAL:

            globus_free(globus_rsl_value_literal_get_string
                           (globus_rsl_value_ptr));
            break;

        case GLOBUS_RSL_VALUE_SEQUENCE:

            tmp_rsl_list = globus_rsl_value_sequence_get_value_list
                                 (globus_rsl_value_ptr);

            while (! globus_list_empty(tmp_rsl_list))
            {
                tmp_rsl_value_ptr = (globus_rsl_value_t *)
		    globus_list_remove(&tmp_rsl_list, tmp_rsl_list);
                globus_rsl_value_free_recursive(tmp_rsl_value_ptr);
            }

            break;

        case GLOBUS_RSL_VALUE_VARIABLE:

            globus_rsl_value_free_recursive
                 (globus_rsl_value_variable_get_sequence(globus_rsl_value_ptr));
            break;

        case GLOBUS_RSL_VALUE_CONCATENATION:

            globus_rsl_value_free_recursive
               (globus_rsl_value_concatenation_get_left(globus_rsl_value_ptr));
            globus_rsl_value_free_recursive
               (globus_rsl_value_concatenation_get_right(globus_rsl_value_ptr));
            break;

        default:

            break;
    }

    globus_free(globus_rsl_value_ptr);
    return(0);
}

int
globus_rsl_free_recursive (globus_rsl_t *ast_node)
{
    globus_list_t * tmp_rsl_list;
    globus_rsl_t * tmp_rsl_ptr;

    switch (ast_node->type)
    {
        case GLOBUS_RSL_BOOLEAN:

            tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);

            while (! globus_list_empty(tmp_rsl_list))
            {
                tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                     (tmp_rsl_list);

                globus_rsl_free_recursive(tmp_rsl_ptr);

                tmp_rsl_list = globus_list_rest(tmp_rsl_list);
            }

            globus_list_free
                 (globus_rsl_boolean_get_operand_list(ast_node));

            break;

        case GLOBUS_RSL_RELATION:

            globus_rsl_value_free_recursive
                (globus_rsl_relation_get_value_sequence(ast_node));

            globus_free(globus_rsl_relation_get_attribute(ast_node));

            break;

        default:

            return(1);
    }

    globus_free(ast_node);
    return(0);
}

int
globus_rsl_value_list_literal_replace(globus_list_t * value_list,
                                     char * string_value)
{
    globus_rsl_value_t * rsl_value_ptr;

    rsl_value_ptr = globus_rsl_value_make_literal (string_value);
    if (rsl_value_ptr == NULL)
       return(1);

    globus_rsl_value_free(
        (globus_rsl_value_t *) globus_list_replace_first(value_list,
                                                (void *) rsl_value_ptr));
    return(GLOBUS_SUCCESS);
}

int
globus_rsl_value_eval(globus_rsl_value_t * ast_node,
                      globus_symboltable_t * symbol_table, 
                      char ** string_value,
                      int rsl_substitution_flag)
{
    char * symbol_name;
    char * symbol_value;
    char * copy_symbol_value;
    char * tmp_string_value;
    globus_list_t * tmp_rsl_value_list;
    globus_rsl_value_t * tmp_rsl_value_ptr;

    if ( globus_rsl_value_is_literal (ast_node) )
    {
         *string_value = globus_rsl_value_literal_get_string(ast_node);
         return GLOBUS_SUCCESS;
    }
    else if ( globus_rsl_value_is_sequence (ast_node) )
    {
        tmp_rsl_value_list = 
             globus_rsl_value_sequence_get_value_list(ast_node);

        if (rsl_substitution_flag)
        {
            /* in this case the each sequence should only have 2 elements.
             * call globus_rsl_value_eval on each element and replace each
             * with a literal node.
             */

            if (globus_list_size(tmp_rsl_value_list) != 2)
            {
               return(1);
            }

            /*
             * take the first value in the list as the symbol name and 
             * the second as the symbol value.
             */
            if (globus_rsl_value_eval(
                (globus_rsl_value_t *) globus_list_first(tmp_rsl_value_list),
                     symbol_table,
                     &symbol_name,
                     rsl_substitution_flag) != 0)
            {
                 return(1);
            }

            /* globus_list_replace_first returns the replaced 
             * rsl_value_ptr, so in this case we want to free it up.
             */
            globus_rsl_value_free(
                (globus_rsl_value_t *) globus_list_replace_first
                     (tmp_rsl_value_list,
                     (void *) globus_rsl_value_make_literal(symbol_name)));

            tmp_rsl_value_list = globus_list_rest(tmp_rsl_value_list);

            if (globus_rsl_value_eval(
                (globus_rsl_value_t *) globus_list_first(tmp_rsl_value_list),
                     symbol_table,
                     &symbol_value,
                     rsl_substitution_flag) != 0)
            {
                 return(1);
            }

            /* globus_list_replace_first returns the replaced 
             * rsl_value_ptr, so in this case we want to free it up.
             */
            globus_rsl_value_free(
                (globus_rsl_value_t *) globus_list_replace_first
                     (tmp_rsl_value_list,
                     (void *) globus_rsl_value_make_literal(symbol_value)));

            if (!symbol_name || !symbol_value)
            {
                return(1);
            }
            else
            {
                /* 
                printf("inserting symbol = %s, value = %s\n",
                        symbol_name, symbol_value);
                */

                copy_symbol_value = (char *) globus_malloc (sizeof(char *) *
                                             (strlen(symbol_value) + 1));
                strcpy(copy_symbol_value, symbol_value);

                globus_symboltable_insert(symbol_table,
                                  (void *) symbol_name,
                                  (void *) copy_symbol_value);
            }
        }
        else
        {
            while (! globus_list_empty(tmp_rsl_value_list))
            {
                tmp_rsl_value_ptr = (globus_rsl_value_t *) globus_list_first
                     (tmp_rsl_value_list);

                if (globus_rsl_value_eval(tmp_rsl_value_ptr,
                                symbol_table,
                                &tmp_string_value,
                                rsl_substitution_flag) == GLOBUS_SUCCESS)
                {
                    if (!globus_rsl_value_is_sequence(tmp_rsl_value_ptr))
                    {
                        /* globus_list_replace_first returns the replaced 
                         * rsl_value_ptr, so in this case we want to free it up.
                         */
                        globus_rsl_value_free(
                            (globus_rsl_value_t *) globus_list_replace_first
                               (tmp_rsl_value_list,
                               (void *) globus_rsl_value_make_literal
                                    (tmp_string_value)));
                    }
                    
                }
                else
                {
                   /* error evaluating rsl value */
                   return(1);
                }

                tmp_rsl_value_list = globus_list_rest(tmp_rsl_value_list);
            }

        }

        *string_value = NULL;
        return GLOBUS_SUCCESS;
    
    }
    else if ( globus_rsl_value_is_variable (ast_node) )
    {

        if (globus_rsl_value_variable_get_size(ast_node) != 1) 
        {
            return(1);
        }

        symbol_name = globus_rsl_value_variable_get_name(ast_node);

        if (symbol_name == NULL)
        {
            /* unable to get var name from variable ast node */
            return(1);
        }

        if ((*string_value = globus_symboltable_lookup(symbol_table,
                 (void *) symbol_name)
            )
            == NULL)
        {
            /* lookup failed for %s, symbol_name */
            return (1); /*  not-bound-error */
        }
        else
        {
            return(GLOBUS_SUCCESS);
        }
    }
    else if ( globus_rsl_value_is_concatenation (ast_node) )
    {
         char * left;
         char * right;

         if ( (globus_rsl_value_eval ( 
                   globus_rsl_value_concatenation_get_left (ast_node),
                   symbol_table,
                   &left,
                   rsl_substitution_flag) 
              == GLOBUS_SUCCESS)  &&
              (globus_rsl_value_eval ( 
                   globus_rsl_value_concatenation_get_right (ast_node),
                   symbol_table,
                   &right,
                   rsl_substitution_flag) 
              == GLOBUS_SUCCESS) )
         {
             if ( (left == NULL) || (right == NULL) )
             {
                 return(1);
             }

             *string_value = (char *) globus_malloc 
                                                (strlen(left) +
                                                 strlen(right) + 1);
             strcpy(*string_value, left);
             strcat(*string_value, right);

             globus_rsl_value_free_recursive(
                globus_rsl_value_concatenation_get_left(ast_node));
             globus_rsl_value_free_recursive(
                globus_rsl_value_concatenation_get_right(ast_node));
             ast_node->value.concatenation.left_value = NULL;
             ast_node->value.concatenation.right_value = NULL;

             return GLOBUS_SUCCESS;
         }
         else return(1); /* concatenate-error; */
    }
    else return(1); /* spec-too-complex-error; */
}

int
globus_rsl_eval (globus_rsl_t *ast_node, 
                 globus_symboltable_t * symbol_table)
{
    globus_rsl_t * tmp_rsl_ptr;
    globus_list_t * tmp_rsl_list;
    globus_list_t * tmp_value_list;
    globus_rsl_value_t * tmp_rsl_value_ptr;
    char * string_value;
    int rsl_substitution_flag = 0;

    if (globus_rsl_is_boolean(ast_node))
    {
        globus_symboltable_create_scope(symbol_table);

        tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);

        while (! globus_list_empty(tmp_rsl_list))
        {
            tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                 (tmp_rsl_list);

            if (globus_rsl_eval(tmp_rsl_ptr, symbol_table) != GLOBUS_SUCCESS)
            {
                return(1);
            }

            tmp_rsl_list = globus_list_rest(tmp_rsl_list);
        }

        globus_symboltable_remove_scope(symbol_table);

    }
    else if (globus_rsl_is_relation(ast_node))
    {
        tmp_value_list = globus_rsl_value_sequence_get_value_list(
                         globus_rsl_relation_get_value_sequence(ast_node));

        rsl_substitution_flag = globus_rsl_is_relation_attribute_equal(
                                   ast_node,
                                   "rsl_substitution");
        rsl_substitution_flag |= globus_rsl_is_relation_attribute_equal(
                                   ast_node,
                                   "rslsubstitution");

        while (! globus_list_empty(tmp_value_list))
        {
            tmp_rsl_value_ptr = (globus_rsl_value_t *) globus_list_first
                 (tmp_value_list);

            if (rsl_substitution_flag && 
                !globus_rsl_value_is_sequence(tmp_rsl_value_ptr) )
            {
               return(1);
            }

            if (globus_rsl_value_eval(tmp_rsl_value_ptr,
                            symbol_table,
                            &string_value,
                            rsl_substitution_flag) == GLOBUS_SUCCESS)
            {
                if (string_value != NULL)
                {
                    /* globus_list_replace_first returns the replaced 
                     * rsl_value_ptr, so in this case we want to free it up.
                     */
                    globus_rsl_value_free(
                        (globus_rsl_value_t *) globus_list_replace_first
                             (tmp_value_list,
                             (void *) globus_rsl_value_make_literal
                                  (globus_libc_strdup(string_value))));
                }
            }
            else
            {
               return(1);
            }

            tmp_value_list = globus_list_rest(tmp_value_list);
        }

    }
    else
    {
        return(1);
    }
    return(0);
}

int
globus_rsl_value_list_param_get(globus_list_t * ast_node_list,
                                int required_type,
                                char *** value,
                                int * value_ctr)
{
    globus_rsl_value_t * tmp_rsl_value_ptr;
    globus_list_t * tmp_value_list;
    char * tmp_value;

    while (! globus_list_empty(ast_node_list))
    {
        tmp_rsl_value_ptr = (globus_rsl_value_t *) globus_list_first
             (ast_node_list);

        if (globus_rsl_value_is_literal(tmp_rsl_value_ptr) &&
            required_type == GLOBUS_RSL_VALUE_LITERAL)
        {
            tmp_value = globus_rsl_value_literal_get_string(tmp_rsl_value_ptr);
            (*value)[*value_ctr] = tmp_value;
            *value_ctr = *value_ctr + 1;
        }
        else if (globus_rsl_value_is_sequence(tmp_rsl_value_ptr) &&
                 required_type == GLOBUS_RSL_VALUE_SEQUENCE)
        {
            tmp_value_list = globus_rsl_value_sequence_get_value_list
                                (tmp_rsl_value_ptr);

            if (globus_list_size(tmp_value_list) != 2)
            {
                return(1);
            }

            if (globus_rsl_value_list_param_get(tmp_value_list,
                                                GLOBUS_RSL_VALUE_LITERAL,
                                                value,
                                                value_ctr) != 0)
            {
                return(1);
            }
        }
        else
        {
            /* if we are after a parameter the best thing to do with an
             * ast node other than a sequence or a literal is to ignore it.
             */
            return(1);
        }

        ast_node_list = globus_list_rest(ast_node_list);
    }
    return(0);
}

globus_list_t *
globus_rsl_param_get_values(
    globus_rsl_t *			ast_node,
    char *				param)
{
    globus_rsl_t * tmp_rsl_ptr;
    globus_list_t * tmp_rsl_list;
    globus_list_t * tmp_value_list;
    globus_list_t * values;

    if (globus_rsl_is_boolean(ast_node))
    {
        tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);

        while (! globus_list_empty(tmp_rsl_list))
        {
            tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                 (tmp_rsl_list);

	    values = globus_rsl_param_get_values(tmp_rsl_ptr, param);

	    if(values)
	    {
		return values;
	    }

            tmp_rsl_list = globus_list_rest(tmp_rsl_list);
        }
    }
    else if (globus_rsl_is_relation(ast_node))
    {
        if (!globus_rsl_is_relation_attribute_equal(ast_node, param))
        {
            return(0);
        }

        return globus_rsl_value_sequence_get_value_list(
                         globus_rsl_relation_get_value_sequence(ast_node));

    }
    else
    {
        return GLOBUS_NULL;
    }

    return GLOBUS_NULL;
}
/* globus_rsl_param_get_values() */

int
globus_rsl_param_get(globus_rsl_t * ast_node,
                     int param_type,
                     char * param,
                     char *** values)
{
    globus_rsl_t * tmp_rsl_ptr;
    globus_list_t * tmp_rsl_list;
    globus_list_t * tmp_value_list;
    int value_ctr = 0;
    int required_type;

    if (globus_rsl_is_boolean(ast_node))
    {
        tmp_rsl_list = globus_rsl_boolean_get_operand_list(ast_node);

        *values = (char **)globus_malloc(sizeof(char *));
        (*values)[0] = NULL;
 
        while (! globus_list_empty(tmp_rsl_list))
        {
            tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                 (tmp_rsl_list);

            if (globus_rsl_param_get(tmp_rsl_ptr,
                                     param_type,
                                     param,
                                     values) != 0)
            {
                return(1);
            }

            if ((*values)[0])
            {
                return(0);
            }

            tmp_rsl_list = globus_list_rest(tmp_rsl_list);
        }
    }
    else if (globus_rsl_is_relation(ast_node))
    {
        if (!globus_rsl_is_relation_attribute_equal(ast_node, param))
        {
            return(0);
        }

        tmp_value_list = globus_rsl_value_sequence_get_value_list(
                         globus_rsl_relation_get_value_sequence(ast_node));

        switch (param_type)
        {
            case GLOBUS_RSL_PARAM_SINGLE_LITERAL:
                /* only 1 literal value.
                 * this is the catch all.
                 */
                if (globus_list_size(tmp_value_list) != 1)
                    return(1);
                required_type = GLOBUS_RSL_VALUE_LITERAL;
                break;
            case GLOBUS_RSL_PARAM_MULTI_LITERAL:
                /* only literal value(s)
                 * for example a list of arguments
                 */
                required_type = GLOBUS_RSL_VALUE_LITERAL;
                break;
            case GLOBUS_RSL_PARAM_SEQUENCE:
                /* only sequence(s).  The list of each sequence must be
                 * made up of 2 literals only!
                 * for example var/value pairs for environment and 
                 * rsl_substitution. 
                 */
                required_type = GLOBUS_RSL_VALUE_SEQUENCE;
                break;
            default:
                return(1);
        }
        
        *values = (char **)globus_malloc(sizeof(char *) *
                                         (globus_list_size (tmp_value_list) *
                                         2 + 1));

        if (globus_rsl_value_list_param_get(tmp_value_list,
                                            required_type,
                                            values,
                                            &value_ctr) != 0)
        {
            return(1);
        }

        (*values)[value_ctr] = NULL;

        return(0);
    }
    else
    {
        return(1);
    }

    return(0);
}

int lvl = 0;

/* for printing RSL tree */
#define INDENT(LVL) { \
    int i; \
    for (i = 0; i < (LVL); i ++) printf("  "); \
    }

int
globus_rsl_value_print_recursive (globus_rsl_value_t * globus_rsl_value_ptr)
{
    globus_rsl_value_t * tmp_rsl_value_ptr;
    globus_list_t * tmp_rsl_list;

    if (globus_rsl_value_ptr==NULL) return(0);

    lvl++;

    switch (globus_rsl_value_ptr->type)
    {
        case GLOBUS_RSL_VALUE_LITERAL:

            if (globus_rsl_value_ptr->value.literal.string == NULL)
            {
                INDENT(lvl) printf("LITERAL string = >NULL<\n");
            }
            else
            {
                INDENT(lvl) printf("LITERAL string = %s\n", 
                    globus_rsl_value_ptr->value.literal.string);
            }
            break;

        case GLOBUS_RSL_VALUE_SEQUENCE:

            INDENT(lvl) printf("SEQUENCE\n");

            tmp_rsl_list = globus_rsl_value_ptr->value.sequence.value_list;

            while (! globus_list_empty(tmp_rsl_list))
            {
                tmp_rsl_value_ptr = (globus_rsl_value_t *) globus_list_first
                     (tmp_rsl_list);
                globus_rsl_value_print_recursive(tmp_rsl_value_ptr);

                tmp_rsl_list = globus_list_rest(tmp_rsl_list);
            }

            break;

        case GLOBUS_RSL_VALUE_VARIABLE:

            INDENT(lvl) printf("VARIABLE\n");
            globus_rsl_value_print_recursive
                  (globus_rsl_value_ptr->value.variable.sequence);
            break;

        case GLOBUS_RSL_VALUE_CONCATENATION:

            INDENT(lvl) printf("CONCATENATION (left)\n");

            globus_rsl_value_print_recursive
                  (globus_rsl_value_ptr->value.concatenation.left_value);
            INDENT(lvl) printf("CONCATENATION (right)\n");
            globus_rsl_value_print_recursive
                  (globus_rsl_value_ptr->value.concatenation.right_value);
            break;

        default:

            break;
    }

    lvl--;

    return(0);
}

char * globus_rsl_get_operator(int my_op)
{
    switch (my_op)
    {
         case GLOBUS_RSL_EQ:        return ("=");
         case GLOBUS_RSL_NEQ:       return ("!=");
         case GLOBUS_RSL_GT:        return (">");
         case GLOBUS_RSL_GTEQ:      return (">=");
         case GLOBUS_RSL_LT:        return ("<");
         case GLOBUS_RSL_LTEQ:      return ("<=");
         case GLOBUS_RSL_AND:       return ("&");
         case GLOBUS_RSL_OR:        return ("|");
         case GLOBUS_RSL_MULTIREQ:  return ("+");
         default:                   return ("??");
    }
}

int
globus_rsl_print_recursive (globus_rsl_t *ast_node)
{
    globus_list_t * tmp_rsl_list;
    globus_rsl_t * tmp_rsl_ptr;

    if (globus_rsl_is_boolean(ast_node))
    {
        printf("\nBOOLEAN\n");
        printf("  operator = %s\n", 
                globus_rsl_get_operator(ast_node->req.boolean.my_operator));

        tmp_rsl_list = ast_node->req.boolean.operand_list;

        while (! globus_list_empty(tmp_rsl_list))
        {
            tmp_rsl_ptr = (globus_rsl_t *) globus_list_first
                 (tmp_rsl_list);
            globus_rsl_print_recursive(tmp_rsl_ptr);

            tmp_rsl_list = globus_list_rest(tmp_rsl_list);
        }
    }
    else
    {
        printf("\n  RELATION\n");
        printf("    attibute name = %s\n", 
            ast_node->req.relation.attribute_name);
        printf("    operator = %s\n", 
                globus_rsl_get_operator(ast_node->req.boolean.my_operator));

        lvl++;
        globus_rsl_value_print_recursive
                (ast_node->req.relation.value_sequence);
        lvl--;
    }
    return(0);
}

/*************************************************************************
 *  unparse
 *************************************************************************/

char *
globus_rsl_unparse (globus_rsl_t *rsl_spec)
{
  int             err;
  globus_fifo_t   buffer;
  int             size;
  char          * char_buffer;

  globus_fifo_init (&buffer);
  err = globus_i_rsl_unparse_to_fifo (rsl_spec, &buffer);

  if (err) {
    char_buffer = NULL;
    goto unparse_exit;
  }

  size = globus_fifo_size (&buffer);
  char_buffer = globus_malloc (sizeof(char) * (size + 1));

  if ( char_buffer != NULL ) {
    int i;

    for (i=0; (i<size) && (!globus_fifo_empty (&buffer)); i++) {
      char_buffer[i] = (char) (long) globus_fifo_dequeue (&buffer);
    }
    char_buffer[size] = '\0';
  }

unparse_exit:
  globus_fifo_destroy (&buffer);
  return char_buffer;
}

char *
globus_rsl_value_unparse (globus_rsl_value_t * rsl_value)
{
  int             err;
  globus_fifo_t   buffer;
  int             size;
  char          * char_buffer;

  globus_fifo_init (&buffer);

  err = globus_i_rsl_value_unparse_to_fifo (rsl_value, &buffer);

  if (err) {
    char_buffer = NULL;
    goto unparse_exit;
  }

  size = globus_fifo_size (&buffer);
  char_buffer = globus_malloc (sizeof(char) * (size + 1));

  if ( char_buffer != NULL ) {
    int i;

    for (i=0; (i<size) && (!globus_fifo_empty (&buffer)); i++) {
      char_buffer[i] = (char) (long) globus_fifo_dequeue (&buffer);
    }
    char_buffer[size] = '\0';
  }

unparse_exit:
  globus_fifo_destroy (&buffer);
  return char_buffer;
}

static int
globus_i_rsl_unparse_string_literal_to_fifo (const char    * string,
                                             globus_fifo_t * bufferp)
{
  int    i;

  if ( string == NULL ) return 1;

  globus_fifo_enqueue (bufferp, (void *) '"');

  for (i=0; string[i] != '\0'; i++) {
    if ( string[i] == '"' ) {
      /* escape '"' characters */
      globus_fifo_enqueue (bufferp, (void *) '"');
      globus_fifo_enqueue (bufferp, (void *) '"');
    }
    else {
      globus_fifo_enqueue (bufferp, (void *) string[i]);
    }
  }

  globus_fifo_enqueue (bufferp, (void *) '"');

  return 0;
}

static int
globus_i_rsl_unparse_operator_to_fifo (int             operator,
                                       globus_fifo_t * bufferp)
{
  switch ( operator ) {
  case GLOBUS_RSL_EQ:
    globus_fifo_enqueue (bufferp, (void *) '=');
    break;

  case GLOBUS_RSL_NEQ:
    globus_fifo_enqueue (bufferp, (void *) '!');
    globus_fifo_enqueue (bufferp, (void *) '=');
    break;

  case GLOBUS_RSL_GT:
    globus_fifo_enqueue (bufferp, (void *) '>');
    break;

  case GLOBUS_RSL_GTEQ:
    globus_fifo_enqueue (bufferp, (void *) '>');
    globus_fifo_enqueue (bufferp, (void *) '=');
    break;

  case GLOBUS_RSL_LT:
    globus_fifo_enqueue (bufferp, (void *) '<');
    break;

  case GLOBUS_RSL_LTEQ:
    globus_fifo_enqueue (bufferp, (void *) '<');
    globus_fifo_enqueue (bufferp, (void *) '=');
    break;

  case GLOBUS_RSL_MULTIREQ:
    globus_fifo_enqueue (bufferp, (void *) '+');
    break;
    
  case GLOBUS_RSL_AND:
    globus_fifo_enqueue (bufferp, (void *) '&');
    break;

  case GLOBUS_RSL_OR:
    globus_fifo_enqueue (bufferp, (void *) '|');
    break;

  default:
    return 1;
  }

  return 0;
}

static int
globus_i_rsl_unparse_to_fifo (globus_rsl_t  * ast,
                            globus_fifo_t * bufferp)
{
  int err;

  if ( ast == NULL ) return 1;
  else if ( globus_rsl_is_relation (ast) ) {
    globus_list_t * values;

    err = globus_i_rsl_unparse_string_literal_to_fifo (
                               globus_rsl_relation_get_attribute (ast),
                               bufferp);
    if ( err ) return 1;

    globus_fifo_enqueue (bufferp, (void *) ' ');

    globus_i_rsl_unparse_operator_to_fifo (
                           globus_rsl_relation_get_operator (ast),
                           bufferp);

    globus_fifo_enqueue (bufferp, (void *) ' ');

    values = globus_rsl_value_sequence_get_value_list (
                               globus_rsl_relation_get_value_sequence (ast));
    while (! globus_list_empty (values)) {
      err = globus_i_rsl_value_unparse_to_fifo (((globus_rsl_value_t *)
                                                 globus_list_first (values)),
                                                bufferp);
      if (err) return 1;

      globus_fifo_enqueue (bufferp, (void *) ' ');

      values = globus_list_rest (values);
    }

    return 0;
  }
  else if ( globus_rsl_is_boolean (ast) ) {
    globus_list_t * operands;

    globus_i_rsl_unparse_operator_to_fifo (
                           globus_rsl_boolean_get_operator (ast),
                           bufferp);

    operands = globus_rsl_boolean_get_operand_list (ast);
    while (! globus_list_empty (operands)) {
      globus_fifo_enqueue (bufferp, (void *) '(');

      err = globus_i_rsl_unparse_to_fifo (((globus_rsl_t *)
                                           globus_list_first (operands)),
                                          bufferp);
      if (err) return 1;

      globus_fifo_enqueue (bufferp, (void *) ')');

      operands = globus_list_rest (operands);
    }

    return 0;
  }
  else return 1;
}

static int
globus_i_rsl_value_unparse_to_fifo (globus_rsl_value_t * ast,
                                    globus_fifo_t      * bufferp)
{
  int err;

  if ( ast == NULL ) return 1;
  else if ( globus_rsl_value_is_literal (ast) ) {
    globus_i_rsl_unparse_string_literal_to_fifo (
                                 globus_rsl_value_literal_get_string (ast),
                                 bufferp);
    return 0;
  }
  else if ( globus_rsl_value_is_sequence (ast) ) {
    globus_list_t * values;

    globus_fifo_enqueue (bufferp, (void *) '(');

    values = globus_rsl_value_sequence_get_value_list (ast);
    while (! globus_list_empty (values)) {
      err = globus_i_rsl_value_unparse_to_fifo (((globus_rsl_value_t *)
                                                 globus_list_first (values)),
                                                bufferp);
      if (err) return 1;

      globus_fifo_enqueue (bufferp, (void *) ' ');

      values = globus_list_rest (values);
    }

    globus_fifo_enqueue (bufferp, (void *) ')');

    return 0;
  }
  else if ( globus_rsl_value_is_variable (ast) ) {
    globus_fifo_enqueue (bufferp, (void *) '$');
    globus_fifo_enqueue (bufferp, (void *) '(');

    err = globus_i_rsl_unparse_string_literal_to_fifo (
                               globus_rsl_value_variable_get_name (ast),
                               bufferp);
    if (err) return 1;

    if ( globus_rsl_value_variable_get_default (ast) != NULL ) {
      globus_fifo_enqueue (bufferp, (void *) ' ');

      err = globus_i_rsl_unparse_string_literal_to_fifo (
                                 globus_rsl_value_variable_get_default (ast),
                                 bufferp);
      if (err) return 1;
    }

    globus_fifo_enqueue (bufferp, (void *) ')');
    return 0;
  }
  else if ( globus_rsl_value_is_concatenation (ast) ) {
    err = globus_i_rsl_value_unparse_to_fifo (
                              globus_rsl_value_concatenation_get_left (ast),
                              bufferp);
    if (err) return 1;

    globus_fifo_enqueue (bufferp, (void *) ' ');
    globus_fifo_enqueue (bufferp, (void *) '#');
    globus_fifo_enqueue (bufferp, (void *) ' ');

    err = globus_i_rsl_value_unparse_to_fifo (
                              globus_rsl_value_concatenation_get_right (ast),
                              bufferp);
    if (err) return 1;

    return 0;
  }
  else return 1;
}
