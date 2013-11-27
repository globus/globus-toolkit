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

#ifndef GLOBUS_I_RSL_PARSER_H
#define GLOBUS_I_RSL_PARSER_H

#include "globus_common.h"

/* the scanner matches left and right-parens by
 * introducing a new counter at the beginning of each
 * variable reference expression.  this allows it to
 * detect the terminating right-paren of the variable reference
 * and check whether the enjambed implicit-concatenation
 * syntax is being used.  it then restores the previous
 * paren counter and keeps going (to recognize the end
 * of any enclosing variable reference expression).
 */
typedef struct paren_count_stack_elem_s
{
  int count;
}
paren_count_stack_elem_t;

typedef struct
globus_parse_state_s
{
    char                               *myinput;
    char                               *myinputptr;
    char                               *myinputlim;
    globus_rsl_t                       *rsl_spec;
    globus_rsl_parse_error_t           *error_structure;
    int                                 globus_parse_error_flag;
    int                                 calling_state;
    char                                quote_delimiter;
    globus_fifo_t                      *quote_text_fifo;
/* manipulate this list as stack...
 * introduced as a list rather than an abstract-data-type
 * so we can simply init it here as the constant NULL. */
    globus_list_t                      *paren_count_stack;
} globus_parse_state_t;

extern
int
globus_i_rsl_yyinput(globus_parse_state_t *parse_state, char *buf, yy_size_t *num_read, int max_size);

#endif /* GLOBUS_I_RSL_PARSER_H */
