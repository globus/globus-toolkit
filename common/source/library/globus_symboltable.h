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


#ifndef GLOBUS_COMMON_SYMBOLTABLE_H
#define GLOBUS_COMMON_SYMBOLTABLE_H

/********************************************************************
 *
 * This file defines the globus_symboltable_t type, 
 * a lightweight chaining symboltable
 *
 *
 ********************************************************************/
#include "globus_common_include.h"
#include "globus_list.h"
#include "globus_hashtable.h"

EXTERN_C_BEGIN

struct globus_symboltable_s;
typedef struct globus_symboltable_s *               globus_symboltable_t;

extern int 
globus_symboltable_init(
    globus_symboltable_t          *                 table,
	globus_hashtable_hash_func_t                    hash_func,
	globus_hashtable_keyeq_func_t                   keyeq_func);


extern void *
globus_symboltable_lookup (globus_symboltable_t *table, void *symbol);

extern int 
globus_symboltable_insert (globus_symboltable_t *table, 
			   void *symbol, 
			   void *datum);

extern void *
globus_symboltable_remove (globus_symboltable_t *table, void *symbol);


extern int
globus_symboltable_create_scope (globus_symboltable_t *table);

extern int
globus_symboltable_remove_scope (globus_symboltable_t *table);


extern int 
globus_symboltable_destroy (globus_symboltable_t *table);

EXTERN_C_END

#endif /* GLOBUS_COMMON_SYMBOLTABLE_H */


