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


/********************************************************************
 *
 * This file implements the symboltable_t type, 
 * a lightweight chaining symboltable
 *
 ********************************************************************/

#include "globus_symboltable.h"
#include "globus_list.h"
#include "globus_hashtable.h"
#include "globus_libc.h"

struct globus_symboltable_s
{
    globus_list_t * scopes;
    globus_hashtable_hash_func_t  volatile          hash_func;
    globus_hashtable_keyeq_func_t volatile          keyeq_func;
};


void *
globus_symboltable_lookup(
    globus_symboltable_t *                          table, 
	void *                                          symbol)
{
    globus_list_t *                                 scope_iter;
    struct globus_symboltable_s *                   s_table;

    assert (table!=GLOBUS_NULL);
    s_table = *table;

    scope_iter = s_table->scopes;

    while(!globus_list_empty(scope_iter)) 
    {
        void *                                      datum;

        if((datum = globus_hashtable_lookup(((globus_hashtable_t *)
					    globus_list_first (scope_iter)),
					   symbol))
	                != GLOBUS_NULL) 
        {
            return datum;
        }
        scope_iter = globus_list_rest (scope_iter);
    }

    return GLOBUS_NULL;
}

int 
globus_symboltable_insert(
    globus_symboltable_t *                      table, 
    void *                                      symbol, 
	void *                                      datum)
{
    struct globus_symboltable_s *               s_table;

    assert (table!=GLOBUS_NULL);
    s_table = *table;

    if(globus_list_empty (s_table->scopes))
    {
        return 1;
    }
    else
    {
        return globus_hashtable_insert (((globus_hashtable_t *)
				    globus_list_first (s_table->scopes)),
				    symbol,
				    datum);
    }
}

void *
globus_symboltable_remove(
    globus_symboltable_t *                      table, 
	void *                                      symbol)
{
    struct globus_symboltable_s *               s_table;

    assert (table!=GLOBUS_NULL);
    s_table = *table;

    if(globus_list_empty (s_table->scopes))
    {
        return GLOBUS_NULL;
    }
    else
    {
        return globus_hashtable_remove (((globus_hashtable_t *)
				        globus_list_first (s_table->scopes)),
				        symbol);
    }
}


int
globus_symboltable_create_scope(
    globus_symboltable_t *                      table)
{
    int                                         err;
    globus_hashtable_t *                        new_scope;
    struct globus_symboltable_s *               s_table;

    assert (table!=GLOBUS_NULL);
    s_table = *table;

    new_scope = globus_malloc (sizeof(globus_hashtable_t));
    assert (new_scope!=GLOBUS_NULL);

    err = globus_hashtable_init(new_scope, 16 /* reasonable default */,
			       s_table->hash_func, s_table->keyeq_func);
    assert(!err);

    err = globus_list_insert (&(s_table->scopes), 
			    (void *) new_scope);
    assert(!err);

    return 0;
}

int 
globus_symboltable_remove_scope(
    globus_symboltable_t *                      table)
{
    struct globus_symboltable_s *               s_table;

    assert (table!=GLOBUS_NULL);
    s_table = *table;

    if(globus_list_empty(s_table->scopes)) 
    {
        return 1;
    }
    else 
    {
        int                                     err;
        globus_hashtable_t *                    old_scope;

        old_scope = ((globus_hashtable_t *)
		    globus_list_first(s_table->scopes));

        globus_list_remove (&(s_table->scopes), s_table->scopes);

        err = globus_hashtable_destroy(old_scope);
        assert(!err);

        globus_libc_free(old_scope);

        return 0;
    }
}


int 
globus_symboltable_init(
    globus_symboltable_t *                              table,
    globus_hashtable_hash_func_t                        hash_func,
	globus_hashtable_keyeq_func_t                       keyeq_func)
{
    struct globus_symboltable_s *                       s_table;

    if (table==NULL) return 1;

    s_table = (struct globus_symboltable_s *)globus_malloc(sizeof(struct globus_symboltable_s));
    *table = s_table;

    s_table->scopes = NULL;
    s_table->hash_func = hash_func;
    s_table->keyeq_func = keyeq_func;

    return 0;
}

int 
globus_symboltable_destroy(
    globus_symboltable_t *                              table)
{
    struct globus_symboltable_s *                       s_table;

    assert (table!=GLOBUS_NULL);
    s_table = *table;

    while(!globus_list_empty(s_table->scopes)) 
    {
        int                                             err;
        globus_hashtable_t *                            old_scope;

        old_scope = ((globus_hashtable_t *)
		    globus_list_first (s_table->scopes));

        globus_list_remove (&(s_table->scopes), s_table->scopes);

        err = globus_hashtable_destroy (old_scope);
        assert (!err);
    }
    globus_free(s_table);

    return 0;
}
