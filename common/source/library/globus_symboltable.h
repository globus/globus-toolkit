
#ifndef GLOBUS_COMMON_SYMBOLTABLE_H
#define GLOBUS_COMMON_SYMBOLTABLE_H

/********************************************************************
 *
 * This file defines the globus_symboltable_t type, 
 * a lightweight chaining symboltable
 *
 *
 ********************************************************************/

#include "globus_list.h"
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

typedef struct symt {
  globus_list_t * scopes;
  globus_hashtable_hash_func_t  volatile hash_func;
  globus_hashtable_keyeq_func_t volatile keyeq_func;
} globus_symboltable_t;


extern int 
globus_symboltable_init (globus_symboltable_t          * table,
			 globus_hashtable_hash_func_t    hash_func,
			 globus_hashtable_keyeq_func_t   keyeq_func);


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
