
#ifndef GLOBUS_COMMON_HASHTABLE_H
#define GLOBUS_COMMON_HASHTABLE_H

/********************************************************************
 *
 * This file defines the globus_hashtable_t type, 
 * a lightweight chaining hashtable
 *
 *
 ********************************************************************/

#include "globus_list.h"

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

typedef int (*globus_hashtable_hash_func_t) (void *key, int limit);

typedef int (*globus_hashtable_keyeq_func_t) (void *key1, void *key2);

typedef struct hasht {
  volatile int size;
  globus_list_t * volatile * volatile chains;
  globus_hashtable_hash_func_t  volatile hash_func;
  globus_hashtable_keyeq_func_t volatile keyeq_func;
} globus_hashtable_t;


extern int 
globus_hashtable_init (globus_hashtable_t *table, int size,
		       globus_hashtable_hash_func_t hash_func,
		       globus_hashtable_keyeq_func_t keyeq_func);

extern void *
globus_hashtable_lookup (globus_hashtable_t *table, void *key);

extern int 
globus_hashtable_insert (globus_hashtable_t *table, void *key, void *datum);

extern void *
globus_hashtable_remove (globus_hashtable_t *table, void *key);

extern int 
globus_hashtable_destroy (globus_hashtable_t *table);

extern int 
globus_hashtable_string_hash (void *string, int limit);
extern int 
globus_hashtable_string_keyeq (void *string1, void *string2);

extern int 
globus_hashtable_voidp_hash (void *voidp, int limit);
extern int 
globus_hashtable_voidp_keyeq (void *voidp1, void *voidp2);

extern int 
globus_hashtable_int_hash (void *integer, int limit);
extern int 
globus_hashtable_int_keyeq (void *integer1, void *integer2);

extern int 
globus_hashtable_ulong_hash (void *integer, int limit);
extern int 
globus_hashtable_ulong_keyeq (void *integer1, void *integer2);

EXTERN_C_END

#endif /* GLOBUS_COMMON_HASHTABLE_H */
