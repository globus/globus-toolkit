
/********************************************************************
 *
 * This file implements the hashtable_t type, a lightweight chaining hashtable
 *
 ********************************************************************/

#include "config.h"
#include "globus_common.h"
#include <assert.h>
#include "globus_hashtable.h"
#include "globus_list.h"

typedef struct hashtentry {
  void *key;
  void *datum;
} globus_hashtable_entry_t;

typedef struct hashtsearchargs {
  globus_hashtable_t *table;
  void *key;
} globus_hashtable_search_args_t;


static
int globus_hashtable_s_chain_pred (void *datum, void *vargs)
{
  globus_hashtable_entry_t *element;
  globus_hashtable_search_args_t *args;
  int status;

  element = (globus_hashtable_entry_t *)datum;
  args = (globus_hashtable_search_args_t *)vargs;

  status = (*(args->table->keyeq_func)) (element->key, args->key);

  return status;
}

void *globus_hashtable_lookup (globus_hashtable_t *table, void *key)
{
  int chainno;
  globus_list_t *found_link;
  globus_hashtable_search_args_t search_args;

  assert (table!=GLOBUS_NULL);
  chainno = (*(table->hash_func)) (key, table->size);
  search_args.table = table;
  search_args.key = key;

  found_link = globus_list_search_pred ((table->chains)[chainno],
					globus_hashtable_s_chain_pred,
					(void *) &search_args);
  if (found_link==GLOBUS_NULL) return GLOBUS_NULL;
  else {
    /* return datum */
    void *datum;
    datum = (((globus_hashtable_entry_t *) 
	      globus_list_first (found_link))
	     ->datum);

    return datum;
  }
}

int globus_hashtable_insert (globus_hashtable_t *table, void *key, void *datum)
{
  assert (table!=GLOBUS_NULL);

  if ( globus_hashtable_lookup (table, key) ) {
    /* this key already in table! */
    return -1;
  }
  else {
    int chainno;
    globus_hashtable_entry_t *new_entry;

    chainno = (*(table->hash_func)) (key, table->size);
    new_entry = globus_malloc (sizeof(globus_hashtable_entry_t));
    if (new_entry==GLOBUS_NULL) return -2;
    new_entry->key = key;
    new_entry->datum = datum;
    return globus_list_insert ((globus_list_t **) &((table->chains)[chainno]),
			       (void *) new_entry);
  }
}

void *globus_hashtable_remove (globus_hashtable_t *table, void *key)
{
  int chainno;
  globus_list_t *found_link;
  globus_hashtable_search_args_t search_args;

  assert (table!=GLOBUS_NULL);
  chainno = (*(table->hash_func)) (key, table->size);
  search_args.table = table;
  search_args.key = key;
  found_link = globus_list_search_pred ((table->chains)[chainno],
					globus_hashtable_s_chain_pred,
					(void *) &search_args);
  if (found_link == GLOBUS_NULL) return GLOBUS_NULL;
  else {
    /* remove entry */
    globus_hashtable_entry_t *entry;
    entry = ((globus_hashtable_entry_t *) 
	     globus_list_remove (((globus_list_t **)
				  &((table->chains)[chainno])),
				 found_link));
    if (entry!=GLOBUS_NULL) {
      void *datum;
      datum = entry->datum;
      globus_free (entry);
      return datum;
    }
    else {
      return GLOBUS_NULL;
    }
  }
}

int globus_hashtable_init (globus_hashtable_t *table, int size,
		globus_hashtable_hash_func_t hash_func,
		globus_hashtable_keyeq_func_t keyeq_func)
{
  int i;

  assert (table!=GLOBUS_NULL);
  assert (size > 0);
  table->size = size;
  table->chains = globus_malloc (sizeof(globus_list_t*)*size);
  if (table->chains == GLOBUS_NULL) return -1; 
  for (i=0; i<size; i++) {
    table->chains[i] = GLOBUS_NULL;
  }
  table->hash_func = hash_func;
  table->keyeq_func = keyeq_func;
  return 0;
}

int globus_hashtable_destroy (globus_hashtable_t *table)
{
  int i;

  assert (table!=GLOBUS_NULL);

  for (i=0; i<table->size; i++) {
    if (! globus_list_empty ( ((globus_list_t *)
			       table->chains[i]) )) {
      globus_list_free ( ((globus_list_t *)
			       table->chains[i]) );
      table->chains[i] = GLOBUS_NULL;
    }
  }

  table->size = 0;
  if (table->chains) globus_free ((globus_list_t *) table->chains);

  return 0;
}

int globus_hashtable_string_hash (void *string, int limit)
{
  int accum = 0;
  char *chars;
  int i = 0;

  chars = (char *)string;
  while (chars[i]!='\0') {
    /* bitwise xor of char and barrel-shifted accumulator */
    accum = chars[i] 
            ^ (accum << sizeof(char) * 8)
            ^ (accum >> ((sizeof(int) - sizeof(char)) * 8));
    i++;
  }

  return accum % limit;
}

int globus_hashtable_string_keyeq (void *string1, void *string2)
{
  if ( string1 == string2 ) return 1;
  else if ( (string1 == GLOBUS_NULL) || (string2 == GLOBUS_NULL) ) return 0;
  else if ( (((char *) string1)[0] == '\0') 
	    && (((char *) string2)[0] == '\0') ) return 1;
  else if ( ((char *) string1)[0] 
	    == ((char *) string2)[0] ) 
    return globus_hashtable_string_keyeq (((char *) string1) + 1, 
					  ((char *) string2) + 1);
  else return 0;
}

int globus_hashtable_voidp_hash (void *voidp, int limit)
{
  /* swap left and right halves portably */
  return (int) (((((unsigned long) voidp) << (sizeof(unsigned long)*4))
		 ^ (((unsigned long) voidp) >> (sizeof(unsigned long)*4))) 
		% limit);
}

int globus_hashtable_voidp_keyeq (void *voidp1, void *voidp2)
{
  return voidp1==voidp2;
}

int globus_hashtable_int_hash (void *integer, int limit)
{
  return ((int) (long) integer) % limit;
}

int globus_hashtable_int_keyeq (void *integer1, void *integer2)
{
  return ((int) (long) integer1) == ((int) (long) integer2);
}

int globus_hashtable_ulong_hash (void *integer, int limit)
{
  return (int) (((unsigned long) integer) % limit);
}

int globus_hashtable_ulong_keyeq (void *integer1, void *integer2)
{
  return ((unsigned long) integer1) == ((unsigned long) integer2);
}



