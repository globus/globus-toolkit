#include "globus_common.h"

int main(int argc, char **argv)
{
    globus_hashtable_t hash_table;

    globus_hashtable_init(&hash_table,
                          256,
                          globus_hashtable_int_hash,
                          globus_hashtable_int_keyeq);

    globus_hashtable_insert(&hash_table,
                            (void *) 123,
                            (void *) "xyz");
    globus_hashtable_insert(&hash_table,
                            (void *) 456,
                            (void *) "abc");
    globus_hashtable_insert(&hash_table,
                            (void *) 111,
                            (void *) "aaa");
    globus_hashtable_insert(&hash_table,
                            (void *) 222,
                            (void *) "bbb");

    printf("removed - %s\n",globus_hashtable_remove(&hash_table,
                                   (void *) 222));
    printf("removed - %s\n",globus_hashtable_remove(&hash_table,
                                   (void *) 456));

    return globus_hashtable_destroy(&hash_table);
}
