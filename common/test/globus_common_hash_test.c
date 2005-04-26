/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

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
