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
