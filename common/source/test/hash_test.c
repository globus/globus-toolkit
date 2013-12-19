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

/** @file hash_test.c Hashtable Test Cases*/

#include "globus_common.h"
#include "globus_test_tap.h"

/** @brief Globus Hashtable Test Cases */
int hash_test(void)
{
    globus_hashtable_t hash_table;

    printf("1..8\n");
    /**
     * @test
     * Initialize hashtable with globus_hashtable_init()
     */
    ok(globus_hashtable_init(&hash_table,
                          256,
                          globus_hashtable_int_hash,
                          globus_hashtable_int_keyeq) == 0, "hashtable_init");

    /**
     * @test
     * Insert datum 123 into hashtable with globus_hashtable_insert()
     */
    ok(globus_hashtable_insert(&hash_table,
                            (void *) 123,
                            (void *) "xyz") == 0, "insert_123");
    /**
     * @test
     * Insert datum 456 into hashtable with globus_hashtable_insert()
     */
    ok(globus_hashtable_insert(&hash_table,
                            (void *) 456,
                            (void *) "abc") == 0, "insert_456");
    /**
     * @test
     * Insert datum 111 into hashtable with globus_hashtable_insert()
     */
    ok(globus_hashtable_insert(&hash_table,
                            (void *) 111,
                            (void *) "aaa") == 0, "insert_111");
    /**
     * @test
     * Insert datum 222 into hashtable with globus_hashtable_insert()
     */
    ok(globus_hashtable_insert(&hash_table,
                            (void *) 222,
                            (void *) "bbb") == 0, "insert_222");

    /**
     * @test
     * Remove datum 222 from hashtable with globus_hashtable_remove()
     */
    ok(strcmp(globus_hashtable_remove(&hash_table,
                                   (void *) 222), "bbb") == 0, "remove_222");
    /**
     * @test
     * Remove datum 456 from hashtable with globus_hashtable_remove()
     */
    ok(strcmp(globus_hashtable_remove(&hash_table,
                                   (void *) 456), "abc") == 0, "remove_456");

    /**
     * @test
     * Destroy hashtable with globus_hashtable_destroy()
     */
    ok(globus_hashtable_destroy(&hash_table) == 0, "hashtable_destroy");
    return TEST_EXIT_CODE;
}

int main(int argc, char **argv)
{
    return hash_test();
}
