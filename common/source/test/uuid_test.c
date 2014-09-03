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

/**
 * @file uuid_test.c
 * @brief UUID Test
 */

#include "globus_common.h"
#include "globus_test_tap.h"

typedef int     (*test_func_t)(void);
typedef struct
{
    test_func_t     test_func;
    const char     *test_name;
}
test_case_t;
#define TEST_CASE(x) {x, #x}

#define SIZEOF_ARRAY(x) (sizeof(x)/sizeof(x[0]))

/**
 * @brief UUID values are unique
 */
int
uuid_is_unique_test(void)
{
    globus_uuid_t                       uuid[2];
    int                                 rc;
    /**
     * @test
     * Create a pair of uuids with globus_uuid_create() and verify that they
     * are different
     */
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error initializing %s\n",
                (GLOBUS_COMMON_MODULE)->module_name);

        goto out;
    }

    rc = globus_uuid_create(&uuid[0]);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error creating uuid: %d\n", rc);

        goto out;
    }
    rc = globus_uuid_create(&uuid[1]);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error creating uuid: %d\n", rc);

        goto deactivate_out;
    }

    if (strcmp(uuid[0].text, uuid[1].text) == 0)
    {
        fprintf(stderr, "UUIDs are the same.\n");

        rc = 1;

        goto deactivate_out;
    }

    if (GLOBUS_UUID_MATCH(uuid[0], uuid[1]))
    {
        fprintf(stderr, "UUIDs are the same.\n");

        rc = 1;

        goto deactivate_out;
    }

deactivate_out:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
out:
    return rc;
}
/* uuid_is_unique_test() */

/**
 * Import a UUID
 */
int
uuid_import_test(void)
{
    globus_uuid_t                       uuid[2];
    int                                 rc;
    /**
     * @test
     * Create a globus_uuid_t with globus_uuid_create(), import its text
     * representation into a new uuid with globus_uuid_import(), and
     * compare the two with GLOBUS_UUID_MATCH()
     */
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error initializing %s\n",
                (GLOBUS_COMMON_MODULE)->module_name);

        goto out;
    }

    rc = globus_uuid_create(&uuid[0]);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error creating uuid: %d\n", rc);

        goto deactivate_out;
    }

    rc = globus_uuid_import(&uuid[1], uuid[0].text);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error importing uuid: %d\n", rc);

        goto deactivate_out;
    }

    if (strcmp(uuid[0].text, uuid[1].text) != 0)
    {
        fprintf(stderr, "UUIDs are not the same.\n");

        rc = 1;

        goto deactivate_out;
    }

    if (!GLOBUS_UUID_MATCH(uuid[0], uuid[1]))
    {
        fprintf(stderr, "UUIDs are not the same.\n");

        rc = 1;

        goto deactivate_out;
    }

deactivate_out:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
out:
    return rc;
}
/* uuid_import_test() */

/**
 * Test globus_uuid_fields
 */
int
uuid_fields_test(void)
{
    globus_uuid_t                       uuid;
    int                                 rc;
    globus_uuid_fields_t                uuid_fields[2];
    /**
     * @test
     * Create a globus_uuid_t with globus_uuid_create(),
     * then get its fields twice and compare the two
     */
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error initializing %s\n",
                (GLOBUS_COMMON_MODULE)->module_name);

        goto out;
    }

    rc = globus_uuid_create(&uuid);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error creating uuid: %d\n", rc);

        goto deactivate_out;
    }

    rc = globus_uuid_fields(&uuid, &uuid_fields[0]);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error getting uuid fields: %d\n", rc);

        goto deactivate_out;
    }

    rc = globus_uuid_fields(&uuid, &uuid_fields[1]);

    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error getting uuid fields: %d\n", rc);

        goto deactivate_out;
    }

    if (memcmp(&uuid_fields[0], &uuid_fields[1], sizeof(globus_uuid_fields_t))
            != 0)
    {
        fprintf(stderr, "uuid fields don't match: %d\n", rc);


        goto deactivate_out;
    }

deactivate_out:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
out:
    return rc;
}
/* uuid_fields_test() */

/**
 * @brief Bad UUID Import Test
 */
int
uuid_bad_import_test(void)
{
    globus_uuid_t                       uuid;
    int                                 rc;
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    /**
     * @test Try to import a string which is not formatted as a UUID
     */
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error initializing %s\n",
                (GLOBUS_COMMON_MODULE)->module_name);

        goto out;
    }

    rc = globus_uuid_import(&uuid, "some-bogus-text");

    if (rc == GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Imported bogus uuid!\n");

        goto deactivate_out;
    }

    rc = 0;

deactivate_out:
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
out:
    return rc;
}

int
main()
{
    int                                 i;
    test_case_t                         test_cases[] =
    {
        TEST_CASE(uuid_is_unique_test),
        TEST_CASE(uuid_import_test),
        TEST_CASE(uuid_fields_test),

        TEST_CASE(uuid_bad_import_test)
    };
    printf("1..%d\n", (int)SIZEOF_ARRAY(test_cases));

    for (i = 0; i < SIZEOF_ARRAY(test_cases); i++)
    {
        ok(test_cases[i].test_func() == 0, test_cases[i].test_name);
    }

    return TEST_EXIT_CODE;
}
/* main() */
