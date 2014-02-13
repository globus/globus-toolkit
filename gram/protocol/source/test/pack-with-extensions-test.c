#include "globus_gram_protocol.h"

#define test_assert(assertion, message) \
    if (!(assertion)) \
    { \
        printf message; \
        return 1; \
    }

#define TEST_CASE(x) { #x, x }

#define ARRAY_LEN(x) ((int) (sizeof(x)/sizeof(x[0])))

typedef struct
{
    char * name;
    int (*test_function)(void);
}
test_case;

char *                                  job_id = "http://example.org:43343/1/2";

/*
 * Test case:
 *
 * PURPOSE:
 *     Check that
 *     globus_gram_protocol_pack_status_update_message_with_extensions()
 *     generates messages which can be parsed with GRAM2 parser if no
 *     extensions are present.
 *
 * STEPS:
 *     - Creates a message
 *       globus_gram_protocol_pack_status_update_message_with_extensions()
 *       with an empty hash table.
 *     - Parses message
 *     - Verifies that all standard attributes match expected values
 */
int
test_pack_with_empty_extensions(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    int                                 rc;
    char *                              job_contact = NULL;
    int                                 status = 0;
    int                                 failure_code = 0;

    rc = globus_hashtable_init(
            &hashtable,
            89,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error initializing hash table (out of memory?)\n"));

    rc = globus_gram_protocol_pack_status_update_message_with_extensions(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            &hashtable,
            &message,
            &message_size);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_status_update_message(
            message,
            message_size,
            &job_contact,
            &status,
            &failure_code);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error parsing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    /* check that expected attributes were parsed correctly */
    test_assert(
            strcmp(job_contact, job_id) == 0,
            ("# job contact mismatch '%s', expected '%s'\n",
             job_contact,
             job_id));
    test_assert(
            status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            ("# job status mismatch '%d', expected '%d'\n",
             status,
             GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE));
    test_assert(
            failure_code == 0,
            ("# failure code mismatch '%d', expected '%d'\n",
             failure_code,
             0));

    globus_gram_protocol_hash_destroy(&hashtable);

    free(message);

    return 0;
}
/* test_pack_with_empty_extensions() */

/*
 * Test case:
 *
 * PURPOSE:
 *     Check that
 *     globus_gram_protocol_pack_status_update_message_with_extensions()
 *     generates messages which can be parsed with GRAM2 parser if some
 *     extensions are present.
 *
 * STEPS:
 *     - Creates a message
 *       globus_gram_protocol_pack_status_update_message_with_extensions()
 *       with a non-empty hash table.
 *     - Parses message
 *     - Verifies that all standard attributes match expected values
 */
int
test_pack_with_extensions(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    globus_gram_protocol_extension_t *  entry;
    int                                 rc;
    char *                              job_contact = NULL;
    int                                 status = 0;
    int                                 failure_code = 0;

    rc = globus_hashtable_init(
            &hashtable,
            89,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error initializing hash table (out of memory?)\n"));

    entry = malloc(sizeof(globus_gram_protocol_extension_t));
    test_assert(
            entry != NULL,
            ("# Error creating extension\n"));
    entry->attribute = strdup("attribute");
    test_assert(
            entry->attribute != NULL,
            ("# Error creating extension attribute name\n"));
    entry->value = strdup("value");
    test_assert(
            entry->value != NULL,
            ("# Error creating extension attribute value\n"));

    rc = globus_hashtable_insert(&hashtable, entry->attribute, entry);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error inserting extension attribute to hashtable\n"));

    rc = globus_gram_protocol_pack_status_update_message_with_extensions(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            &hashtable,
            &message,
            &message_size);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_status_update_message(
            message,
            message_size,
            &job_contact,
            &status,
            &failure_code);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error parsing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    /* check that expected attributes were parsed correctly */
    test_assert(
            strcmp(job_contact, job_id) == 0,
            ("# job contact mismatch '%s', expected '%s'\n",
             job_contact,
             job_id));
    test_assert(
            status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            ("# job status mismatch '%d', expected '%d'\n",
             status,
             GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE));
    test_assert(
            failure_code == 0,
            ("# failure code mismatch '%d', expected '%d'\n",
             failure_code,
             0));

    free(job_contact);

    globus_gram_protocol_hash_destroy(&hashtable);

    free(message);

    return 0;
}
/* test_pack_with_extensions() */

/* Test case:
 * PURPOSE:
 *     Make sure
 *     globus_gram_protocol_pack_status_update_message_with_extensions()
 *     handles NULL job id, hashtable, message, or message size.
 * TEST STEPS:
 *   - Call globus_gram_protocol_unpack_status_update_message_to_hash() with
 *     NULL message and verify that result is NULL_PARAM error
 *   - Call globus_gram_protocol_unpack_status_update_message_to_hash() with
 *     NULL hashtable pointer and verify that result is NULL_PARAM error.
 */
int
test_null_param(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    int                                 rc;

    rc = globus_hashtable_init(
            &hashtable,
            89,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    test_assert(rc == GLOBUS_SUCCESS,
            ("# Error constructing hashtable (out of memory?)\n"));

    /* Null job id */
    rc = globus_gram_protocol_pack_status_update_message_with_extensions(
            NULL /* job_id */,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            &hashtable,
            &message,
            &message_size);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("# With null job_id, expected "
             "GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER, got %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_pack_status_update_message_with_extensions(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            NULL,
            &message,
            &message_size);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("# With null extensions, expected "
             "GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER, got %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_pack_status_update_message_with_extensions(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            &hashtable,
            NULL,
            &message_size);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("# With null reply, expected "
             "GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER, got %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));
    rc = globus_gram_protocol_pack_status_update_message_with_extensions(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            &hashtable,
            &message,
            NULL);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("# With null replysize, expected "
             "GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER, got %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    globus_hashtable_destroy(&hashtable);

    return 0;
}
/* test_null_param() */

int
test_null_extension_value(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    globus_gram_protocol_extension_t    entry;
    int                                 rc;

    rc = globus_hashtable_init(
            &hashtable,
            89,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    test_assert(rc == GLOBUS_SUCCESS,
            ("# Error constructing hashtable (out of memory?)\n"));
    entry.attribute = "attribute";
    entry.value = NULL;

    rc = globus_hashtable_insert(&hashtable, entry.attribute, &entry);
    test_assert(rc == GLOBUS_SUCCESS,
            ("# Error adding extension to attribute\n"));

    rc = globus_gram_protocol_pack_status_update_message_with_extensions(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            &hashtable,
            &message,
            &message_size);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_PACK_FAILED,
            ("# With null job_id, expected "
             "GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_PACK_FAILED, got %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    globus_hashtable_destroy(&hashtable);

    return 0;
}
/* test_null_extension_value() */

int main(int argc, char * argv[])
{
    test_case                           tests[] =
    {
        TEST_CASE(test_pack_with_empty_extensions),
        TEST_CASE(test_pack_with_extensions),
        TEST_CASE(test_null_param),
        TEST_CASE(test_null_extension_value)
    };
    int                                 i;
    int                                 rc;
    int                                 not_ok = 0;

    printf("1..%d\n", ARRAY_LEN(tests));

    globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    for (i = 0; i < ARRAY_LEN(tests); i++)
    {
        rc = tests[i].test_function();

        if (rc != 0)
        {
            not_ok++;
            printf("not ok - %s\n", tests[i].name);
        }
        else
        {
            printf("ok - %s\n", tests[i].name);
        }
    }
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);

    return not_ok;
}
