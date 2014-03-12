#include "globus_gram_protocol.h"
#include "globus_preload.h"

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
 *     globus_gram_protocol_unpack_message()
 *     correctly unpacks standard GRAM2 messages
 *
 * STEPS:
 *     - Creates a message using server-side API.
 *     - Parses message to hash.
 *     - Verifies that all attributes we expect in the message are present in
 *       the parsed values.
 *     - Verifies that the number of attributes in the message match the count
 *       of ones we expect.
 */
static
int
unpack_test(void)
{
    char *                              message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    globus_gram_protocol_extension_t *  entry;
    int                                 rc;
    char *                              expected[] =
    {
            "protocol-version",
            "job-manager-url",
            "status",
            "failure-code"
    };
    int                                 i;

    rc = globus_gram_protocol_pack_status_update_message(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            (globus_byte_t **)&message,
            &message_size);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_message(
            message,
            message_size,
            &hashtable);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error parsing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    /* check that expected attributes were parsed */
    for (i = 0; i < ARRAY_LEN(expected); i++)
    {
        entry = globus_hashtable_lookup(&hashtable, expected[i]);
        test_assert(
                entry != NULL,
                ("# Missing expected attribute %s\n", expected[i]));
    }

    test_assert(ARRAY_LEN(expected) == globus_hashtable_size(&hashtable),
            ("# Hash table contains %d entries, expected %d",
             globus_hashtable_size(&hashtable),
             ARRAY_LEN(expected)));

    globus_gram_protocol_hash_destroy(&hashtable);

    free(message);

    return 0;
}
/* unpack_test() */

/*
 * Test case:
 *
 * PURPOSE:
 *     Check that
 *     globus_gram_protocol_unpack_message()
 *     correctly unpacks standard GRAM2 messages with escaped extensions
 *
 * STEPS:
 *     - Creates a message using server-side API.
 *     - Parses message to hash.
 *     - Verifies that all attributes we expect in the message are present in
 *       the parsed values.
 *     - Verifies that the number of attributes in the message match the count
 *       of ones we expect.
 */
static
int
unpack_test_with_extensions(void)
{
    char *                              message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    globus_gram_protocol_extension_t *  entry;
    int                                 rc;
    char                                ext_text[] = "extension: \"hello\\\"\"\r\n";
    char *                              expected[] =
    {
            "protocol-version",
            "job-manager-url",
            "status",
            "failure-code",
            "extension"
    };
    int                                 i;

    rc = globus_gram_protocol_pack_status_update_message(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            (globus_byte_t **) &message,
            &message_size);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));
    message = realloc(message, strlen(message) + strlen(ext_text) + 1);
    test_assert(
            message != NULL,
            ("# Error reallocing test message\n"));
    strcat(message, ext_text);
    message_size = strlen((char *) message)+1;

    rc = globus_gram_protocol_unpack_message(
            (char *) message,
            message_size,
            &hashtable);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error parsing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    /* check that expected attributes were parsed */
    for (i = 0; i < ARRAY_LEN(expected); i++)
    {
        entry = globus_hashtable_lookup(&hashtable, expected[i]);
        test_assert(
                entry != NULL,
                ("# Missing expected attribute %s\n", expected[i]));
    }

    test_assert(ARRAY_LEN(expected) == globus_hashtable_size(&hashtable),
            ("# Hash table contains %d entries, expected %d",
             globus_hashtable_size(&hashtable),
             ARRAY_LEN(expected)));

    globus_gram_protocol_hash_destroy(&hashtable);

    free(message);

    return 0;
}
/* unpack_test() */



/* Test case:
 * PURPOSE:
 *     Make sure
 *     globus_gram_protocol_unpack_status_update_message_with_extensions()
 *     handles NULL message or hashtable with the expected error.
 * TEST STEPS:
 *   - Create message
 *   - Call globus_gram_protocol_unpack_status_update_message_with_extensions() with
 *     NULL message and verify that result is NULL_PARAM error
 *   - Call globus_gram_protocol_unpack_status_update_message_with_extensions() with
 *     NULL hashtable pointer and verify that result is NULL_PARAM error.
 */
int
unpack_null_param_test(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    int                                 rc;

    rc = globus_gram_protocol_pack_status_update_message(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            &message,
            &message_size);

    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_message(
            NULL,
            message_size,
            &hashtable);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("# Expected GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER "
             "got %d (%s)\n",
             rc,
             globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_message(
            (char *) message,
            message_size,
            NULL);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("# Expected GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER "
             "got %d (%s)\n",
             rc,
             globus_gram_protocol_error_string(rc)));

    free(message);

    return 0;
}
/* unpack_null_param_test() */


/*
 * PURPOSE:
 *     Verify that
 *     globus_gram_protocol_unpack_status_update_message_with_extensions()
 *     deals with messages which are badly formatted: lines without ':',
 *     values without terminating "\r\n"
 *     protocol.
 * TEST STEPS:
 *   - Construct a status update message with the
 *     globus_gram_protocol_pack_status_update_message() function.
 *   - Replace initial ":" with "\t"
 *   - Call globus_gram_protocol_unpack_status_update_message_with_extensions() and
 *     expect a UNPACK_FAILED error
 *   - Replace "\t" with ":", then remove the training "\n" in the message
 *   - Call globus_gram_protocol_unpack_status_update_message_with_extensions() and
 *     expect a UNPACK_FAILED error
 */
int
unpack_bad_message_test(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    char *                              ptr;
    int                                 rc;

    rc = globus_gram_protocol_pack_status_update_message(
            job_id,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            &message,
            &message_size);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    ptr = strchr((char *) message, ':');
    test_assert(
            ptr != NULL,
            ("# Error locating \":\" in message\n"));
    *ptr = '\t';

    rc = globus_gram_protocol_unpack_status_update_message_with_extensions(
            message,
            message_size,
            &hashtable);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED,
            ("# Expected GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED, got "
             " %d (%s)\n",
             rc,
             globus_gram_protocol_error_string(rc)));

    *ptr = ':';
    message[message_size-2] = 0;
    rc = globus_gram_protocol_unpack_status_update_message_with_extensions(
            message,
            message_size,
            &hashtable);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED,
            ("# Expected GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED, got "
             " %d (%s)\n",
             rc,
             globus_gram_protocol_error_string(rc)));

    free(message);

    return 0;
}
/* unpack_bad_message_test() */


int main(int argc, char * argv[])
{
    test_case                           tests[] =
    {
        TEST_CASE(unpack_test),
        TEST_CASE(unpack_test_with_extensions),
        TEST_CASE(unpack_null_param_test),
        TEST_CASE(unpack_bad_message_test)
    };
    int                                 i;
    int                                 rc;
    int                                 not_ok = 0;

    LTDL_SET_PRELOADED_SYMBOLS();
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
