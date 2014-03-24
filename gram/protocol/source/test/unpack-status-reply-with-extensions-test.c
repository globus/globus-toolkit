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
 *     globus_gram_protocol_unpack_status_reply_with_extensions()
 *     correctly unpacks standard GRAM2 messages
 *
 * STEPS:
 *     - Creates a message using server-side API.
 *     - Parses message to extensions hash.
 *     - Verifies that all attributes we expect in the message are present in
 *       the parsed values.
 *     - Verifies that the number of attributes in the message match the count
 *       of ones we expect.
 */
int test_unpack_with_extensions(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    globus_gram_protocol_extension_t *  entry;
    int                                 rc;
    char *                              expected[] =
    {
            "protocol-version",
            "status",
            "failure-code",
            "job-failure-code"
    };
    int                                 i;

    rc = globus_gram_protocol_pack_status_reply(   
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            0,
            &message,
            &message_size);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_status_reply_with_extensions(
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


/* Test case:
 * PURPOSE:
 *     Make sure
 *     globus_gram_protocol_unpack_status_reply_with_extensions()
 *     handles NULL message or hashtable with the expected error.
 * TEST STEPS:
 *   - Create message
 *   - Call globus_gram_protocol_unpack_status_reply_with_extensions() with
 *     NULL message and verify that result is NULL_PARAM error
 *   - Call globus_gram_protocol_unpack_status_reply_with_extensions() with
 *     NULL hashtable pointer and verify that result is NULL_PARAM error.
 */
int test_null_param(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    int                                 rc;

    rc = globus_gram_protocol_pack_status_reply(   
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            0,
            &message,
            &message_size);

    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_status_reply_with_extensions(
            NULL,
            message_size,
            &hashtable);
    test_assert(
            rc == GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER,
            ("# Expected GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER "
             "got %d (%s)\n",
             rc,
             globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_status_reply_with_extensions(
            message,
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

/*
 * PURPOSE:
 *     Verify that
 *     globus_gram_protocol_unpack_status_reply_with_extensions()
 *     catches protocol mismatch errors.
 * TEST STEPS:
 *   - Manually construct status update message with version equal to
 *     GLOBUS_GRAM_PROTOCOL_VERSION + 1
 *   - Call globus_gram_protocol_unpack_status_reply_with_extensions() and
 *     expect a VERSION_MISMATCH error
 */
int test_version_mismatch(void)
{
    char *                              message;
    globus_size_t                       message_size;
    int                                 rc;
    globus_hashtable_t                  hashtable;

    message = globus_common_create_string(
        "protocol-version: %d\r\n"
        "status: %d\r\n"
        "failure-code: %d\r\n"
        "job-failure-code: %d\r\n",
        GLOBUS_GRAM_PROTOCOL_VERSION + 1,
        GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
        0,
        0);
    test_assert(message != NULL,
            ("# Error creating message (out of memory?)\n"));
    message_size = strlen(message) + 1;

    rc = globus_gram_protocol_unpack_status_reply_with_extensions(
            (globus_byte_t *) message,
            message_size,
            &hashtable);
    test_assert(rc == GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH,
            ("# Expected GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH, "
            "got %d (%s)\n",
            rc, 
            globus_gram_protocol_error_string(rc)));

    if (hashtable != NULL)
    {
        globus_gram_protocol_hash_destroy(&hashtable);
    }
    free(message);

    return 0;
}

/*
 * PURPOSE:
 *     Verify that
 *     globus_gram_protocol_unpack_status_reply_with_extensions()
 *     deals with messages missing attributes from GRAM2 protocol.
 * TEST STEPS:
 *   - Manually construct status update messages with each piece of the GRAM2
 *     protocol missing
 *   - Call globus_gram_protocol_unpack_status_reply_with_extensions() and
 *     expect an UNPACK_FAILED error
 */
int test_missing_attribute()
{
    char *                              message;
    globus_size_t                       message_size;
    int                                 rc;
    globus_hashtable_t                  hashtable;
    int                                 i;
    char *                              lines[] =
    {
        "protocol-version: 2\r\n",
        "status: 2\r\n",
        "failure-code: 0\r\n"
    };

    for (i = 0; i < ARRAY_LEN(lines); i++)
    {
        message = globus_common_create_string(
                "%s%s%s",
                lines[i % ARRAY_LEN(lines)],
                lines[(i+1) % ARRAY_LEN(lines)],
                lines[(i+2) % ARRAY_LEN(lines)]);

        test_assert(message != NULL,
                ("# Error creating message (out of memory?)\n"));
        message_size = strlen(message) + 1;

        rc = globus_gram_protocol_unpack_status_reply_with_extensions(
                (globus_byte_t *) message,
                message_size,
                &hashtable);
        test_assert(rc == GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED,
                ("# Expected GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED, "
                "got %d (%s)\n",
                rc, 
                globus_gram_protocol_error_string(rc)));
        free(message);
    }

    return 0;
}
/* int test_missing_attribute() */


/*
 * PURPOSE:
 *     Verify that
 *     globus_gram_protocol_unpack_status_reply_with_extensions()
 *     deals with messages containing extension attributes not defined in the
 *     GRAM2
 *     protocol.
 * TEST STEPS:
 *   - Construct a status update message with the
 *     globus_gram_protocol_pack_status_reply_with_extensions()
 *     function.
 *   - Call globus_gram_protocol_unpack_status_reply_with_extensions() and
 *     expect a GLOBUS_SUCCESS
 *   - Check that our new attribute is in the hash
 */
int
test_extra_attributes(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    globus_gram_protocol_extension_t *  entry;
    int                                 rc;
    char *                              expected[] =
    {
            "protocol-version",
            "status",
            "failure-code",
            "job-failure-code",
            "attribute"
    };
    int                                 i;

    rc = globus_hashtable_init(
            &hashtable,
            89,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error initializing hashtable (out of memory?)\n"));
    entry = malloc(sizeof(globus_gram_protocol_extension_t));
    test_assert(entry != NULL,
            ("# Error allocating hash entry (out of memory?)\n"));
    entry->attribute = "attribute";
    entry->value = "value";
    rc = globus_hashtable_insert(&hashtable, entry->attribute, entry);

    rc = globus_gram_protocol_pack_status_reply_with_extensions(
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
            0,
            &hashtable,
            &message,
            &message_size);
    test_assert(rc == GLOBUS_SUCCESS,
            ("# Error packing status message: %d (%s)\n",
            rc, globus_gram_protocol_error_string(rc)));

    globus_hashtable_destroy(&hashtable);
    free(entry);
    hashtable = NULL;

    test_assert(
            rc == GLOBUS_SUCCESS,
            ("# Error constructing test message: %d (%s)\n",
            rc,
            globus_gram_protocol_error_string(rc)));

    rc = globus_gram_protocol_unpack_status_reply_with_extensions(
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

/*
 * PURPOSE:
 *     Verify that
 *     globus_gram_protocol_unpack_status_reply_with_extensions()
 *     deals with messages which are badly formatted: lines without ':', 
 *     values without terminating "\r\n"
 *     protocol.
 * TEST STEPS:
 *   - Construct a status update message with the
 *     globus_gram_protocol_pack_status_reply() function.
 *   - Replace initial ":" with "\t"
 *   - Call globus_gram_protocol_unpack_status_reply_with_extensions() and
 *     expect a UNPACK_FAILED error
 *   - Replace "\t" with ":", then remove the training "\n" in the message
 *   - Call globus_gram_protocol_unpack_status_reply_with_extensions() and
 *     expect a UNPACK_FAILED error
 */
int
test_bad_message(void)
{
    globus_byte_t *                     message;
    globus_size_t                       message_size;
    globus_hashtable_t                  hashtable;
    char *                              ptr;
    int                                 rc;

    rc = globus_gram_protocol_pack_status_reply(   
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE,
            0,
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

    rc = globus_gram_protocol_unpack_status_reply_with_extensions(
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
    rc = globus_gram_protocol_unpack_status_reply_with_extensions(
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


int main(int argc, char * argv[])
{
    test_case                           tests[] =
    {
        TEST_CASE(test_unpack_with_extensions),
        TEST_CASE(test_null_param),
        TEST_CASE(test_version_mismatch),
        TEST_CASE(test_missing_attribute),
        TEST_CASE(test_extra_attributes),
        TEST_CASE(test_bad_message)
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

