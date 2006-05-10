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

/* test the various pack/unpack routines */

#include "globus_gram_protocol.h"
#include <string.h>

/* job request */
int test1()
{
    int					rc;
    int					job_state_mask[2];
    char *				callback_url[2];
    char *				rsl[2];
    globus_byte_t *				query;
    globus_size_t			query_size;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed activating GRAM protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }

    /* setup parameters for job request pack tests */
    job_state_mask[0] = GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING;
    callback_url[0] = "https://some-bogus-callback-url/";
    rsl[0] = "&(executable=/bin/echo)(arguments=hello)"; /* a classic! */

    rc = globus_gram_protocol_pack_job_request(
	    job_state_mask[0],
	    callback_url[0],
	    rsl[0],
	    &query,
	    &query_size);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed packing job request because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }

    rc = globus_gram_protocol_unpack_job_request(
	    query,
	    query_size,
	    &job_state_mask[1],
	    &callback_url[1],
	    &rsl[1]);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed unpacking job request because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }
    if(strcmp(rsl[0], rsl[1]) != 0 ||
       job_state_mask[0] != job_state_mask[1] ||
       strcmp(callback_url[0], callback_url[1]) != 0)
    {
	fprintf(stderr, "Unpacking job request returned junk!\n");
	rc = 1;
    }
    globus_libc_free(query);
    globus_libc_free(rsl[1]);
    globus_libc_free(callback_url[1]);
error_exit:
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

/* job request w/null callback_url*/
int test2()
{
    int					rc;
    int					job_state_mask[2];
    char *				callback_url[2];
    char *				rsl[2];
    globus_byte_t *			query;
    globus_size_t			query_size;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed activating GRAM protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }

    /* setup parameters for job request pack tests */
    job_state_mask[0] = GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING;
    callback_url[0] = GLOBUS_NULL;
    rsl[0] = "&(executable=/bin/echo)(arguments=hello)"; /* a classic! */

    rc = globus_gram_protocol_pack_job_request(
	    job_state_mask[0],
	    callback_url[0],
	    rsl[0],
	    &query,
	    &query_size);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed packing job request because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }

    rc = globus_gram_protocol_unpack_job_request(
	    query,
	    query_size,
	    &job_state_mask[1],
	    &callback_url[1],
	    &rsl[1]);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed unpacking job request because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }
    if(strcmp(rsl[0], rsl[1]) != 0 ||
       job_state_mask[0] != job_state_mask[1] ||
       (callback_url[1] != GLOBUS_NULL &&
	strlen(callback_url[1]) != 0))
    {
	fprintf(stderr, "Unpacking job request returned junk!\n");
	rc = 1;
    }
    globus_libc_free(rsl[1]);
    globus_libc_free(query);
error_exit:
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

/* job request reply */
int test3()
{
    int					rc;
    int					status[2];
    char *				job_contact[2];
    globus_byte_t *			msg;
    globus_size_t			msg_size;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed activating GRAM protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }

    /* setup parameters for job request reply tests */
    status[0] = GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING;
    job_contact[0] = "https://globus.org/test/1234";

    rc = globus_gram_protocol_pack_job_request_reply(
	    status[0],
	    job_contact[0],
	    &msg,
	    &msg_size);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed packing job request reply because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }

    rc = globus_gram_protocol_unpack_job_request_reply(
	    msg,
	    msg_size,
	    &status[1],
	    &job_contact[1]);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed unpacking job request reply because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }
    if(status[0] != status[1] ||
       strcmp(job_contact[0],job_contact[1]) != 0)
    {
	fprintf(stderr, "Unpacking job request reply returned junk!\n");
	rc = 1;
    }
    globus_libc_free(msg);
    globus_libc_free(job_contact[1]);
error_exit:
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

/* status request */
int
test4()
{
    int					rc;
    char *				status[2];
    globus_byte_t *			msg;
    globus_size_t			msg_size;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed activating GRAM protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }

    /* setup parameters for job request reply tests */
    status[0] = "status";

    rc = globus_gram_protocol_pack_status_request(
	    status[0],
	    &msg,
	    &msg_size);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed packing status request because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }

    rc = globus_gram_protocol_unpack_status_request(
	    msg,
	    msg_size,
	    &status[1]);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed unpacking status request because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }
    if(strcmp(status[0], status[1]) != 0)
    {
	fprintf(stderr, "Unpacking status request returned junk!\n");
	rc = 1;
    }
    globus_libc_free(msg);
    globus_libc_free(status[1]);
error_exit:
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

/* status request reply */
int
test5()
{
    int					rc;
    int 				status[2];
    int 				failure_code[2];
    int 				job_failure_code[2];
    globus_byte_t *			msg;
    globus_size_t			msg_size;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed activating GRAM protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }

    /* setup parameters for job request reply tests */
    status[0] = 1;
    failure_code[0] = 2;
    job_failure_code[0] = 3;

    rc = globus_gram_protocol_pack_status_reply(
	    status[0],
	    failure_code[0],
	    job_failure_code[0],
	    &msg,
	    &msg_size);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed packing status reply because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }

    rc = globus_gram_protocol_unpack_status_reply(
	    msg,
	    msg_size,
	    &status[1],
	    &failure_code[1],
	    &job_failure_code[1]);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed unpacking status reply because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }
    if(status[0] != status[1] ||
       failure_code[0] != failure_code[1] ||
       job_failure_code[0] != job_failure_code[1])
    {
	fprintf(stderr, "Unpacking status request reply returned junk!\n");
	rc = 1;
    }
    globus_libc_free(msg);
error_exit:
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

/* status update */
int
test6()
{
    int					rc;
    char *				job_contact[2];
    int 				status[2];
    int 				failure_code[2];
    globus_byte_t *			msg;
    globus_size_t			msg_size;

    rc = globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed activating GRAM protocol module because %s.\n",
		globus_gram_protocol_error_string(rc));
	return rc;
    }

    /* setup parameters for job request reply tests */
    job_contact[0] = "https://globus.org:123/345/678";
    status[0] = 1;
    failure_code[0] = 2;

    rc = globus_gram_protocol_pack_status_update_message(
	    job_contact[0],
	    status[0],
	    failure_code[0],
	    &msg,
	    &msg_size);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed packing status update because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }

    rc = globus_gram_protocol_unpack_status_update_message(
	    msg,
	    msg_size,
	    &job_contact[1],
	    &status[1],
	    &failure_code[1]);

    if(rc != GLOBUS_SUCCESS)
    {
	fprintf(stderr, "Failed unpacking status update because %s.\n",
		globus_gram_protocol_error_string(rc));
	goto error_exit;
    }
    if(strcmp(job_contact[0], job_contact[1]) != 0 ||
       status[0] != status[1] ||
       failure_code[0] != failure_code[1])
    {
	fprintf(stderr, "Unpacking status update returned junk!\n");
	rc = 1;
    }
    globus_libc_free(msg);
    globus_libc_free(job_contact[1]);
error_exit:
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);
    return rc;
}

int main(int argc, char *argv[])
{
    int					not_ok = 0;
    int					rc;
    int					test_num = 0;

    if(argc > 1)
    {
	test_num = atoi(argv[1]);
    }
    if(test_num == 0 || test_num == 1)
    {
	rc = test1();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 2)
    {
	rc = test2();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 3)
    {
	rc = test3();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 4)
    {
	rc = test4();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 5)
    {
	rc = test5();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    if(test_num == 0 || test_num == 6)
    {
	rc = test6();
	printf("%sok\n", (rc == 0) ? "" : "not ");
	not_ok |= rc;
    }
    return not_ok;
}
