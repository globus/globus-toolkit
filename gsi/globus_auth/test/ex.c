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

#include "gaa.h"

struct my_right {
    char *authority;
    char *value;
};

struct my_request {
    char *object;
    struct my_right *my_rights;
};

static struct my_request *get_my_request();
static process_request(struct my_request *req);
char *users;

main()
{
    gaa_ptr gaa = 0;
    void *client_raw_creds;
    char *cred_mechanism = "assertion";
    char *foo;

    foo = "laura";
    client_raw_creds = (void *)foo;
    gaa_initialize(&gaa, (void *)"/nfs/asd/laura/gaa/stable/Security/gaa/gaa_plugin/examples/gaa.linux.nogss.cf");
    process_session(gaa, client_raw_creds, cred_mechanism);
    gaa_cleanup(gaa, 0);
}

/*
 * process_session() -- sample function to process several gaa
 * requests under the same credentials.
 * Arguments:
 *    gaa - input gaa pointer
 *    client_raw_creds - input raw credentials of client.
 *    cred_mechanism - name of mechanism for client credentials
 *                            (e.g. gss-api).
 * Return values:
 *   0 success
 *   -1 failure
 *
 * This function calls two application-specific functions:
 *   get_my_request, to get a request from the client, and
 *   process_request, to do whatever the request is if
 *   authorization has been granted.
 */
process_session(gaa_ptr gaa, void *client_raw_creds, char *cred_mechanism)
{   
    gaa_status status;
    gaa_sc_ptr sc = 0;
    gaa_policy_ptr policy = 0;
    struct my_request *myreq;
    struct my_right *myright;
    gaa_list_ptr list = 0;
    gaa_cred *cred = 0;
    gaa_answer_ptr answer = 0;
    gaa_request_right_ptr right = 0;
    
    /* First initialize the security context */
    if (gaa_new_sc(&sc) != GAA_S_SUCCESS)
        return(-1);
    if (gaa_new_cred(gaa, sc, &cred, cred_mechanism, client_raw_creds,
		     GAA_IDENTITY, 1, 0) != GAA_S_SUCCESS)
	return(-1);
    if (gaa_add_cred(gaa, sc, cred) != GAA_S_SUCCESS)
	return(-1);
    
    while (myreq = get_my_request()) {
	/* Find the appropriate policy for the object specified in the request */
	if ((status = gaa_get_object_policy_info(myreq->object, gaa,
						 &policy)) != GAA_S_SUCCESS)
	    return(-1);
	
	/* Next, build the list of requested rights */
	if ((list = gaa_new_req_rightlist()) == 0)
	    return(-1);
	for (myright = myreq->my_rights; myright->value; myright++) {
	    if ((status = gaa_new_request_right(gaa, &right, myright->authority,
						myright->value)) != GAA_S_SUCCESS)
		return(-1);
	    if ((status = gaa_add_request_right(list, right)) != GAA_S_SUCCESS)
		return(-1);
	}
	
	/* Now check to see whether the request is authorized */
	if ((status = gaa_new_answer(&answer)) != GAA_S_SUCCESS)
	    return(-1);
	
	switch (gaa_check_authorization(gaa, sc, policy, list, answer))
	{
	case GAA_C_YES:
	    printf("request authorized\n");
	    process_request(myreq);
	    break;
	case GAA_C_NO:
	    printf("request denied\n");
	    break;
	case GAA_C_MAYBE:
	    printf("request undetermined\n");
	    break;
	default:
	    fprintf(stderr, "error determining request authorizaton: %s\n",
		    gaa_get_err());
	    break;
	}
	
	/* Finally, clean up after this request. */
	gaa_list_free(list);
	gaa_free_answer(answer);
    }
    gaa_free_sc(sc);
    return(0);
}

static struct my_request *
get_my_request()
{
    static char buf[1024];
    static struct my_request myreq;

    char *auth;
    char *val;
    int i = 0;

    static struct my_right myr[100];
    fgets(buf, sizeof(buf), stdin);
    myreq.object = strtok(buf, " \t\n");
    while (auth = strtok(0, " \t\n")) {
	val = strtok(0, " \t\n");
	myr[i].authority = strdup(auth);
	myr[i].value = strdup(val);
	i++;
    }
    myr[i].authority = myr[i].value = 0;
    myreq.my_rights = myr;
    return(&myreq);
}

static
process_request(struct my_request *req)
{
    printf("in process request\n");
    return(0);
}
