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
#include "gaa_simple.h"
#include "gaa_debug.h"
#include "gaa_utils.h"
#include <string.h>
#include <strings.h>

#define USAGE "Usage: %s cffile\n"

char *users = 0;

main(int argc, char **argv)
{
    gaa_status status;
    gaa_sc_ptr sc = 0;
    gaa_ptr gaa = 0;
    gaa_policy *policy = 0;
    char *ifname = 0;
    FILE *reqfile = stdin;
    gaa_list_ptr rlist;
    gaa_policy_right *pright;
    gaa_list_entry_ptr ent;
    char *object = 0;
    char buf[1024];
    char rbuf[8192];
    char *repl;
    char *what;
    char *cfname;

    switch(argc) {
    case 2:
	cfname = argv[1];
	break;
    default:
	fprintf(stderr, USAGE, argv[0]);
	exit(1);
    }

    if ((status = gaa_initialize(&gaa, (void *)cfname)) != GAA_S_SUCCESS) {
	fprintf(stderr, "init_gaa failed: %s: %s\n",
		gaa_x_majstat_str(status), gaa_get_err());
	exit(1);
    }

    if ((status = gaa_new_sc(&sc)) != GAA_S_SUCCESS) {
	fprintf(stderr, "gaa_new_sc failed: %s: %s\n",
		gaa_x_majstat_str(status), gaa_get_err());
	exit(1);
    }

    printf("> ");
    while (fgets(buf, sizeof(buf), stdin)) {
	repl = process_msg(gaa, &sc, buf, rbuf, sizeof(rbuf), &users, &policy);
	if (repl == 0)
	    printf("(null reply)");
	else
	    printf("%s", repl);
	printf("> ");
    }
    exit(0);
}
