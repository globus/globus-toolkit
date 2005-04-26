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

#include "gaa.h"
#include "gaa_simple.h"
#include "gaa_debug.h"
#include "gaa_test_utils.h"
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define USAGE "Usage: %s cffile assertionfile\n"

extern gaa_getpolicy_func gaa_simple_read_saml;

char *users = 0;

main(int argc, char **argv)
{

    gaa_status status;
    gaa_sc_ptr sc = 0;
    gaa_ptr gaa = 0;
    gaa_policy *policy = 0;
    gaa_list_entry_ptr ent;
    char *object = 0;
    char buf[1024];
    char rbuf[8192];
    char *repl;
    char *what;
    char *cfname;
    char *assertion = 0;
    int assertionfile = 0;
    char *assertionfilename;
    void *getpolicy_param;
    struct stat st;

    switch(argc) {
    case 3:
	assertionfilename = argv[2];
	if ((assertionfile = open(assertionfilename, O_RDONLY)) < 0) {
	    perror(assertionfilename);
	    exit(1);
	}

	if (fstat(assertionfile, &st) != 0) {
	    perror(assertionfilename);
	    exit(1);
	}
	if ((assertion = malloc(st.st_size)) == 0) {
	    perror("malloc failed");
	    exit(1);
	}
	if (read(assertionfile, assertion, st.st_size) <= 0) {
	    perror(argv[2]);
	    exit(1);
	}

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

    if ((status = gaa_x_get_getpolicy_param(gaa, &getpolicy_param)) != GAA_S_SUCCESS) {
	fprintf(stderr, "getpolicy plugin not configured");
	exit(1);
    }

    if (getpolicy_param)
	*((char **)getpolicy_param) = assertion;

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
