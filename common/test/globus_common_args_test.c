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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "globus_common.h"


const char * oneline_usage
    = "globus_args_test [-foo] [-replicate file N] [-host hn] [-file file]";

const char * long_usage
    =   "\nglobus_args_test [options] x\n" \
        "OPTIONS\n" \
        "\t -foo              : triggers the \"foo mode\"\n" \
        "\t -replicate file N : replicates an existing file N times\n" \
        "\t -host  hostname   : defines a hostname\n" \
        "\t -file  x          : defines a filename\n\n";

#define foo_id   1
#define rep_id   2
#define hn_id    3
#define np_id    4
#define file_id  5

static char *  foo_aliases[]  = { "-foo", GLOBUS_NULL };
static char *  np_aliases[]   = { "-np", GLOBUS_NULL };
static char *  file_aliases[] = { "-file", "-f", GLOBUS_NULL };
static char *  rep_aliases[]  = { "-replicate", "-rep", "-r", GLOBUS_NULL };
static char *  hn_aliases[]   = { "-host", "-hn", "-h", GLOBUS_NULL };


static int validate_filename_parms
    = O_RDONLY;

static globus_validate_int_parms_t validate_int_parms
    = { GLOBUS_VALIDATE_INT_MINMAX, 0, 64 };

static globus_args_valid_predicate_t np_checks[] 
    = { globus_validate_int };

static void* np_check_parms[] 
    = { (void *) &validate_int_parms };

static globus_args_valid_predicate_t rep_checks[] 
    = { globus_validate_filename, globus_validate_int };

static void* rep_check_parms[]
    = { (void *) &validate_filename_parms, (void *) &validate_int_parms };

static globus_args_valid_predicate_t file_checks[] 
    = { globus_validate_filename };

static void* file_check_parms[]
    = { (void *) &validate_filename_parms };


/* forward decl. */
int
test_hostname( char * value, void * parms, char ** error_msg );

static globus_args_valid_predicate_t hn_checks[]
    = { test_hostname };

static globus_args_option_descriptor_t option_list[]
    = { {foo_id,  foo_aliases,  0, GLOBUS_NULL, GLOBUS_NULL} ,
        {np_id,   np_aliases,   1, np_checks,   np_check_parms} ,
        {rep_id,  rep_aliases,  2, rep_checks,  rep_check_parms} ,
        {hn_id,   hn_aliases,   1, hn_checks,   GLOBUS_NULL} ,
        {file_id, file_aliases, 1, file_checks, file_check_parms} };


int
test_hostname( char * value, void * parms, char ** error_msg )
{
    struct hostent    h;
    char              buf[2048];
    int               err;

    err = 0;
    globus_libc_gethostbyname_r( value, &h, buf, 2048, &err );

    return err;
}


int
do_test( char *argv[] )
{
    globus_args_option_instance_t *  option;
    globus_list_t *                  options_found;
    globus_list_t *                  list;
    char *                           error_msg;
    int                              argc;
    int                              n_options;
    int                              err;
    int                              i;

    for (argc=0; argv[argc]; argc++)
	;

    n_options = sizeof(option_list)/sizeof(globus_args_option_descriptor_t);

    error_msg = GLOBUS_NULL;
    err = globus_args_scan( &argc,
			    &argv,
			    n_options,
			    option_list,
			    "footest",
			    GLOBUS_NULL,
			    oneline_usage,
			    long_usage,
			    &options_found,
			    GLOBUS_NULL    );

    printf("globus_args_scan returned %d\n", err);

    if (error_msg)
        printf(error_msg);
    else
	printf("error_msg = null\n");

    if (err >= 0)
    {
        printf("after args_scan : argc = %d\n", argc);
        for (i=0; i<argc; i++)
            printf("\targv[%2d] = [%s]\n", i, (argv[i]) ? argv[i] : "NULL" );

	printf("option list : \n");

	for (list = options_found;
	     !globus_list_empty(list);
	     list = globus_list_rest(list))
	{
	    option = globus_list_first(list);
	    printf("\tid=%d arity=%d\n", option->id_number, option->arity);
	    for (i=0; i<option->arity; i++)
		printf("\t\tval[%2d] = [%s]\n", i,
		       (option->values[i]) ? option->values[i] : "NULL" );
	}

	globus_args_option_instance_list_free( &options_found );
    }

    return err;
}


static char * test1[] = { 
    "globus_args_test", "-foo", GLOBUS_NULL };    /* ok */

static char * test2[] = {
    "globus_args_test", "-file", "globus_common_args_test", GLOBUS_NULL };   /* ok */

static char * test3[] = {
    "globus_args_test", "-rep", "globus_common_args_test", "3", GLOBUS_NULL };   /* ok */

static char * test4[] = {
    "globus_args_test", "-np", "12", GLOBUS_NULL };   /* ok */

static char * testhexok[] = {
    "globus_args_test", "-np", "0x2F", GLOBUS_NULL };  /* ok */

static char * testhexmax[] = {
    "globus_args_test", "-np", "0xAB", GLOBUS_NULL };  /* fail */

static char * testoctok[] = {
    "globus_args_test", "-np", "077", GLOBUS_NULL };  /* ok */

static char * testoctmax[] = {
    "globus_args_test", "-np", "0101", GLOBUS_NULL };  /* fail */

static char * test7[] = {
    "globus_args_test", "-np", "-1", GLOBUS_NULL };  /* fail */

static char * test8[] = {
    "globus_args_test", "-np", "65", GLOBUS_NULL };  /* fail */

static char * test9[] = {
    "globus_args_test", "-file", "does/not/exist", GLOBUS_NULL };  /* fail */

static char * testhnok[] = {
    "globus_args_test", "-hn", "www.globus.org", GLOBUS_NULL }; /*ok*/

static char * testhnfail[] = {
    "globus_args_test", "-hn", "smutt.mqs.anl.gov", GLOBUS_NULL }; /*fail*/


int
main(int argc, char *argv[])
{
    int i = 1;

    #define xxx(q) printf("test %d returned %d\n", i++, do_test(q) );

    globus_module_activate(GLOBUS_COMMON_MODULE);

    xxx(test1);
    xxx(test2);
    xxx(test3);
    xxx(test4);
    xxx(testhexok);
    xxx(testhexmax);
    xxx(testoctok);
    xxx(testoctmax);
    xxx(test7);
    xxx(test8);
    xxx(test9);
    xxx(testhnok);
    xxx(testhnfail);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return 0;
}



