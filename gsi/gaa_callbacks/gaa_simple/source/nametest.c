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

#define USAGE "Usage: %s policyname objectname\n"
#include <stdio.h>

main(int argc, char **argv)
{
#ifdef COMPILE_NAME_TEST
    char *policyname;
    char *objectname;
    char ebuf[2048];

    ebuf[0] = '\0';

    if (argc < 3) {
	fprintf(stderr, USAGE, argv[0]);
	exit(1);
    }
    policyname = argv[1];
    objectname = argv[2];
    if (gaa_simple_l_name_matches(policyname, objectname, ebuf, sizeof(ebuf))) {
	printf("%s matches %s\n", policyname, objectname);
    } else {
	printf("%s does not match %s\n", policyname, objectname);
    }
#else /* COMPILE_NAME_TEST */
    printf("compile with -DCOMPILE_NAME_TEST to produce this test\n");
#endif    
}
