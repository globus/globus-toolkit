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
