#include "globus_rsl.h"
#include <stdlib.h>

char * tests[] =
{
    "x = 1",
    "&(x = 1)",
    "&(x = (1 1) )",
    "&(x = 1 1 )",
    "&(x != 1 1 )",
    "&(x > 1)",
    "&(x < 1)",
    "|(x < 1)",
    "+(&(x < 1))",
    "&(rsl_substitution = (x y))(z = $(x))",
    NULL
};

int main()
{
    int i;
    int not_ok = 0;

    printf("1..%zd\n",sizeof(tests)/sizeof(tests[0]));  

    for (i = 0; tests[i] != NULL; i++)
    {
        globus_rsl_t * parse_tree;
        char * unparsed;

        parse_tree = globus_rsl_parse(tests[i]);
        if (parse_tree == NULL)
        {
            printf("not ok %d %s\n", i+1, tests[i]);
            not_ok++;
        }
        else
        {
            unparsed = globus_rsl_unparse(parse_tree);
            if (unparsed)
            {
                printf("ok %d %s -> %s\n", i+1, tests[i], unparsed);
                free(unparsed);
            }
            else
            {
                printf("not ok %d %s -> ?\n", i+1, tests[i]);
                not_ok++;
            }
            globus_rsl_free_recursive(parse_tree);
        }
    }
    return not_ok;
}
