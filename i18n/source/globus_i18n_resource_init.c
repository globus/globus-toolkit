#include <stdio.h>
#include "globus_common.h"

int
main(int argc, char *argv[])
{
    FILE *              fptr, *outptr;
    char                line[1024];
    char		keyline[1024];
    char *		newlineptr;
    char *		it;
    int			hash;

    fptr = fopen(argv[1], "r");
    outptr = fopen(argv[2], "wt");


    fprintf(outptr, "root { \n\n");


    while(fgets(line, sizeof(line), fptr) != NULL)
    {
    strncpy(keyline,line, 1024);

    printf("Keyline is:\n %s\n", keyline);
    /*convert non-invariant characters to "_" for key*/
    it=&keyline; 
    while (it[0]!=0)
    {   
        switch (it[0])
        {
                case '#':
                case '!':
                case '@':
                case '[':
                case ']':
                case '^':
                case '`':
                case '{':
                case '|':
                case '}':
                case '~':

                it[0]= '_';

                        break;
                default:
                        /*we don't need to do anything*/
                        break;
        }
            it++;
    }

	newlineptr = strchr(line, '\n');
	if (newlineptr!=NULL)
	{
		*newlineptr=NULL;
	}

	newlineptr = strchr(keyline, '\n');
	if (newlineptr!=NULL)
	{
		*newlineptr=NULL;
	}

	hash=globus_hashtable_string_hash(line, 35535);
	fprintf(outptr, "%s_%d     {%s}\n", keyline, hash, line);
    }
    fprintf(outptr, "}");

}
