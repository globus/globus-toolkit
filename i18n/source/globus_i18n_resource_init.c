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
    char * 		out;
    int			hash;

    fptr = fopen(argv[1], "r");
    outptr = fopen(argv[2], "wt");


    fprintf(outptr, "root { \n\n");


    while(fgets(line, sizeof(line), fptr) != NULL)
    {
   /* strncpy(keyline,line, 1024);*/
    /*sprintf(&keyline, "%s", line);
    fprintf(outptr, "%s", line);*/

    /*convert non-invariant characters to "_" for key*/
    it=line; 
    out=keyline;

    /*get rid of trailing \n*/
    while (it[0]!='\n')
    {
	it++;
    }
    it[0]='\0';
    it=line;
    /*collapse \n to return line char*/
    while (it[0]!='\0')
    {
	switch (it[0])
	{
                case '\\':

		    if (it[1]=='n')
		    {
		        out[0]='\n';
		        it++;
		    }
		    else
		    {
			out[0]=it[0];
		    }
		    break;
                default:
		    out[0]=it[0];
                        /*we don't need to do anything*/
                        break;
        }
	it++;
	out++;
    }
    out[0]='\0';  /* need the NULL termination*/
	    
	hash=globus_hashtable_string_hash(keyline, 35535);
	it=keyline;
    while (it[0]!='\0')
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
                case ' ':
		case '\n':


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

	fprintf(outptr, "\"%s_%d\"     {\"%s\"}\n", keyline, hash, line);
    }
    fprintf(outptr, "}");

    return GLOBUS_SUCCESS;
}
