#include "config.h"
#include "proto.h"
#include "mlsx.h"
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int 
main(
    int                                 argc,
    char *                              argv[]) 
{
    DIR *                               dir = NULL;
    struct dirent *                     dirp;
    int                                 cwd = 0;
    char *                              facts = 
        "Type;Size;Modify;Perm;Charset;UNIX.mode;UNIX.slink;Unique;";

    if(argc >= 2)
    {
        dir = opendir(argv[1]);
    }
    else
    {
        dir = opendir(".");
        cwd = 1;
    }
    
    if(!dir)
    {
        perror("opendir");
        fprintf(stderr, "usage: %s [ <path> [ <facts> ] ]\n", argv[0]);
        exit(1);
    }
    
    if(argc > 2)
    {
        facts = argv[2];
    }
    
    while((dirp = readdir(dir)))
    {
        char                            fact_str[MAXPATHLEN * 5];
        char                            path[MAXPATHLEN];
        
        if(cwd)
        {
            strncpy(path, dirp->d_name, sizeof(path));
        }
        else
        {
            snprintf(path, sizeof(path), "%s/%s", argv[1], dirp->d_name);
        }
        
        path[sizeof(path) - 1] = 0;
        if(get_fact_string(fact_str, sizeof(fact_str), path, facts) != 0)
        {
            continue;
        }
        printf("%s\n", fact_str);
    }
    
    closedir(dir);
    return 0;
}
