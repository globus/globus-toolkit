#include "mlsx.h"
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

int 
main(
    int                                 argc,
    char *                              argv[]) 
{
    DIR *                               dir = NULL;
    struct dirent *                     dirp;

    if(argc == 3)
    {
        dir = opendir(argv[2]);
    }
    else if(argc == 2)
    {
        dir = opendir(".");
    }
    
    if(!dir)
    {
        if(argc >= 2)
        {
            perror("opendir");
        }
        fprintf(stderr, "usage: %s <facts> [ <path> ]\n", argv[0]);
        exit(1);
    }
    
    
    while((dirp = readdir(dir)))
    {
        char                            facts[2048];
        char                            path[1024];
        
        if(argc == 3)
        {
            snprintf(path, sizeof(path), "%s/%s", argv[2], dirp->d_name);
        }
        else
        {
            strncpy(path, dirp->d_name, sizeof(path));
        }
        
        path[sizeof(path) - 1] = 0;
        get_fact_string(facts, sizeof(facts), path, argv[1]);
        printf("%s\n", facts);
    }
    
    closedir(dir);
    return 0;
}
