#include "mlsx.h"

#include <unistd.h>
#include <dirent.h>
#include <stdio.h>

int 
main(int argc, char *argv[] ) 
{
    DIR *dir;
    char *filename= (char*)malloc(512);
    char *facts = (char*)malloc(512);


    struct dirent *dirp = (struct dirent*)malloc(sizeof(struct dirent));
    FILE *fd;

    fd = fopen("/tmp/bob","w");
    fwrite(argv[1], strlen(argv[1]), 1, fd);
    fclose(fd);
    

    if(argc == 3)
        dir = opendir(argv[2]);
    else
        dir = opendir(".");
    
    dirp = readdir(dir);
    while(dirp) 
        {
            if(argc == 3)
                sprintf(filename, "%s/%s",argv[2], dirp->d_name);
            else
                sprintf(filename, "%s", dirp->d_name);

            get_fact_list(facts, 512, filename, argv[1]);
            printf("%s %s\n", facts, filename);
            
            
            dirp = readdir(dir);
        }
}

            
