#include "globus_gss_assist.h"

int main(int argc, char * argv[])
{
    char *                              local_user;
    
    if(globus_gss_assist_gridmap("/DC=org/DC=doegrids/OU=People/CN=John Doe 328453245", &local_user))
    {
        exit(-1);
    }
    else if(strcmp(local_user, "jdoe"))
    {
        exit(-1);
    }

    if(globus_gss_assist_userok("/DC=org/DC=doegrids/OU=People/CN=John Doe 328453245", "john_doe"))
    {
        exit(-1);
    }    
}
