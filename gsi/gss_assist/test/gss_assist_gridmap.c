#include "globus_gss_assist.h"

int main(int argc, char * argv[])
{
    char *                              local_user;
    
    if(globus_gss_assist_gridmap("/DC=org/DC=doegrids/OU=People/UserID=328453245/EMAIL=john@doe.com/EmailAddress=john@doe.com", &local_user))
    {
        exit(-1);
    }
    else if(strcmp(local_user, "jdoe"))
    {
        exit(-1);
    }

    if(globus_gss_assist_userok("/DC=org/DC=doegrids/OU=People/UID=328453245/Email=john@doe.com/E=john@doe.com", "john_doe"))
    {
        exit(-1);
    }    
}
