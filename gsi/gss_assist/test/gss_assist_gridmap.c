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
    return 0;
}
