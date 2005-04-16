/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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
}
