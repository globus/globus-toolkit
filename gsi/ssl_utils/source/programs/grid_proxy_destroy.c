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


/**********************************************************************

cinit.c

Description:
	This program usee to cleanup proxy files. 

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/
#include "config.h"


#ifndef DEFAULT_SECURE_TMP_DIR
#ifndef WIN32
#define DEFAULT_SECURE_TMP_DIR "/tmp"
#else
#define DEFAULT_SECURE_TMP_DIR "c:\\tmp"
#endif /* WIN32 */
#endif /* DEFAULT_SECURE_TMP_DIR */

#ifndef WIN32
#define FILE_SEPERATOR "/"
#else
#define FILE_SEPERATOR "\\"
#endif

#include "sslutils.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef WIN32
#include <io.h>
#else
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <dirent.h>
#endif
#include <string.h>


/**********************************************************************
                       Define module specific variables
**********************************************************************/

#define SHORT_USAGE_FORMAT \
"\nSyntax: %s [-help][-dryrun][-default][-all][--] [file1...]\n"

static char *  LONG_USAGE = \
"\n" \
"    Options\n" \
"    -help, -usage             Displays usage\n" \
"    -version                  Displays version\n" \
"    -dryrun                   Prints what files would have been destroyed\n" \
"    -default                  Destroys file at default proxy location\n" \
"    -all                      Destroys any delegated proxy as well\n" \
"    --                        End processing of options\n" \
"    file1 file2 ...           Destroys files listed\n" \
"\n";



/********************************************************************/
#ifdef WIN32
static unsigned long getuid() { return 0;}
#endif

static int
myremove(char* filename,int flag) 
{
    int   f;
    int   rec;
    int   left;
    long  size;
    char  msg[65] = "Destroyed by globus_proxy_destroy\r\n";

    if (flag)
	fprintf(stderr,"Would remove %s\n", filename);
    else
    {
	f = open(filename,O_RDWR);
	if (f) 
	{
	    size = lseek(f,0L,SEEK_END);
	    lseek(f,0L,SEEK_SET);
	    if (size> 0) 
	    {
		rec = size/64;
		left = size - rec*64;
		while (rec)
		{
		    write(f,msg,64);
		    rec--;
		}
		if (left) 
		    write(f,msg,left);
	    }
	    close(f);
	}
	remove(filename);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int                all_flag      = 0;
    int                default_flag  = 0;
    int                dryrun_flag   = 0;
    int                i;
    unsigned long      uid;
    char *             argp;
    char *             program;
    char *             env_file;
    char *             default_file;
    char *             default_full_file;
#ifndef WIN32
    char *             filename;
    DIR *              dirp;
    struct dirent *    direntp;
    struct stat        stx;
#endif

    default_full_file = (char *) malloc(strlen(DEFAULT_SECURE_TMP_DIR) + 
					strlen(X509_USER_PROXY_FILE) + 64);
    if (! default_full_file)
	goto err;
    
    uid = getuid();
    sprintf( default_full_file,
	     "%s%s%s%lu",
	     DEFAULT_SECURE_TMP_DIR,
	     FILE_SEPERATOR,
	     X509_USER_PROXY_FILE,
	     uid );
    
    default_file = (char *) malloc(strlen(X509_USER_PROXY_FILE) + 64);
    if (!default_file)
	goto err;
    
    sprintf( default_file,
	     "%s%lu",
	     X509_USER_PROXY_FILE,
	     uid );

    if (strrchr(argv[0],'/'))
	program = strrchr(argv[0],'/') + 1;
    else
	program = argv[0];

#   define args_show_version() \
    { \
	char buf[64]; \
	sprintf( buf, \
		 "%s-%s", \
		 PACKAGE, \
		 VERSION); \
	fprintf(stderr, "%s", buf); \
	exit(0); \
    }

#   define args_show_short_help() \
    { \
        fprintf(stderr, \
		SHORT_USAGE_FORMAT \
		"\nOption -help will display usage.\n", \
		program); \
	exit(0); \
    }

#   define args_show_full_usage() \
    { \
	fprintf(stderr, SHORT_USAGE_FORMAT \
		"%s", \
		program, \
		LONG_USAGE); \
	exit(0); \
    }

#   define args_error_message(errmsg) \
    { \
	fprintf(stderr, "ERROR: %s\n", errmsg); \
        args_show_short_help(); \
	exit(1); \
    }

#   define args_error(argnum, argval, errmsg) \
    { \
	char buf[1024]; \
	sprintf(buf, "argument #%d (%s) : %s", argnum, argval, errmsg); \
	args_error_message(buf); \
    }

    for (i=1; i<argc; i++)
    {
	argp = argv[i];

	/* '--' indicates end of options */
	if (strcmp(argp,"--") == 0)
	{
	    i++;
	    break;
	}

	/* If no leading dash assume it's start of filenames */
	if (strncmp(argp,"-",1) != 0)
	{
	    break;
	}

#ifndef WIN32
	if (strcmp(argp,"-all") == 0)
	    all_flag++;
#endif
	if (strcmp(argp,"-default") == 0)
	    default_flag++;
	else if (strcmp(argp,"-dryrun") == 0)
	    dryrun_flag++;
	else if (strncmp(argp,"--",2) == 0)
	{
	    args_error(i,argp,"double-dashed options not allowed");
	}
	else if ((strcmp(argp,"-help") == 0) ||
		 (strcmp(argp,"-usage") == 0) )
	{
	    args_show_full_usage();
	}
	else if (strcmp(argp,"-version") == 0)
	{
	    args_show_version();
	}
	else 
	{
	    args_error(i,argp,"unknown option");
	}
    }

    /* remove the files listed on the command line first */
    for (; i<argc; i++)
	myremove(argv[i],dryrun_flag);

    if (default_flag)
	myremove(default_full_file,dryrun_flag);

#ifndef WIN32	
    if (all_flag && (dirp = opendir(DEFAULT_SECURE_TMP_DIR)) != NULL)
    {
	while ( (direntp = readdir( dirp )) != NULL )
	{
	    if (!strcmp(direntp->d_name,default_file) ||
		!strncmp(direntp->d_name,
			 X509_USER_DELEG_FILE,
			 strlen(X509_USER_DELEG_FILE)))
	    {
		filename = (char *)malloc(strlen(DEFAULT_SECURE_TMP_DIR)
					  +strlen(direntp->d_name)+2);
		if (!filename) 
		    goto err;

		sprintf(filename,
			"%s%s%s",
			DEFAULT_SECURE_TMP_DIR,
			FILE_SEPERATOR,
			direntp->d_name);
			
		if (stat(filename,&stx)	== 0)
		{
		    if (stx.st_uid == getuid())
			myremove(filename,dryrun_flag);
		}
		free(filename);
	    }
	}
    }
#endif
	
    /* 
     * no options, remove the default file, which is the ENV
     * or the /tmp/x509up_u<uid> file
     */

    if (!default_flag && !all_flag)
    {
	env_file = getenv(X509_USER_PROXY);
	if (env_file)
	    myremove(env_file,dryrun_flag);
	else
	    myremove(default_full_file,dryrun_flag);
    }

    return 0;

err:
    fprintf(stderr,"Malloc error\n");
    return 1;
}












