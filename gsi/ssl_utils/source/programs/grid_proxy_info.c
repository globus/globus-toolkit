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

/*********************************************************************
grid_proxy_info.c

Description:
	This program display proxy info, or compare times.

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

static char *rcsid = "$Header$";

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
#include <time.h>
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
                               Type definitions
**********************************************************************/

#define SHORT_USAGE_FORMAT \
"\nSyntax: %s [-help][-f proxyfile][-subject][...][-e [-h H][-b B]]\n"


static char *  LONG_USAGE = \
"\n" \
"    Options\n" \
"    -help, -usage             Displays usage\n" \
"    -version                  Displays version\n" \
"    -file <proxyfile>  (-f)   Non-standard location of proxy\n" \
"    [printoptions]            Prints information about proxy\n" \
"    -exists [options]  (-e)   Returns 0 if valid proxy exists, 1 otherwise\n"\
"\n" \
"    [printoptions]\n" \
"        -subject              Distinguished name (DN) of subject\n" \
"        -issuer               DN of issuer (certificate signer)\n" \
"        -type                 Type of proxy (full or limited)\n" \
"        -timeleft             Time (in seconds) until proxy expires\n" \
"        -strength             Key size (in bits)\n" \
"        -all                  All above options in a human readable format\n"\
"        -text                 All of the certificate\n"\
"        -path                 Pathname of proxy file\n"\
"\n" \
"    [options to -exists]      (if none are given, H = B = 0 are assumed)\n" \
"        -hours H       (-h)   time requirement for proxy to be valid\n" \
"        -bits  B       (-b)   strength requirement for proxy to be valid\n" \
"\n";


#define STATUS_OK               0
#define STATUS_EXPIRED		1
#define STATUS_NOT_FOUND	2
#define STATUS_CANT_LOAD	3
#define STATUS_NO_NAME		4
#define STATUS_BAD_OPTS		5
#define STATUS_INTERNAL		6


/*******************************************************************/
int 
main(int argc, char* argv[])
{
    char *                program;
    int                   strength          = 0;
    int                   bits              = 0;
    int                   hours             = 0;
    int                   exists_flag       = 0;
    int                   hours_flag        = 0;
    int                   bits_flag         = 0;
    int                   is_valid          = 0;
    int                   i;
    char *                argp;
    char *                proxy_file = NULL;
    char *                subject;
    char *                issuer;
    char *                proxy_type;
    proxy_cred_desc *     pcd = NULL;
    time_t                time_after;
    time_t                time_now;
    time_t                time_diff;
    ASN1_UTCTIME *        asn1_time = NULL;
    
#ifndef WIN32
    struct stat           stx;
#endif

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

    /* Parsing phase 1: check all arguments that they are valid */
    for (i=1; i<argc; i++)
    {
	argp = argv[i];

        if (strncmp(argp,"--",2) == 0)
	{
	    if (argp[2] != '\0')
	    {
		args_error(i,argp,"double-dashed options are not allowed");
	    }
	    else
	    {
		i = argc+1;   		/* no more parsing */
		continue;
	    }
	}
	if ((strcmp(argp,"-help")== 0) ||
	    (strcmp(argp,"-usage")== 0)  )
	{
	    args_show_full_usage();
	}
	else if (strcmp(argp,"-version")== 0)
	{
	    args_show_version();
	}
	else if ((strcmp(argp,"-file")==0) ||
		 (strcmp(argp,"-f") == 0)   )
	{
	    if ((i+1 >= argc) || (argv[i+1][0] == '-'))
	    {
		args_error(i,argp,"need a file name argument");
	    }
	    else
		proxy_file = argv[++i];
	}
	else if ((strcmp(argp,"-exists")==0) ||
		 (strcmp(argp,"-e")==0)       )
	{
	    if (exists_flag)
	    {
		args_error(i,argp,"can only be given once");
	    }
	    exists_flag++;
	}
	else if ((strcmp(argp,"-hours")==0) ||
		 (strcmp(argp,"-h")==0)       )
	{
	    if (!exists_flag || hours_flag)
	    {
		args_error(i,argp,"suboption to -exists");
	    }
	    hours_flag++;
	    if ((i+1 >= argc) || (argv[i+1][0] == '-'))
	    {
		args_error(i,argp,"need a non-negative integer argument");
	    }
	    else
		hours = atoi(argv[++i]);
	}
	else if ((strcmp(argp,"-bits")==0) ||
		 (strcmp(argp,"-b")==0)       )
	{
	    if (!exists_flag || bits_flag)
	    {
		args_error(i,argp,"suboption to -exists");
	    }
	    bits_flag++;
	    if ((i+1 >= argc) || (argv[i+1][0] == '-'))
	    {
		args_error(i,argp,"need a non-negative integer argument");
	    }
	    else
		bits = atoi(argv[++i]);
	}
	else if ((strcmp(argp,"-subject")==0)  ||
		 (strcmp(argp,"-issuer")==0)   ||
		 (strcmp(argp,"-strength")==0) ||
		 (strcmp(argp,"-type")==0)     ||
		 (strcmp(argp,"-timeleft")==0) ||
		 (strcmp(argp,"-text")==0) ||
		 (strcmp(argp,"-all")==0) ||
		 (strcmp(argp,"-path")==0))
	{
	    continue;
	}
	else
	    args_error(i,argp,"unrecognized option");
    }

	/* initialize SSLeay and the error strings */
	ERR_load_prxyerr_strings(0);
	SSLeay_add_ssl_algorithms();
    
    pcd = proxy_cred_desc_new();
    
    if (!pcd)
    {
	    fprintf(stderr,"ERROR: problem during internal initialization\n");
	    return STATUS_INTERNAL;
    }

    /* Load proxy */
    if (!proxy_file) 
	proxy_get_filenames(pcd, 1, NULL, NULL, &proxy_file, NULL, NULL);

    if (!proxy_file)
    {
	if (exists_flag)
	    return 1;
	fprintf(stderr,"ERROR: unable to determine proxy file name\n");
	return STATUS_NO_NAME;
    }

    if (stat(proxy_file,&stx) != 0)
    {
	if (exists_flag)
	    return 1;
	fprintf(stderr, "ERROR: file %s not found\n",proxy_file);
	return STATUS_NOT_FOUND;
    }
		
    

    pcd->type=CRED_TYPE_PROXY;

    if (proxy_load_user_cert(pcd, proxy_file, NULL, NULL))
    {
	if (exists_flag)
	    return 1;

	fprintf(stderr,"ERROR: unable to load proxy");
	return STATUS_CANT_LOAD;
    }

    if ((pcd->upkey = X509_get_pubkey(pcd->ucert)) == NULL)
    {
	if (exists_flag)
	    return 1;

	fprintf(stderr,"ERROR: unable to load public key from proxy");
	return STATUS_CANT_LOAD;
    }


    /* The things we will need to know below: subject, issuer,
       strength, validity, type */

    /* subject */
    subject=X509_NAME_oneline(X509_get_subject_name(pcd->ucert),NULL,0);

    /* issuer */
    issuer=X509_NAME_oneline(X509_get_issuer_name(pcd->ucert),NULL,0);

    /* validity: set time_diff to time to expiration (in seconds) */
    asn1_time = ASN1_UTCTIME_new();
    X509_gmtime_adj(asn1_time,0);
    time_now = ASN1_UTCTIME_mktime(asn1_time);
    time_after = ASN1_UTCTIME_mktime(X509_get_notAfter(pcd->ucert));
    time_diff = time_after - time_now ;

    /* strength: set strength to key size (in bits) */
    strength = 8 * EVP_PKEY_size(pcd->upkey);

    /* check if proxy is valid in our own defined sense */
    if (exists_flag)
	is_valid = (time_diff >= (hours*60*60)) && (strength >= bits) ? 0 : 1;
    else
	is_valid = 0;

    /* type: limited or full */
    {
	char *  tstr;
	int     res = 0;
	for (tstr=subject; (int)(*tstr); tstr++)
	{
	    if (strncmp(tstr,"/CN=limited proxy", 17)==0)
		res=1;
	    else if (strncmp(tstr,"/CN=proxy", 9)==0 && res != 1)
		res=2;
	}
	proxy_type = (res) ? ((res==1) ? "limited" : "full") : "not a proxy";
    }

    for (i=1; i<argc; i++)
    {
	argp = argv[i];
	if (strcmp(argp,"-subject") == 0)
	{
	    printf("%s\n",subject);
	}
	else if (strcmp(argp,"-issuer") == 0)
	{
	    printf("%s\n",issuer);
	}
	else if (strcmp(argp,"-timeleft") == 0)
	{
	    printf("%ld\n", (long) ((time_diff >= 0) ? time_diff : -1));
	}
	else if (strcmp(argp,"-type") == 0)
	{
	    printf("%s\n", proxy_type);
	}
	else if (strcmp(argp,"-strength") == 0)
	{
	    printf("%d\n",strength);
	}
	else if (strcmp(argp,"-text") == 0)
	{
		X509_print_fp(stdout,pcd->ucert);
	}
	else if (strcmp(argp,"-all") == 0)
	{
	    printf("subject  : %s\n" 
		   "issuer   : %s\n" 
		   "type     : %s\n" 
		   "strength : %d bits\n"
		   "timeleft : ",
		   subject,
		   issuer,
		   proxy_type,
		   strength );

	    if (time_diff <= 0)
		time_diff = 0;

	    printf("%ld:%02ld:%02ld",
		   (long)(time_diff / 3600),
		   (long)(time_diff % 3600) / 60,
		   (long)time_diff % 60 );

	    if (time_diff > 3600 * 24)
		printf("  (%.1f days)", (float)(time_diff / 3600) / 24.0);
	    printf("\n");
	}
	else if ((strcmp(argp,"-hours") == 0) ||
		 (strcmp(argp,"-bits") == 0) ||
		 (strcmp(argp,"-file") == 0) ||
		 (strcmp(argp,"-f") == 0))
	{
	    i++;
	    continue;
	}
	else if (strcmp(argp,"-path") == 0)
	{
	    printf("path     : %s\n", proxy_file);
	}
    }

    if (argc == 1)
    {
        printf("subject  : %s\n" 
               "issuer   : %s\n" 
               "type     : %s\n" 
               "strength : %d bits\n"
               "timeleft : ",
               subject,
               issuer,
               proxy_type,
               strength );
        
        if (time_diff <= 0)
            time_diff = 0;
        
        printf("%ld:%02ld:%02ld",
               (long)(time_diff / 3600),
               (long)(time_diff % 3600) / 60,
               (long)time_diff % 60 );
        
        if (time_diff > 3600 * 24)
            printf("  (%.1f days)", (float)(time_diff / 3600) / 24.0);
        printf("\n");
    }

    free(subject);
    free(issuer);

    return (is_valid);
}




