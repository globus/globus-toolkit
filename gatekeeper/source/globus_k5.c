/******************************************************************************

grami_ggg_k5_simple.c

Description:
	globus to Kerberos simple authentication module. 

	When exec-ed by the gram_gatekeeper after 
	authentiicating the globus user, this routine 
	will attempt to issue a K5 kinit for the user. 

	The args passed to this routine will not be used,
	but will be passed onto the job manager. The first parameter
	must be the path to the job manager. (Much like what wrapper
	or inetd does.)

	It is expected that the environment will contain the
	GLOBUSID=globusid of the user and USER=userid for the local 
	unix system.  This program is normaly run as root,
	and will seteuid before execing the other modules. 

	If not run as root, the user should have started the gatekeeper, 	
	and should already have gotten a K5 credential. 

	The parameters to use and the mapping for the
	globus to K5 user are located in the 
	.globuskmap file. 

	Format of the .globuskmap file:
		 globus_user kinit command line ... including k5 principal
         This looks a lot like the inetd.conf. 
	This is designed to be a simple interface, and no attempt
	to parse or use the command info is made. 
	This allows for other commands to be used instead
	of kinit. 

	This will only be attempted if the gatekeeper
	is run as root, as if the user has started 
	the gatekeeper, then he should have a K5 
	credentials already. 

CVS Information:
	$Source$
	$Date$
	$Revision$
	$Author$

******************************************************************************/
/*****************************************************************************
Include header files
******************************************************************************/
#include "nexus_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <pwd.h>
#include <string.h>
#include <malloc.h>
#include <sys/wait.h>
#include <sys/stat.h>

/******************************************************************************
                               Type definitions
******************************************************************************/
#ifndef K5AFSLOGIN
#define K5AFSLOGIN "/krb5/sbin/k5afslogin"
#endif

#ifndef K5DCELOGIN
#define K5DCELOGIN "/krb5/sbin/k5dcelogin"
#if defined(sun)
#define K5DCELIB "/usr/lib/libdce.so"
#else
#define K5DCELIB "/usr/lib/libdce.a"
#endif
#endif

#ifdef DEBUG
#define DEEDEBUG(A) fprintf(stderrX,A)
#define DEEDEBUG2(A,B) fprintf(stderrX,A,B)
FILE *stderrX;
#else
#define DEEDEBUG(A)
#define DEEDEBUG2(A,B)
#endif


/******************************************************************************
                          Module specific prototypes
******************************************************************************/
static int
grami_ggg_k5_globuskmap( char * globusid, char ** params);

static int
grami_ggg_k5_tokenize(char * command, char ** args, int n);

static int
grami_ggg_k5_exec(char *args[]);
/******************************************************************************
                       Define module specific variables
******************************************************************************/

/******************************************************************************
Function:   grami_ggg_k5_globuskmap()
Description:
	Given a globusID, find the command to be issued.

Parameters:
	globusID
	A pointer to a char*. will strduped with command
Returns:
******************************************************************************/
static int
grami_ggg_k5_globuskmap( char * globusid, char ** command)
{

	FILE * fd;
	char   line[BUFSIZ];
	char   globuskmap[256] ;
	char   f_globusid[256]; 
	int    rc;
	int	   i;
    int    offset;

	*command = NULL;

  /* the following logic is taken from the gssapi_cleartext
   * globusfile.c. Since it is almost the same logic.
   * of the globusmap file. 
   */
  {
    char *char_p, filename[256];
    if ( ((char_p = (char*) getenv("GLOBUSKMAP")) != NULL) ) {
	  if (strlen(char_p) > 255) {
		fprintf(stderr,"GLOBUSKMAP file name to long\n");
		return (-1);
	  }
      strcpy(filename, char_p) ;
      strcpy(globuskmap, filename) ;
    } else 
    if ( getuid() && ((char_p = (char*) getenv("HOME")) != NULL) ) {
      if (strlen(char_p) > 255-12) {
	    fprintf(stderr,"HOME to long for globuskmap\n");
		return (-1);
	  }
      strcpy(filename, char_p) ;
      strcat(filename, "/") ;
      strcat(filename, ".globuskmap") ;
      strcpy(globuskmap, filename) ;
	} else
	if (getuid == 0) {
	  strcpy(globuskmap, "/etc/globuskmap");
	} else {
	  return(-1);   /* no file return */
    }
  }

     DEEDEBUG2("Globuskmap = %s\n", globuskmap);

  /* the following is not similiar to the globusfile.c
   */

  if ((fd = fopen(globuskmap, "r")) != NULL) {

    while(fgets(line, sizeof(line), fd)) {
      i = strlen(line);
	  if (line[0] != '#') {   /* comment line */
	    if (line[i - 1] == '\n')
		  line[i - 1] = '\0';
        rc = sscanf(line, "%s%n %n", f_globusid, &offset, &offset);
        if (rc == 1) {
	      if (!strcmp(globusid, f_globusid)) {
		    *command = strdup(&line[offset]);
            DEEDEBUG2("Globus command= %s\n",*command);
            close(fd);
		    return(0);
 
	      }
	    }
	  }
	}
	close(fd);
	return(-1); /* not found */	
  }
  return(-2);   /* open failed */
}
/******************************************************************************
Function:   grami_ggg_k5_tokenize()
Description:
Parameters:
Returns:
******************************************************************************/

static int
grami_ggg_k5_tokenize(char * command, char ** args, int n)
{
  int i,j,k;
  char * cp;
  char * next;
  char ** arg;

  arg = args;
  i = n - 1;
  
  for (cp = strtok(command, " \t\n"); cp != 0; cp = next) {
    *arg = cp;
	i--;
    if (i == 0)
	  return(-1); /* to many args */
    arg++;
	next = strtok(NULL, " \t\n");
  }
  *arg = (char *) 0;
  return(0);
}

/******************************************************************************
Function:   grami_ggg_k5_exec()
Description:
Parameters:
Returns:
******************************************************************************/
static int
grami_ggg_k5_exec(char *args[])
{

  int i,j;
  int pid;
  int err; 
  char *path;
  char * cp;

#define WAIT_USES_INT
#ifdef  WAIT_USES_INT
  int wait_status;
#else   /* WAIT_USES_INT */
  union wait wait_status;
#endif  /* WAIT_USES_INT */



  pid = fork();
  if (pid <0) 
   return(-1);

  if (pid == 0) {  /* child process */

    path = strdup(args[0]);
    cp = strrchr(path, '/');
    if (cp)
      cp++;
    else
      cp = path;
 
    args[0] = cp;

    execv(path, args);

    exit(127);      /* in case execl fails */
  } 

  /* parent, wait for child to finish */

  wait_status = 0;
#ifdef  HAVE_WAITPID
  err = waitpid((pid_t) pid, &wait_status, 0);
#else   /* HAVE_WAITPID */
  err = wait4(pid, &wait_status, 0, (struct rusage *) NULL);
#endif  /* HAVE_WAITPID */

  /* if it worked or failed, continue on. */
  return(wait_status);
}

/******************************************************************************
Function:   grami_ggg_k5_kinit()
Description:
Parameters:
Returns:
******************************************************************************/
int
grami_ggg_k5_kinit(char * globus_client)
{

  int rc;
  int i;
  char ccname[100];
  char * command;
  char * args[100];
  struct passwd *pw;
  struct stat stx;

  if ((rc = grami_ggg_k5_globuskmap(globus_client, &command)))
    return(rc); /* not found, or nothing to do */
 
  if (!command)
    return(0); /* no command */
  
  if ((rc = grami_ggg_k5_tokenize( command, args, 100)))
	return(rc);

  i = 0;
  do {
   sprintf(ccname,"FILE:/tmp/krb5cc_p%d%d",getpid(),i++);
  }
  while(stat(ccname+5,&stx) == 0);

  setenv("KRB5CCNAME", ccname, 1);

  rc = grami_ggg_k5_exec(args);

  /*
   * Make sure the creds cache is owned by the user. 
   * If we ran kinit as root, root will own it. 
   */

  if (rc == 0 && getuid() == 0) {
	if ((pw = getpwnam(getenv("USER"))) != NULL) {
	  (void) chown(ccname+5,pw->pw_uid, pw->pw_gid);
    }
  }

  DEEDEBUG2("ggg_k5_exec rc = %d\n", rc);
  return(rc);
}

/******************************************************************************
Function:   main()
Description:
Parameters:
Returns:
******************************************************************************/
main(int argc, char *argv[])
{
    int i;
    char *ccname;
	char *globusid;
	char *user;
    char *newpath;
    char *cp;
    char **ap;
    char **newargv;
    struct stat stx;
    extern int optind;
    extern char *optarg;
    int      ch;
	uid_t	 myuid;
	uid_t    luid;
	struct passwd *pw;

#ifdef DEBUG
	stderrX = stderr;
 /* stderrX = fopen("/tmp/k5gram.debug","w"); */
#endif

	myuid = getuid();  /* get our uid, to see if we are root. */
    DEEDEBUG2("k5gram uid = %d\n", myuid);

	/* we will need to copy the args, and may add the k5declogin 
	 * and k5afslogin before. So get three extra. 
	 */

    if ((newargv = calloc(argc + 3, sizeof(argv[0]))) == NULL) {
        fprintf(stderr,"Unable to allocate new argv\n");
        exit(1);
    }
    ap = newargv;


#ifdef DEBUG
    {
      int i;
      fprintf(stderrX,"k5gram args: ");
      i = 0;
      while (argv[i]) {
        fprintf(stderrX,"%s ",argv[i]);
        i++;
      }
      fprintf(stderrX,"\n");
    }
#endif

    ccname = getenv("KRB5CCNAME");

    /* If there is a cache, then the user must have 
	 * started the gatekeeper on thier own. So
	 * don't try and get a K5 cache for them.  
     */

    if (ccname == NULL) {

	  globusid = getenv("GLOBUSID");
	  if (globusid == NULL)
		goto done;  /* Can't do globus-to-k5 without the globusid */
      DEEDEBUG2("GLOBUSID = %s\n",globusid);

	  user = getenv("USER");
	  if (user == NULL)
	    goto done; 
      DEEDEBUG2("USER = %s\n",user);

	  if (grami_ggg_k5_kinit(globusid) == 0) {
	   ccname = getenv("KRB5CCNAME");
	  }

	  /* even if the above failed, we want to continue */
	
    }

	if (ccname) {
      DEEDEBUG2("KRB5CCNAME = %s\n",ccname);

      /* test if this machine has DCE and k5dcelogin is available.
       * if so put the k5dcelogin program on the list to call
       */

      if ((stat(K5DCELIB,&stx) == 0) &&
          (stat(K5DCELOGIN,&stx) == 0)) {
          *ap++ = K5DCELOGIN;
          DEEDEBUG2("Will try %s\n",K5DCELOGIN);
      }

      /* if this system has AFS and not a NFS/AFS translator
       * put it on the list too
       */


      if ((stat("/afs",&stx) == 0) &&
          (stat(K5AFSLOGIN,&stx) == 0) &&
          (stat("/usr/vice/etc/ThisCell",&stx) == 0)) {
          *ap++ = K5AFSLOGIN;

          DEEDEBUG2("Will try %s\n",K5AFSLOGIN);
      }
	}


 done:
    unsetenv("GLOBUSKMAP"); /* dont pass on */

	/* before continuing on, if we were run as root, 
	 * we will seteuid
	 */

	if (!myuid) {
	  if ((pw = getpwnam(user)) == NULL)
		exit(2); /* have to fail, since cant run as root */

	  setuid(pw->pw_uid);

    }

    /* copy over the rest of the argument list.
     * gram_gatekeeper will have placed the path to the job_manager
	 * as arg[1]. 
     */

    for (i = 1; i<argc; i++) {
        *ap++ = argv[i];
    }
    *ap = 0;   /* null as last */

    /* newargv[0] has the fully qualified name of the program to exec.
     * either it is K5DCELOGIN, K5AFSLOGIN, or the job_manager program
     * this was specified by the gatekeeper
     * We will parse to get the new argv[0] and the path.
     * we then exec the program with the rest of the parameters.
     */

    newpath = strdup(newargv[0]);

    cp = strrchr(newpath, '/');
    if (cp)
      cp++;
    else
      cp = newpath;

    newargv[0] = cp;

    DEEDEBUG2("calling the program %s \n",newpath);

#ifdef DEBUG
	/* fclose(stderrX); */
#endif

      execv(newpath,newargv);

    /* only reachable if execl fails */

    fprintf(stderr, "Exec of %s failed: \n", newpath);
        exit(1);
}
