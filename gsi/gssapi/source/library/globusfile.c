#if 0
/* OBSOLETE */
/**********************************************************************

globusfile.c 

Description:
	Routine to find the Globusid in the user's directory.
	This is a hold over from the cleartext version and may
	be droped, infavor of using the certificarte subject name

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

#include "gssapi_ssleay.h"
#include "globusfile.h"
#include "gssutils.h"

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/**********************************************************************
Function: retrieve_globusid

Description:
	find the globusid by looking in the user's directories, i
	or environment

Parameters:
   
Returns:
**********************************************************************/

tis_gss_ret_t
retrieve_globusid
(gss_name_desc** globusid_name) {
  FILE *fd ;
  char globus_name[256], *char_p, globusid[256] ;
  gss_buffer_desc buffer ;
  int return_value ;

  globus_name[255] = globusid[255] = '\0'; 

  /* ADDED kcsmilak 09/02/97 */
  /* If running as root, look in /etc/globusid, if not there, fail */
  if (getuid() == 0) {

    char *char_p, filename[256];
	filename[255]='\0';

    if ( ((char_p = (char*) getenv("GLOBUSID")) != NULL) ||
	   ((char_p = (char*) getenv("globusid")) != NULL) ||
	   ((char_p = (char*) getenv("GlobusID")) != NULL)) {
      strncpy(globus_name, char_p, 255) ;
    } else 
    {
    strcpy(filename, "/etc/globusid") ;

    if ((fd = fopen(filename, "r")) == NULL) {
#ifdef DEBUG
      fprintf(stderr,
	      "E Unable to access [%s]\n",globusid) ;
#endif
      return TIS_GSS_FAILURE ;

    } else {

      do {
	return_value = fscanf(fd, "%255s\n",globus_name) ;
      } while (return_value == 0 && return_value != EOF) ;
    
      if (return_value == EOF) {
	fprintf(stderr,
		"E Unable to find globusid in globusid file\n") ;
	return TIS_GSS_FAILURE ;
      }
#ifdef DEBUG
  fprintf(stderr,"Using [%s] (from /etc/globusid)\n", globus_name) ; 
#endif /* DEBUG */
    }
    }
  } else {
    /* end ADDED */

    /* check if in environment. else ... */

    if ( ((char_p = (char*) getenv("GLOBUSID")) != NULL) ||
	 ((char_p = (char*) getenv("globusid")) != NULL) ||
	 ((char_p = (char*) getenv("GlobusID")) != NULL)) {
      strncpy(globus_name, char_p, 255) ;
#ifdef DEBUG
      fprintf(stderr,"Using [%s] (from environment)\n", globus_name) ; 
#endif /* DEBUG */
    } else {

      {
	char *char_p, filename[256];
    filename[255]='\0';

	if ( ((char_p = (char*) getenv("home")) != NULL) ||
	     ((char_p = (char*) getenv("Home")) != NULL) ||
	     ((char_p = (char*) getenv("HOME")) != NULL)) {

	  strncpy(filename, char_p, 255-10) ;
	  strcat(filename, "/") ;
	  strcat(filename, ".globusid") ;
	  strcpy(globusid, filename) ;
	} else {
	  strcpy(globusid, ".globusid") ;
	}
      }
      if ((fd = fopen(globusid, "r")) == NULL) {
#ifdef DEBUG
	fprintf(stderr,
		"E Unable to access [%s]\n",globusid) ;
#endif

	/* ADDED kcsmilak 09/02/97 */
	if (getuid() == 0 ) {
	  return TIS_GSS_FAILURE ;
	}
	/* end ADDED */
	do {
	  fprintf(stderr,"  Please enter your GlobusID: ") ;
	  return_value = scanf("%255s",globus_name) ;
	} while (return_value == 0 ) ;
#ifdef DEBUG
	fprintf(stderr,"Using [%s] (from user input)\n", globus_name) ; 
#endif /* DEBUG */
      } else {

	do {
	  return_value = fscanf(fd, "%255s\n",globus_name) ;
	} while (return_value == 0 && return_value != EOF) ;
    
	if (return_value == EOF) {
	  fprintf(stderr,
		  "E Unable to find globusid in .globusid file\n") ;
	  return TIS_GSS_FAILURE ;
	}
#ifdef DEBUG
	fprintf(stderr,"Using [%s] (from .globusid)\n", globus_name) ; 
#endif /* DEBUG */
      }
    }
  } /* if..else */
   
   buffer.value = globus_name;
   buffer.length = strlen(globus_name);

  {
    OM_uint32 inv_minor_status = 0, inv_major_status = 0 ;
    inv_major_status = gss_import_name(&inv_minor_status,
				       &buffer,
				       GSS_C_NO_OID,
				       (gss_name_t) globusid_name) ;
  }

  return TIS_GSS_SUCCESS ;

}
#endif
