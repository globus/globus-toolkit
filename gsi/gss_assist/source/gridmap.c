/******************************************************************************
gridmap.c

Description:
	Functions for interfacing with the gridmapfile.

CVS Information:
	$Source$
	$Date$
	$Revision$
	$Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_gss_assist.h"
#include <stdio.h>
#include <string.h>
#include <pwd.h>

/******************************************************************************
                               Type definitions
******************************************************************************/

typedef struct _gridmap_line_s {
  char *dn;
  char **user_ids;
} gridmap_line_t;

/******************************************************************************
                                Definitions
******************************************************************************/

#define WHITESPACE_CHARS		" \t\n"

#define QUOTING_CHARS			"\""

#define ESCAPING_CHARS			"\\"

#define COMMENT_CHARS			"#"

/* Characters seperating user ids in the gridmap file */
#define USERID_SEP_CHARS		","

/*
 * Characters that terminate a user id in the gridmap file. This
 * is a combination of whitespace and seperators.
 */
#define USERID_TERMINATOR_CHARS		USERID_SEP_CHARS WHITESPACE_CHARS

#ifndef NUL
#define NUL				'\0'
#endif

/*
 * Number of user id slots to allocate at a time
 * Arbitraty value, but must be >= 2.
 */
#define USERID_CHUNK_SIZE		4

/******************************************************************************
                          Module specific prototypes
******************************************************************************/

static int gridmap_default_path(char **ppath);

static int gridmap_find_dn(const char * const dn,
			     gridmap_line_t **gline);

static int gridmap_find_local_user(const char * const local_user,
				     gridmap_line_t **gline);

static int gridmap_parse_line(char *line,
				gridmap_line_t **gline);

static void gridmap_free_gridmap_line(gridmap_line_t *line);

static int gridmap_parse_globusid(const char * unparse,
				    char **pparsed);

static int xdigit_to_value(char xdigit);

/******************************************************************************
                       Define module specific variables
******************************************************************************/
/******************************************************************************
Function:   globus_gss_assist_gridmap.c
Description:
	Routines callable from globus based code to 
	map a globusID to a local unix user

	GRIDMAP environment variable pointing at the
	map file. Defaults to ~/.gridmap 

	A gridmap file is required if being run as root. 
	if being run as a user,it is not required, and defaults to 
	the current user who is running the command. 

	This is the same file used by the gssapi_cleartext
	but will be used with other gssapi implementations which 
	do not use the gridmap file. 

Parameters:
	globus client name who requested authentication 
	*userid returned userid name for local system. 

Returns:

	0 on sucess
	!=0 on failure
******************************************************************************/
int 
globus_gss_assist_gridmap(char * 	globusidp,
			  char ** 	useridp) 
{
    gridmap_line_t *			gline = NULL;


    /* Check arguments */
    if ((globusidp == NULL) ||
	(useridp == NULL))
	return(-1);

    *useridp = NULL;


    if (gridmap_find_dn(globusidp, &gline) != 0)
    {
        /* no gridmap file found -> fail */
	return 1;
    }

    if (gline != NULL)
    {
	if ((gline->user_ids == NULL) ||
	    (gline->user_ids[0] == NULL))
	{
	    /*
	     * If we get here then something in this code is broken
	     * or the gridmap file is badly formatted or, most likely,
	     * both.
	     */
	    return 1;
	}

	/* First user id is default */
	*useridp = strdup(gline->user_ids[0]);

	gridmap_free_gridmap_line(gline);

	if (*useridp == NULL)
	{
	    /* strdup() failed */
	    return 1;
	}
    }
    else
    {
	/* No entry found in gridmap file for this user */
	return 1;
    }

    /* Success */
    return 0;

} /* globus_gss_assist_gridmap() */



/******************************************************************************
Function:   globus_gss_assist_userok.c
Description:
	Check to see if a particular globusid is authorized to access
	the given local user account.

Parameters:
	globusid, the globus id in string form

	userid, the local account that access is sought for

Returns:
	0 on sucess (authorization allowed)
	!=0 on failure or authorization denied

******************************************************************************/
int
globus_gss_assist_userok(
    char *                              globusid,
    char *                              userid)
{
    gridmap_line_t *            gline;
    char **             useridp;
    int                 authorized = 0;


    /* Check arguments */
    if ((globusid == NULL) ||
        (userid == NULL))
        return(-1);

    if (gridmap_find_dn(globusid, &gline) != 0)
    {
        return 1;
    }

    if (gline == NULL)
        return 1;       /* No entry found in gridmap file */

    if (gline->user_ids == NULL)
        return 1;       /* Broken code or misformated gridmap file */

    for (useridp = gline->user_ids; *useridp != NULL; useridp++)
    {
        if (strcmp(*useridp, userid) == 0)
        {
            authorized = 1;
            break;
        }
    }

    gridmap_free_gridmap_line(gline);

    return (authorized ? 0 : 1);

} /* globus_gss_assist_userok() */


/******************************************************************************
Function:   globus_gss_assist_map_local_user.c
Description:
	Routine for returning the default globus ID associated with
        a local user name. This is somewhat of a hack since there is
	not a guarenteed one-to-one mapping. What we do is look for
	the first entry in the gridmap file that has the local
	user as the default login.

Parameters:
	local_user, local username

	globusidp, filled in with pointer to allocated string containing
	globus id string.

Returns:
	0 on sucess
	!=0 on failure

******************************************************************************/
int 
globus_gss_assist_map_local_user(char * 	local_user,
				 char ** 	globusidp) 
{
    gridmap_line_t *			gline = NULL;


    /* Check arguments */
    if ((local_user == NULL) ||
	(globusidp == NULL))
	return(-1);

    *globusidp = NULL;


    if (gridmap_find_local_user(local_user, &gline) != 0)
    {
	/*
	 * We failed to open the gridmap file.
	 */
	return 1;
    }

    if (gline != NULL)
    {
	if (gline->dn == NULL)
	{
	    /*
	     * If we get here then something in this code is broken
	     * or the gridmap file is badly formatted or, most likely,
	     * both.
	     */
	    return 1;
	}

	/* First user id is default */
	*globusidp = strdup(gline->dn);

	gridmap_free_gridmap_line(gline);

	if (*globusidp == NULL)
	{
	    /* strdup() failed */
	    return 1;
	}
    }
    else
    {
	/* No entry found in gridmap file for this user */
	return 1;
    }

    /* Success */
    return 0;

} /* globus_gss_assist_map_local_user() */




/******************************************************************************
                           Internal Functions
******************************************************************************/

/******************************************************************************
Function:   gridmap_default_path
Description:
	Determine and return the path to the gridmap file.

Parameters:
	ppath, a pointer to a pointer that will be set to an allocated
	string.

Returns:
	0 on success, non-zero on error.

******************************************************************************/

static
int
gridmap_default_path(char **		ppath)
{
    char				gridmap[256];


    /* the following logic is taken from the gssapi_cleartext
     * globusfile.c. Since it needs this same information,
     * but other gssapi's may not, we duplicate the parsing
     * of the gridmap file. 
     */
    if (getuid() == 0)
    {
	char *char_p;

	if ( ((char_p = (char*) getenv("GRIDMAP")) != NULL) ||
	     ((char_p = (char*) getenv("GLOBUSMAP")) != NULL) ||
	     ((char_p = (char*) getenv("globusmap")) != NULL) ||
	     ((char_p = (char*) getenv("GlobusMap")) != NULL) ) {

	    strncpy(gridmap, char_p, sizeof(gridmap)) ;

	} else
	    strcpy(gridmap, "/etc/grid-security/grid-mapfile") ;

    }
    else
    {
	char *char_p;

	if ( ((char_p = (char*) getenv("GRIDMAP")) != NULL) ||
	     ((char_p = (char*) getenv("GLOBUSMAP")) != NULL) ||
	     ((char_p = (char*) getenv("globusmap")) != NULL) ||
	     ((char_p = (char*) getenv("GlobusMap")) != NULL) ) {

	    strncpy(gridmap, char_p, sizeof(gridmap)) ;

	}
	else
	{
	    if ( ((char_p = (char*) getenv("home")) != NULL) ||
		 ((char_p = (char*) getenv("Home")) != NULL) ||
		 ((char_p = (char*) getenv("HOME")) != NULL)) {
	  
		strcpy(gridmap, char_p);
		strcat(gridmap, "/.gridmap");

	    } else {
		strcpy(gridmap,".gridmap") ;
	    }
	}	
    }

    /* Make certain that no buffer overflow occurred */
    if (strlen(gridmap) > sizeof(gridmap))
	return -1;

    *ppath = strdup(gridmap);

    if (ppath == NULL)
	return -1;

    return 0;

} /* gridmap_default_path() */


/******************************************************************************
Function:   gridmap_find_dn
Description:
	Locate the entry for the given DN in the default gridmap file.

Parameters:
	dn, the name to search for.

	gline, a pointer to a pointer that will be set to point at
	the gridmap_line_t structure containing the line information.
	Will be set to NULL if the line is not found.

Returns:
	0 on success, non-zero on error.

******************************************************************************/

static
int
gridmap_find_dn(const char * const 		dn,
		  gridmap_line_t **		gline)
{
    char *				gridmap_path = NULL;
    char *				open_mode = "r";
    FILE *				gmap_stream = NULL;
    int					found = 0;
    gridmap_line_t *			gline_tmp;


    /* Check arguments */
    if (dn == NULL)
	goto failure;

    if (gridmap_default_path(&gridmap_path) != 0)
	goto failure;

    gmap_stream = fopen(gridmap_path, open_mode);

    if (gmap_stream == NULL)
	goto failure;

    free(gridmap_path);
    gridmap_path = NULL;

    do
    {
	char 				line[1024];


	if (fgets(line, sizeof(line), gmap_stream) == NULL)
	    break;		/* EOF or error */

	if (gridmap_parse_line(line, &gline_tmp) != 0)
	    continue;		/* Parse error */

	if ((gline_tmp != NULL) && (strcmp(dn, gline_tmp->dn) == 0))
	{
	    found = 1;
	}
	else
	{
	    gridmap_free_gridmap_line(gline_tmp);
	}

    } while (!found);

    fclose(gmap_stream);
    gmap_stream = NULL;

    if (found)
	*gline = gline_tmp;
    else
	*gline = NULL;

    return 0;

 failure:

    if (gridmap_path != NULL)
	free(gridmap_path);

    if (gmap_stream)
	fclose(gmap_stream);

    return -1;

} /* gridmap_find_dn() */



/******************************************************************************
Function:   gridmap_local_user
Description:
	Locate the first entry with the given local user as the default
	in the default gridmap file.

Parameters:
	local_user, the name to search for.

	gline, a pointer to a pointer that will be set to point at
	the gridmap_line_t structure containing the line information.
	Will be set to NULL if the line is not found.

Returns:
	0 on success, non-zero on error.

******************************************************************************/

static
int
gridmap_find_local_user(const char * const	local_user,
			  gridmap_line_t **	gline)
{
    char *				gridmap_path = NULL;
    char *				open_mode = "r";
    FILE *				gmap_stream = NULL;
    int					found = 0;
    gridmap_line_t *			gline_tmp;


    /* Check arguments */
    if (local_user == NULL)
	goto failure;

    if (gridmap_default_path(&gridmap_path) != 0)
	goto failure;

    gmap_stream = fopen(gridmap_path, open_mode);

    if (gmap_stream == NULL)
	goto failure;

    free(gridmap_path);
    gridmap_path = NULL;

    do
    {
	char 				line[1024];


	if (fgets(line, sizeof(line), gmap_stream) == NULL)
	    break;		/* EOF or error */

	if (gridmap_parse_line(line, &gline_tmp) != 0)
	    continue;		/* Parse error */

	if (gline_tmp == NULL)
	{
	    /* Empty line */
	    continue;
	}

	if ((gline_tmp->user_ids != NULL) &&
	    (gline_tmp->user_ids[0] != NULL) &&
	    (strcmp(local_user, gline_tmp->user_ids[0]) == 0))
	{
	    found = 1;
	}
	else
	{
	    gridmap_free_gridmap_line(gline_tmp);
	}

    } while (!found);

    fclose(gmap_stream);
    gmap_stream = NULL;

    if (found)
	*gline = gline_tmp;
    else
	*gline = NULL;

    return 0;

 failure:

    if (gridmap_path != NULL)
	free(gridmap_path);

    if (gmap_stream)
	fclose(gmap_stream);

    return -1;

} /* gridmap_find_local_user() */


  
/******************************************************************************
Function:   gridmap_parse_line
Description:
	Given a line from the gridmap file, parse it returning
	a gridmap_line_t structure. line is modified during parsing.

	The format of the line is expected to be:

	<DN> <userid>[,<userid>[,<userid>...]]

	Leading and trailing whitespace is ignored.

	userids must only have a comma between them, no whitespace.

	Anything after the userids is ignored.

	Anything after an unescaped comment character is ignored.

Parameters:
	line, a pointer to the line from the file (NUL-terminated string)

	gline, a pointer to a pointer that will be set to point at
	the gridmap_line_t structure containing the line information.
	If the line contains no content, gline will be set to NULL.

Returns:
	0 on success, non-zero on error.

******************************************************************************/

static
int
gridmap_parse_line(char * 			line,
		     gridmap_line_t **	gline)
{
    char *				dn_end;
    char *				parsed_dn = NULL;
    char **				userids = NULL;
    int					num_userids = 0;
    int					userid_slots = 0;
    gridmap_line_t *			gline_tmp = NULL;
    

    /* Check arguments */
    if ((line == NULL) ||
	(gline == NULL))
	goto error;

    /* Skip over leading whitespace */
    line += strspn(line, WHITESPACE_CHARS);

    /* Check for comment at start of line and ignore line if present */
    if (strchr(COMMENT_CHARS, *line) != NULL) 
    {
	/* Ignore line, return NULL gline */
	*gline = NULL;
	return 0;
    }
	
    /* Check for empty line */
    if (*line == NUL)
    {
	/* Empty line, return NULL gline. */
	*gline = NULL;
	return 0;
    }

    /* Is DN quoted? */
    if (strchr(QUOTING_CHARS, *line) != NULL)
    {
	/*
	 * Yes, skip over opening quote and look for unescaped
	 * closing double quote
	 */
	line++;
	dn_end = line;

	do
	{
	    dn_end += strcspn(dn_end, QUOTING_CHARS);

	    if (*dn_end == NUL)
		goto error;	/* Missing closing quote */

	    /* Make sure it's not escaped */
	}
	while (strchr(ESCAPING_CHARS, *(dn_end - 1)) != NULL);
    }
    else
    {
	/* No, just find next whitespace */
	dn_end = line + strcspn(line, WHITESPACE_CHARS);

	if (*dn_end == NUL)
	    goto error;	/* Nothing after DN */
    }

    /* NUL terminate DN and parse */
    *dn_end = NUL;

    if (gridmap_parse_globusid(line, &parsed_dn) != 0)
	return -1;

    /* Skip over closing delim and any whitespace after DN */
    line = dn_end + 1;
    line += strspn(line, WHITESPACE_CHARS);

    /* Parse list of unix user ID seperated by USERID_SEP_CHARS */
    while ((*line != NUL) &&
	   (strchr(WHITESPACE_CHARS, *line) == NULL))
    {
	int					userid_len;

	/* Find end of this userid */
	userid_len = strcspn(line, USERID_TERMINATOR_CHARS);

	/* Make sure we have a slot and if not allocate it */
	if ((num_userids + 1 /* new entry */+ 1 /* for NULL */) > userid_slots)
	{
	    char **userids_tmp;


	    userid_slots += USERID_CHUNK_SIZE;

	    userids_tmp = realloc(userids, userid_slots * sizeof(char *));

	    if (userids_tmp == NULL)
		goto error;

	    userids = userids_tmp;
	}
  
	userids[num_userids] = malloc(userid_len + 1 /* for NUL */);

	if (userids[num_userids] == NULL)
	    goto error;

	strncpy(userids[num_userids], line, userid_len);
	userids[num_userids][userid_len] = NUL;

	num_userids++;
	userids[num_userids] = NULL;

	line += userid_len;

	/* If we're on a seperator character, skip over it */
	if (strchr(USERID_SEP_CHARS, *line) != NULL)
	    line++;
    }

    /*
     * There might be more stuff on the line, but we're ignoring
     * it for now.
     */

    /* Ok, build our gridmap_line_t structure */
    gline_tmp = malloc(sizeof(*gline_tmp));

    if (gline_tmp == NULL)
	goto error;

    gline_tmp->dn = parsed_dn;
    gline_tmp->user_ids = userids;

    *gline = gline_tmp;
  
    return 0;

 error:
    if (parsed_dn != NULL)
	free(parsed_dn);

    if (userids != NULL) {
	char **userids_tmp = userids;

	while (*userids_tmp != NULL)
	    free(*userids_tmp++);

	free(userids);
    }

    if (gline_tmp != NULL)
	free(gline_tmp);

    return -1;

} /* gridmap_parse_line() */



/******************************************************************************
Function:   gridmap_free_gridmap_line
Description:
	Frees all memory allocated to a gridmap_line_t structure.

Parameters:
	gline, pointer to structure to be freed.

Returns:
	Nothing.
******************************************************************************/
static
void
gridmap_free_gridmap_line(gridmap_line_t *gline)
{
  if (gline != NULL)
  {
    if (gline->dn != NULL)
      free(gline->dn);

    if (gline->user_ids != NULL)
    {
      char **userids_tmp = gline->user_ids;

      while (*userids_tmp != NULL)
	free(*userids_tmp++);

      free(gline->user_ids);
    }

    free(gline);
  }

} /* gridmap_free_gridmap_line() */



/******************************************************************************
Function:   gridmap_parse_globusid
Description:
	Given a pointer to a string containing the globusid from the
	gridmap file, return a pointer to a string containing the
	parsed from of the id.

	Specifically handle backslashed characters - e.g. '\\',
	'\x4a' or '\37'.

Parameters:
	unparsed, pointer to unparsed string

	pparsed, pointer to pointer that should be set to point at
	allocated parsed string

Returns:
	0 on success
	non-zero on error.

******************************************************************************/
static
int
gridmap_parse_globusid(
    const char *			unparsed,
    char **				pparsed)
{
    /* Is the current character escaped? (Previous char was backslash) */
    int					escaped = 0;

  /* Buffer we are putting resulting name into */
    char *				buffer = NULL;

    /* Buffer's length in bytes */
    int					buffer_len = 0;

    /* And our current position in buffer */
    int					buffer_index = 0;

    /* Character we're currently looking at */
    char					unparsed_char;


    /*
   * Check input parameters for legality
   */
    if ((unparsed == NULL) ||
	(pparsed == NULL))
	return -1;

    buffer_len = strlen(unparsed);

    buffer = malloc(buffer_len);

    if (buffer == NULL)
	return -1;

  /*
   * Walk through the name, parsing as we go
   */
    while ((unparsed_char = *(unparsed++)) != NUL)
    {
	/* Unescaped backslash */
	if (strchr(ESCAPING_CHARS, unparsed_char) && !escaped)
	{
	    escaped = 1;
	    continue;
	}

	/* Escaped hex character - e.g. '\xfe' */
	if ((unparsed_char == 'x') && escaped)
	{
	    if (isxdigit(*unparsed) &&
		isxdigit(*(unparsed + 1)))
	    {
		/* Set unparsed_char to value represented by hex value */
		unparsed_char =
		    xdigit_to_value(*unparsed) << 4 +
		    xdigit_to_value(*(unparsed + 1));
	
		unparsed += 2;
	    }
	    /* else just fall through */
	}

	/*
     * Ok, we now have the character in unparsed_char to be appended
     * to our output string.
     *
     * First, make sure we have enough room in our output buffer.
     */
	if ((buffer_index + 1 /* for NUL */) >= buffer_len)
	{
	    /* Grow buffer */
	    char *tmp_buffer;

	    buffer_len *= 2;

	    tmp_buffer = realloc(buffer, buffer_len);

	    if (tmp_buffer == NULL)
	    {
		free(buffer);
		return -1;
	    }

	    buffer = tmp_buffer;
	}

	buffer[buffer_index++] = unparsed_char;
	buffer[buffer_index] = NUL;

	escaped = 0;
    }

    /* XXX What if escaped == 1 here? */

  /* Success */

    *pparsed = buffer;

    return 0;

} /* gridmap_parse_globusid() */



/******************************************************************************
Function:   xdigit_to_value
Description:
	Convert a ascii character representing a hexadecimal digit
	into a integer.

Parameters:
	xdigit, character contain the hex digit.

Returns:
	value contained in xdigit, or -1 on error.

******************************************************************************/

static int
xdigit_to_value(
    char 				xdigit)
{
    if ((xdigit >= '0') && (xdigit <= '9'))
	return (xdigit - '0');

    if ((xdigit >= 'a') && (xdigit <= 'f'))
	return (xdigit - 'a' + 0xa);

    if ((xdigit >= 'A') && (xdigit <= 'F'))
	return (xdigit - 'A' + 0xa);

    /* Illegal digit */
    return -1;
} /* xdigit_to_value() */



