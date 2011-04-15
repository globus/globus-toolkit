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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file module.c
 * GSSAPI module activation code
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */
#endif

#include "globus_i_gss_assist.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_cert_utils.h"
#include "globus_callout.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
typedef struct _gridmap_line_s {
  char *dn;
  char **user_ids;
} globus_i_gss_assist_gridmap_line_t;

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

#define GLOBUS_GENERIC_MAPPING_TYPE     "globus_mapping"
#define GLOBUS_GENERIC_AUTHZ_TYPE       "globus_authorization"

/*
 * Number of user id slots to allocate at a time
 * Arbitraty value, but must be >= 2.
 */
#define USERID_CHUNK_SIZE		4

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

static 
globus_result_t
globus_i_gss_assist_gridmap_find_dn(
    const char * const                  dn,
    globus_i_gss_assist_gridmap_line_t **                   
                                        gline);

static 
globus_result_t
globus_i_gss_assist_gridmap_find_local_user(
    const char * const                  local_user,
    globus_i_gss_assist_gridmap_line_t **                   
                                        gline);

static 
globus_result_t
globus_i_gss_assist_gridmap_parse_line(
    char *                              line,
    globus_i_gss_assist_gridmap_line_t **                   
                                        gline);

static void 
globus_i_gss_assist_gridmap_line_free(
    globus_i_gss_assist_gridmap_line_t *                    
                                        line);

static
globus_result_t 
globus_i_gss_assist_gridmap_parse_globusid(
    const char *                        unparse,
    char **                             pparsed);

static int 
globus_i_gss_assist_xdigit_to_value(
    char                                xdigit);

static
globus_result_t
globus_l_gss_assist_gridmap_lookup(
    gss_ctx_id_t                        context,
    char *                              service,
    char *                              desired_identity,
    char *                              identity_buffer,
    unsigned int                        identity_buffer_length);
  
static
globus_result_t
globus_l_gss_assist_line_length(
    FILE *                              fp,
    size_t *                            len);

#endif



/******************************************************************************
                       Start of gridmapdir functions

 These all use the environment variable GRIDMAPDIR
  (a) if not set, then the gridmapdir functions are not used
  (b) the value it is set to defines the gridmap directory
      (eg export GRIDMAPDIR=/etc/grid-security/gridmapdir)

******************************************************************************/

#include <utime.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <sys/types.h>

/******************************************************************************
Function:   gridmapdir_otherlink
Description:
        find another link in GRIDMAPDIR to the same inode as firstlink
        and change the modification time of firstlink to now (so that we
        always know when this pair was last used)
        
Parameters:
        firstlink, the filename of the link we already know

Returns:
        a pointer to the other link's filename (without path) or NULL if none
        found (this is malloc'd and will need freeing)

******************************************************************************/
static char 
*gridmapdir_otherlink(char *   firstlink)
{
     int            ret;
     char           *firstlinkpath, *otherlinkdup, *otherlinkpath,
                    *gridmapdir;
     struct dirent  *gridmapdirentry;
     DIR            *gridmapdirstream;
     struct stat    statbuf;
     ino_t          firstinode;

     gridmapdir = getenv("GRIDMAPDIR");
     if (gridmapdir == NULL) return NULL;
     
     firstlinkpath = malloc(strlen(gridmapdir) + 2 + strlen(firstlink));
     sprintf(firstlinkpath, "%s/%s", gridmapdir, firstlink);     
     ret = stat(firstlinkpath, &statbuf);
     free(firstlinkpath);   
     if (ret != 0) return NULL;
     if (statbuf.st_nlink != 2) return NULL;
     
     firstinode = statbuf.st_ino; /* save for comparisons */
          
     gridmapdirstream = opendir(gridmapdir);

     if (gridmapdirstream != NULL)
     {
         while ((gridmapdirentry = readdir(gridmapdirstream)) != NULL)
         {       
                 if (strcmp(gridmapdirentry->d_name, firstlink) == 0) continue;
           
                 otherlinkpath = malloc(strlen(gridmapdir) + 2 + 
                                        strlen(gridmapdirentry->d_name));
                 sprintf(otherlinkpath, "%s/%s", gridmapdir, 
                                            gridmapdirentry->d_name);

                 ret = stat(otherlinkpath, &statbuf);     
                 if ((ret == 0) && (statbuf.st_ino == firstinode))
                 {
                      utime(otherlinkpath, (struct utimbuf *) NULL);
                      free(otherlinkpath);
                      otherlinkdup = strdup(gridmapdirentry->d_name);
                      closedir(gridmapdirstream);     
                      return otherlinkdup;
                 }
                 else free(otherlinkpath);
         }
         
         closedir(gridmapdirstream);     
     }

     return NULL;
}

/******************************************************************************
Function:   gridmapdir_urlencode
Description:
        Convert string to URL encoded and return pointer to the encoded
        version, obtained through malloc. Calling routine must free
        this. Here "URL encoded" means anything other than an isalnum()
        goes to %HH where HH is its ascii value in hex; also A-Z => a-z 
        This name is suitable for filenames since no / or spaces.

Parameters:
        rawstring, the string to be converted

Returns:
        a pointer to the encoded string or NULL if the malloc failed

******************************************************************************/
static char 
*gridmapdir_urlencode(char * rawstring)
{
     int          encodedchar = 0, rawchar = 0;
     char *       encodedstring;
     
     encodedstring = (char *) malloc(3 * strlen(rawstring) + 1);
     
     if (encodedstring == NULL) return (char *) NULL;

     while (rawstring[rawchar] != '\0')
     {
           if (isalnum(rawstring[rawchar]))
           {
               encodedstring[encodedchar] = tolower(rawstring[rawchar]);
               ++rawchar;
               ++encodedchar;
           }
           else
           {
               sprintf(&encodedstring[encodedchar], "%%%02x", 
                                               rawstring[rawchar]);
               ++rawchar;
               encodedchar = encodedchar + 3;
           }        
     }

     encodedstring[encodedchar] = '\0';
     
     return encodedstring;
}

/******************************************************************************
Function:   gridmapdir_newlease
Description:
        Search for an unleased local username to give to the globus user
        corresponding to encodedfilename, and then lease it.

Parameters: 
        encodedfilename, URL-encoded globus client name and pathname of 
           the globus user who requested authentication 
        usernameprefix, the prefix of acceptable usernames (or "\0")

Returns:
        no return value
******************************************************************************/

void
gridmapdir_newlease(char *     encodedglobusidp,
                    char *     usernameprefix)
{
     int            ret;
     char           *userfilename, *encodedfilename, *gridmapdir;
     struct dirent  *gridmapdirentry;
     DIR            *gridmapdirstream;
     struct stat    statbuf;
     
     gridmapdir = getenv("GRIDMAPDIR");
     if (gridmapdir == NULL) return;

     encodedfilename = malloc(strlen(gridmapdir) + (size_t) 2 + 
                              strlen(encodedglobusidp));
     sprintf(encodedfilename, "%s/%s", gridmapdir, encodedglobusidp);

     gridmapdirstream = opendir(gridmapdir);

     while ((gridmapdirentry = readdir(gridmapdirstream)) != NULL)
     {
       /* we dont want any files that dont look like acceptable usernames */
       if ((*(gridmapdirentry->d_name) == '%') || 
           (strcmp(gridmapdirentry->d_name, "root") == 0))   continue;
       else if (*(gridmapdirentry->d_name) == '.')           continue;
       else if (index(gridmapdirentry->d_name, '~') != NULL) continue;
       else if (strncmp(gridmapdirentry->d_name, usernameprefix,
                        strlen(usernameprefix)) != 0)        continue;

       userfilename = malloc(strlen(gridmapdir) + (size_t) 2 + 
                             strlen(gridmapdirentry->d_name));
       sprintf(userfilename, "%s/%s", gridmapdir, gridmapdirentry->d_name);
       stat(userfilename, &statbuf);
       
       if (statbuf.st_nlink == 1) /* this one isnt leased yet */
       {   
           ret = link(userfilename, encodedfilename);
           free(userfilename);
           if (ret != 0) 
           {
               /* link failed: this is probably because a VERY lucky
                  other process has obtained a lease for encodedfilename 
                  while we were faffing around */
               closedir(gridmapdirstream);
               free(encodedfilename);
               return;
           }
     
           stat(encodedfilename, &statbuf);
           if (statbuf.st_nlink > 2) 
           {
              /* two globusIDs have grabbed the same username: back off */
              unlink(encodedfilename);
              continue;
           }

           closedir(gridmapdirstream);
           free(encodedfilename);
           return; /* link worked ok, so return */
       }
       else free(userfilename); /* already in use, try next one */
     }
     
     closedir(gridmapdirstream);
     free(encodedfilename);
     return; /* no unleased names left: give up */     
}
     
/******************************************************************************
Function:   gridmapdir_userid
Description:
        This is equivalent to globus_gss_assist_gridmap but for the dynamic
        user ids in the gridmapdir: maps a globusID to a local unix user id,
        either one already leased, or calls gridmapdir_newlease() to obtain 
        a new lease. This is called by globus_gss_assist_gridmap if the 
        local user id in the static gridmap file begins . (for a dynamic id)

Parameters: 
        globusidp, globus client name who requested authentication 
        usernameprefix, prefix of the local usernames which would 
               be acceptable (or "\0" )
        *userid returned userid name for local system. 

Returns:
       
        0 on success
        !=0 on failure

******************************************************************************/

static int
gridmapdir_userid(char *     globusidp,
                  char *     usernameprefix,
                  char **    useridp)
{
     char             *encodedglobusidp;
     
     if (getenv("GRIDMAPDIR") == NULL) return 1; /* GRIDMAPDIR defined? */

     if (globusidp[0] != '/') return 1; /* must be a proper subject DN */
     
     encodedglobusidp = gridmapdir_urlencode(globusidp);

     *useridp = gridmapdir_otherlink(encodedglobusidp);

     if (*useridp == NULL) /* maybe no lease yet */
     {
         gridmapdir_newlease(encodedglobusidp, usernameprefix); 
         /* try making a lease */
         
         *useridp = gridmapdir_otherlink(encodedglobusidp); 
         /* check if there is a now a lease - possibly made by someone else */

         if (*useridp == NULL) 
         {
             free(encodedglobusidp);
             return 1; /* still no good */
         }
     }

     free(encodedglobusidp);
     return 0;
}

/******************************************************************************
Function:   gridmapdir_globusid
Description:
        This is equivalent to globus_gss_assist_map_local_user but for the 
        dynamic user ids in the gridmapdir: search through leases to find
        which globusID corresponds to a local unix user id.
        This is called by globus_gss_assist_map_local_user 

Parameters: 
        globus client name who requested authentication 
        *userid returned userid name for local system. 

Returns:
       
        0 on success
        !=0 on failure

******************************************************************************/

static int
gridmapdir_globusid(char *     useridp,
                    char **    globusidp)
{
     int              encodedptr = 0, decodedptr = 0;
     char             *encodedglobusidp;

     if (useridp == NULL || globusidp == NULL)
     {
         return 1;
     }
     
     if (useridp[0] == '/') return 1; /* must not be a subject DN */
     
     encodedglobusidp = gridmapdir_otherlink(useridp);

     if (encodedglobusidp == NULL) return 1; /* not leased */
     
     *globusidp = malloc(strlen(encodedglobusidp));
     
     while (encodedglobusidp[encodedptr] != '\0')
     {
            if (encodedglobusidp[encodedptr] != '%')
            {
                (*globusidp)[decodedptr] = encodedglobusidp[encodedptr];
                ++encodedptr;
                ++decodedptr;
            }
            else /* must be a %HH encoded character */
            {
                /* even paranoids have enemies ... */
                if (encodedglobusidp[encodedptr+1] == '\0') break;
                if (encodedglobusidp[encodedptr+2] == '\0') break;

                (*globusidp)[decodedptr] = 
                   globus_i_gss_assist_xdigit_to_value(encodedglobusidp[encodedptr+1]) * 16 +
                   globus_i_gss_assist_xdigit_to_value(encodedglobusidp[encodedptr+2]);

                encodedptr = encodedptr + 3;
                ++decodedptr;
            }
     }
              
     free(encodedglobusidp);
     (*globusidp)[decodedptr] = '\0';
     return 0;
}

/******************************************************************************
Function:   gridmapdir_userok
Description:
        This is equivalent to globus_gss_assist_userok but for the dynamic
        user ids in the gridmapdir: finds the local unix username leased to 
        a globusID and compare with the username being checked.
        This is called by globus_gss_assist_userok if the local user id in
        the static gridmap file is -  (for a dynamic id)

Parameters: 
        globus client name who requested authentication 
        userid to be checked

Returns:
        0 on success (authorization allowed)
        !=0 on failure or authorization denied
                
******************************************************************************/

static int
gridmapdir_userok(char *     globusidp,
                  char *     userid)
{
     char                    *encodedglobusidp, *leasedname;
     
     if (globusidp[0] != '/') return 1; /* must be a proper subject DN */
     
     encodedglobusidp = gridmapdir_urlencode(globusidp);
     leasedname       = gridmapdir_otherlink(encodedglobusidp);
     free(encodedglobusidp);

     if (leasedname == NULL) return 1;

     if (strcmp(userid, leasedname) == 0)
     {
         free(leasedname);
         return 0;
     }
     else
     {
         free(leasedname);
         return 1;
     }
}

/******************************************************************************
                     End of gridmapdir functions
******************************************************************************/

/**
 * @brief Look up the default mapping for a Grid identity in a gridmap file
 * @ingroup globus_gsi_gss_assist
 * 
 * @details
 * The globus_gss_assist_gridmap() function parses the default gridmap file
 * and modifies its @a useridp parameter to point to a copy of the string
 * containing the default local identity that the grid identity is mapped to.
 * If successful, the caller is responsible for freeing the string pointed
 * to by @a useridp.
 *
 * By default, @a globus_gss_assist_gridmap() looks for the default gridmap
 * file defined by the value of the GRIDMAP environment variable. If that
 * is not set, it falls back to $HOME/.gridmap.
 *
 * @param globusidp
 *     The GSSAPI name string of the identity who requested authorization
 * @param useridp
 *     A pointer to a string to be set to the default user ID for the local
 *     system. No validation is done to check that such a user exists.
 *
 * @return 
 *     On success, globus_gss_assist_gridmap() returns 0 and modifies the
 *     the string pointed to by the @a useridp parameter. If an error occurs,
 *     a non-zero value is returned and the value pointed to by @a useridp
 *     is undefined.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval 1
 *     Error
 */
int 
globus_gss_assist_gridmap(
    char * 	                        globusidp,
    char ** 	                        useridp) 
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_i_gss_assist_gridmap_line_t *
                                        gline = NULL;
    char                               *usernameprefix;
    int                                 ret;

    static char *                       _function_name_ =
    "globus_gss_assist_gridmap";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    /* Check arguments */
    if ((globusidp == NULL) || (useridp == NULL))
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_ARGUMENTS,
            (_GASL("Params passed to function are NULL")));
        goto exit;
    }

    *useridp = NULL;

    result = globus_i_gss_assist_gridmap_find_dn(globusidp, &gline);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP);
        goto exit;
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
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
                (_GASL("Invalid (NULL) user id values")));
            goto exit;
	}

	/* First user id is default */
	*useridp = strdup(gline->user_ids[0]);

	globus_i_gss_assist_gridmap_line_free(gline);

	if (*useridp == NULL)
	{
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
                (_GASL("Duplicate string operation failed")));
	    goto exit;
	}

	if ((*useridp)[0] == '.') /* need to use gridmapdir */
	{             
	    usernameprefix = strdup(&((*useridp)[1]));
	    free(*useridp); *useridp = NULL;
	    ret = gridmapdir_userid(globusidp, usernameprefix, useridp);
	    free(usernameprefix);
	    return ret;
        }

    }
    else
    {
        char *                          gridmap_filename = NULL;

        GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME(&gridmap_filename);

	/* No entry found in gridmap file for this user */
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_IN_GRIDMAP_NO_USER_ENTRY,
            (_GASL("The DN: %s could not be mapped to a valid user in the "
             "gridmap file: %s."),
             globusidp,
             gridmap_filename != NULL ? gridmap_filename : "(NULL)"));

        free(gridmap_filename);
        goto exit;
    }

 exit:

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    if(result == GLOBUS_SUCCESS)
    {
        return 0;
    }
    else
    {
        globus_object_t *               error_obj;
        error_obj = globus_error_get(result);
        globus_object_free(error_obj);

        return 1;
    }
}
/* globus_gss_assist_gridmap() */

/**
 * @brief Gridmap entry existence check
 * @ingroup globus_gsi_gss_assist
 *
 * @details
 * The @a globus_gss_assist_userok() function parses the default gridmap file
 * and checks whether any mapping exists for the grid identity passed as the
 * @a globusid parameter and the local user identity passed as the @ userid
 * parameter.
 *
 * By default, @a globus_gss_assist_userok() looks for the default gridmap
 * file defined by the value of the GRIDMAP environment variable. If that
 * is not set, it falls back to $HOME/.gridmap.
 *
 * @param globusid
 *     The GSSAPI name string of the identity who requested authorization
 * @param userid
 *     The local account name that access is sought for.
 *
 * @return
 *     If @a globus_gss_assist_userok() is able to find a mapping between
 *     @a globusid and @a userid, it returns 0; otherwise it returns 1.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval 1
 *     Error
 */
int
globus_gss_assist_userok(
    char *		                globusid,
    char *		                userid)
{
    char *                              gridmap_filename = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_i_gss_assist_gridmap_line_t *			
                                        gline = NULL;
    char **				useridp;
    static char *                       _function_name_ =
        "globus_gss_assist_userok";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    /* Check arguments */
    if ((globusid == NULL) ||
	(userid == NULL))
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_ARGUMENTS,
            (_GASL("Arguments passed to function are NULL")));
        goto exit;
    }
    
    result = globus_i_gss_assist_gridmap_find_dn(globusid, &gline);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP);
        goto exit;
    }

    if (gline == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_IN_GRIDMAP_NO_USER_ENTRY,
            (_GASL("The DN: %s does not map to the username: %s"),
             globusid,
             userid));
	goto exit;
    }
    if (gline->user_ids == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
            (_GASL("The gridmap is malformated.  No user id's could be be found.")));
        goto exit;
    }

    if (*((gline->user_ids)[0]) == '.') /* try using gridmapdir */ 
    {
        globus_i_gss_assist_gridmap_line_free(gline);
        return gridmapdir_userok(globusid, userid);
    }
    else
    for (useridp = gline->user_ids; *useridp != NULL; useridp++)
    {
	if (strcmp(*useridp, userid) == 0)
	{
            goto exit;
	}
    }

    GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME(&gridmap_filename);
    GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
        result,
        GLOBUS_GSI_GSS_ASSIST_ERROR_USER_ID_DOESNT_MATCH,
        (_GASL("The user id: %s, doesn't match the the DN: %s, in the "
         "gridmap file: %s"),
         globusid,
         userid,
         gridmap_filename != NULL ? gridmap_filename : "(NULL)"));
    free(gridmap_filename);

 exit:

    if(gline)
    {
        globus_i_gss_assist_gridmap_line_free(gline);
    }

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    if(result == GLOBUS_SUCCESS)
    {
        return 0;
    }
    else
    {
        globus_object_t *               error_obj;
        error_obj = globus_error_get(result);
        globus_object_free(error_obj);

        return 1;
    }
}
/* globus_gss_assist_userok() */

/**
 * @brief Look up the default Grid identity associated with a local user name
 * @ingroup globus_gsi_gss_assist
 *
 * @details
 * The @a globus_gss_assist_map_local_user() function parses the 
 * gridmap file to determine a if the user name passed as the @a local_user 
 * parameter is the default local user for a Grid ID in the gridmap file. If
 * so, it modifies @a globusidp to point to a copy of that ID. Otherwise, it
 * searches the gridmap file for a Grid ID that has a non-default mapping for
 * @a local_user and modifies @a globusidp to point to a copy of that ID.
 * If successful, the caller is responsible for freeing the string pointed to
 * by the @a globusidp pointer.
 *
 * By default, @a globus_gss_assist_map_local_user() looks for the default
 * gridmap file defined by the value of the GRIDMAP environment variable. If
 * that is not set, it falls back to $HOME/.gridmap.
 *
 * @param local_user
 *     The local username to find a Grid ID for
 * @param globusidp
 *     A Grid ID that maps from the local_user.
 *
 * @return
 *     On success, @a globus_gss_assist_map_local_user() returns 0 and
 *     modifies @a globusidp to point to a Grid ID that maps to @a local_user;
 *     otherwise, @a globus_gss_assist_map_local_user() returns 1 and the
 *     value pointed to by @a globusidp is undefined.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval 1
 *     Error
 */
int 
globus_gss_assist_map_local_user(
    char * 	                        local_user,
    char ** 	                        globusidp) 
{
    char *                              gridmap_filename = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_i_gss_assist_gridmap_line_t *			
                                        gline = NULL;
    static char *                       _function_name_ =
        "globus_gss_assist_map_local_user";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    /* Check arguments */
    if ((local_user == NULL) ||
	(globusidp == NULL))
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_ARGUMENTS,
            (_GASL("Arguments passed to the function are NULL.")));
        goto exit;
    }

    *globusidp = NULL;

    result = globus_i_gss_assist_gridmap_find_local_user(local_user, &gline);
    if(result != GLOBUS_SUCCESS)
    {
	/*
	 * We failed to open the gridmap file.
	 */
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP);
        goto exit;
    }

    if (gline != NULL)
    {
	if (gline->dn == NULL)
	{
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
                (_GASL("The gridmap file: %s is formatted incorrectly.  No "
                 "distinguished names could be found.")));
            goto exit;
        }

	/* First user id is default */
	*globusidp = strdup(gline->dn);

	if (*globusidp == NULL)
	{
	    /* strdup() failed */
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
                (_GASL("The string duplication operation failed.")));
            goto exit;
	}
    }
    else
    {
        GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME(&gridmap_filename);
	/* No entry found in gridmap file for this user */
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_IN_GRIDMAP_NO_USER_ENTRY,
            (_GASL("No DN entry found for user: %s in gridmap file: %s"),
             local_user,
             gridmap_filename != NULL ? gridmap_filename : "(NULL)"));
        free(gridmap_filename);
        goto exit;
    }

 exit:

    if(gline)
    {
        globus_i_gss_assist_gridmap_line_free(gline);
    }

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    if(result == GLOBUS_SUCCESS)
    {
        return 0;
    }
    else
    {
        globus_object_t *               error_obj;
        error_obj = globus_error_get(result);
        globus_object_free(error_obj);

        /* try with gridmapdir before giving up completely */
        return gridmapdir_globusid(local_user, globusidp);
    }
} 
/* globus_gss_assist_map_local_user() */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @name Gridmap Find DN
 */
/* @{ */
/**
 * @ingroup globus_i_gsi_gss_assist
 * Locate the entry for the given DN in the default gridmap file
 *
 * @param dn
 *        the distinguished name to search for
 * @param gline
 *        gives the line information 
 *
 * @return
 *        0 on success, otherwise an error object identifier is returned.
 *        use globus_error_get to get the error object from the id.  The
 *        resulting error object must be freed using globus_object_free
 *        when it is no longer needed.
 *
 * @see globus_error_get
 * @see globus_object_free
 */
static
globus_result_t
globus_i_gss_assist_gridmap_find_dn(
    const char * const 		        dn,
    globus_i_gss_assist_gridmap_line_t **		        
                                        gline)
{
    char *                              gridmap_filename = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char *				open_mode = "r";
    FILE *				gmap_stream = NULL;
    int					found = 0;
    globus_i_gss_assist_gridmap_line_t *			
                                        gline_tmp = NULL;
    static char *                       _function_name_ =
        "globus_i_gss_assist_gridmap_find_dn";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;


    /* Check arguments */
    if (dn == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_ARGUMENTS,
            (_GASL("The DN passed to function is NULL.")));
	goto exit;
    }

    result = GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME(&gridmap_filename);
    if(result != GLOBUS_SUCCESS)
    {
        gridmap_filename = NULL;
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP);
        goto exit;
    }

    gmap_stream = fopen(gridmap_filename, open_mode);

    if (gmap_stream == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
            (_GASL("Couldn't open gridmap file: %s for reading."),
             gridmap_filename));
        goto exit;
    }

    free(gridmap_filename);
    gridmap_filename = NULL;

    do
    {
        size_t                          line_len;
        char *                          line;

        result = globus_l_gss_assist_line_length(gmap_stream, &line_len);
        if (result != GLOBUS_SUCCESS || line_len == 0)
        {
            break;
        }

        line = malloc(++line_len);
        if (line == NULL)
        {
            result = globus_error_put(globus_error_wrap_errno_error(
                GLOBUS_GSI_GSS_ASSIST_MODULE,
                errno,
                GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
                __FILE__,
                _function_name_,
                __LINE__,
                _GASL("Could not allocate enough memory")));
            break;
        }

        if (fgets(line, line_len, gmap_stream) == NULL)
        {
            free(line);
	    break;		/* EOF or error */
        }

        result = globus_i_gss_assist_gridmap_parse_line(line, &gline_tmp);
	if (result != GLOBUS_SUCCESS)
	{
            GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP);
            free(line);
            continue;		/* Parse error */
        }

	if ((gline_tmp != NULL) &&
            (globus_i_gsi_cert_utils_dn_cmp(dn, gline_tmp->dn) == 0))
	{
            found = 1;
	}
	else
	{
	    globus_i_gss_assist_gridmap_line_free(gline_tmp);
	}
        free(line);
    } while (!found);

    fclose(gmap_stream);
    gmap_stream = NULL;

    if (found)
    {
        *gline = gline_tmp;
    }
    else
    {
        *gline = NULL;
    }

 exit:

    if (gridmap_filename != NULL)
    {
	free(gridmap_filename);
    }

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return result;
} 
/* gridmap_find_dn() */
/* @} */

/**
 * @name Find Local User
 */
/* @{ */
/**
 * @ingroup globus_i_gsi_gss_assist
 * Locate the first entry with the given local user as the default in the
 * default gridmap file.  If the user is not a default on any entry, locate the
 * first entry in which the user exists as a secondary mapping.
 *
 * @param local_user
 *        the name to search for
 * @param gline
 *        the resulting gridmap_line_t contianing the user and DN information
 *
 * @return
 *        0 on success, otherwise an error object identifier is returned.
 *        use globus_error_get to get the error object from the id.  The
 *        resulting error object must be freed using globus_object_free
 *        when it is no longer needed.
 *
 * @see globus_error_get
 * @see globus_object_free
 */
static
globus_result_t
globus_i_gss_assist_gridmap_find_local_user(
    const char * const	                local_user,
    globus_i_gss_assist_gridmap_line_t **	                
                                        gline)
{
    char *				gridmap_filename = NULL;
    char *				open_mode = "r";
    FILE *				gmap_stream = NULL;
    int					found = 0;
    globus_i_gss_assist_gridmap_line_t *			
                                        gline_tmp;
    char ** 	                        useridp;
    char *                              nondefault_line = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_i_gss_assist_gridmap_find_local_user";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    /* Check arguments */
    if (local_user == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_ARGUMENTS,
            (_GASL("Arguments passed to function are NULL.")));
        goto exit;
    }

    result = GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME(&gridmap_filename);
    if(result != GLOBUS_SUCCESS)
    {
        gridmap_filename = NULL;
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP);
        goto exit;
    }
            
    gmap_stream = fopen(gridmap_filename, open_mode);

    if (gmap_stream == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
            (_GASL("Can't open the file: %s"), gridmap_filename));
        goto exit;
    }

    do
    {
        size_t                          line_len;
        char *                          line;
        char *                          save_line;

        result = globus_l_gss_assist_line_length(gmap_stream, &line_len);
        if (result != GLOBUS_SUCCESS || line_len == 0)
        {
            break;
        }
        
        line = malloc(++line_len);
        if (line == NULL)
        {
            result = globus_error_put(globus_error_wrap_errno_error(
                GLOBUS_GSI_GSS_ASSIST_MODULE,
                errno,
                GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
                __FILE__,
                _function_name_,
                __LINE__,
                _GASL("Could not allocate enough memory")));
            break;
        }
        
        if (fgets(line, line_len, gmap_stream) == NULL)
        {
	    break;		/* EOF or error */
        }

        save_line = strdup(line);
        
	result = globus_i_gss_assist_gridmap_parse_line(line, &gline_tmp);
        if(result != GLOBUS_SUCCESS)
        {
            free(line);
            free(save_line);
	    continue;		/* Parse error */
        }

	if (gline_tmp == NULL)
	{
	    /* Empty line */
            free(line);
            free(save_line);
	    continue;
	}

        for(useridp = gline_tmp->user_ids; 
            useridp != NULL && *useridp != NULL && !found; 
            useridp++)
        {
            if(strcmp(local_user, *useridp) == 0)
            {
                /* check all names, but only stop looking if we match a 
                 * default name.  save the first nondefault match til 
                 * we've checked all the defaults */
                if(*useridp == gline_tmp->user_ids[0])
                {
                    found = 1;
                }
                else if(nondefault_line == NULL)
                {
                    nondefault_line = strdup(save_line);
                }
            }
        }
        if(!found)
	{
	    globus_i_gss_assist_gridmap_line_free(gline_tmp);
	}
        free(line);
        free(save_line);
    } while (!found);
    
    if(nondefault_line != NULL)
    {
	result = globus_i_gss_assist_gridmap_parse_line(
	    nondefault_line, &gline_tmp);
        free(nondefault_line);
        if(result != GLOBUS_SUCCESS)
        {
	    goto exit;
        }
        found = 1;
    }        

    fclose(gmap_stream);
    gmap_stream = NULL;

    if (found)
	*gline = gline_tmp;
    else
	*gline = NULL;

 exit:

    if (gridmap_filename)
    {
	free(gridmap_filename);
    }

    if (gmap_stream)
	fclose(gmap_stream);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return result;
} 
/* gridmap_find_local_user() */
/* @} */

/**
 * @name Gridmap Parse Line
 */
/* @{ */
/**
 * @ingroup globus_i_gsi_gss_assist
 * 
 * Given a line from the gridmap file, parse it returning
 * a gridmap_line_t structure. line is modified during parsing.
 * The format of the line is expected to be:
 * <DN> <userid>[,<userid>[,<userid>...]]
 * Leading and trailing whitespace is ignored.
 * userids must only have a comma between them, no whitespace.
 * Anything after the userids is ignored.
 * Anything after an unescaped comment character is ignored.
 *
 * @param line
 *        the line to parse
 * @param gline
 *        the resulting parsed gridmap line structure
 *
 * @return
 *        0 on success, otherwise an error object identifier is returned.
 *        use globus_error_get to get the error object from the id.  The
 *        resulting error object must be freed using globus_object_free
 *        when it is no longer needed.
 *
 * @see globus_error_get
 * @see globus_object_free
 */
static
globus_result_t
globus_i_gss_assist_gridmap_parse_line(
    char * 			        line,
    globus_i_gss_assist_gridmap_line_t **	                
                                        gline)
{
    char *				dn_end;
    char *				parsed_dn = NULL;
    char **				userids = NULL;
    int					num_userids = 0;
    int					userid_slots = 0;
    globus_i_gss_assist_gridmap_line_t *			
                                        gline_tmp = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_i_gss_assist_gridmap_parse_line";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;
    
    /* Check arguments */
    if ((line == NULL) ||
	(gline == NULL))
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
            (_GASL("Arguments passed to function are NULL.")));
	goto exit;
    }

    /* Skip over leading whitespace */
    line += strspn(line, WHITESPACE_CHARS);

    /* Check for comment at start of line and ignore line if present */
    if (strchr(COMMENT_CHARS, *line) != NULL) 
    {
	/* Ignore line, return NULL gline */
	*gline = NULL;
        goto exit;
    }
	
    /* Check for empty line */
    if (*line == NUL)
    {
	/* Empty line, return NULL gline. */
	*gline = NULL;
	goto exit;
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
            /* If loop below resolves bug 4979 */
            if (strchr(ESCAPING_CHARS, *(dn_end - 1))) 
            {
                dn_end++;
            }
	    
	    dn_end += strcspn(dn_end, QUOTING_CHARS);

	    if (*dn_end == NUL)
            {
                GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                    result,
                    GLOBUS_GSI_GSS_ASSIST_ERROR_INVALID_GRIDMAP_FORMAT,
                    (_GASL("A closing quote is missing in the gridmap file, "
                     "on the line:\n%s\n"),
                     line));
                goto exit;
            }

	    /* Make sure it's not escaped */
	}
	while (strchr(ESCAPING_CHARS, *(dn_end - 1)) != NULL);
    }
    else
    {
	/* No, just find next whitespace */
	dn_end = line + strcspn(line, WHITESPACE_CHARS);

	if (*dn_end == NUL)
        {
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_ERROR_INVALID_GRIDMAP_FORMAT,
                (_GASL("Nothing follows the DN on the line:\n%s\n"),
                 line));
            goto exit;
        }
    }

    /* NUL terminate DN and parse */
    *dn_end = NUL;

    result = globus_i_gss_assist_gridmap_parse_globusid(line, &parsed_dn);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP);
        goto exit;
    }

    /* Skip over closing delim and any whitespace after DN */
    line = dn_end + 1;
    line += strspn(line, WHITESPACE_CHARS);

    /* Parse list of unix user ID seperated by USERID_SEP_CHARS */
    while (*line != NUL)
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

	    if (!userids_tmp)
            {
                result = globus_error_put(globus_error_wrap_errno_error(
                    GLOBUS_GSI_GSS_ASSIST_MODULE,
                    errno,
                    GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
                    __FILE__,
                    _function_name_,
                    __LINE__,
                    _GASL("Could not allocate enough memory")));
		goto error_exit;
            }

	    userids = userids_tmp;
	}
  
	userids[num_userids] = malloc(userid_len + 1 /* for NUL */);

	if (!userids[num_userids])
        {
            result = globus_error_put(globus_error_wrap_errno_error(
                GLOBUS_GSI_GSS_ASSIST_MODULE,
                errno,
                GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
                __FILE__,
                _function_name_,
                __LINE__,
                _GASL("Could not allocate enough memory")));
            goto error_exit;
        }

	strncpy(userids[num_userids], line, userid_len);
	userids[num_userids][userid_len] = NUL;

	num_userids++;
	userids[num_userids] = NULL;

	line += userid_len;
        line += strspn(line, USERID_TERMINATOR_CHARS);
    }

    /* Ok, build our gridmap_line_t structure */
    gline_tmp = malloc(sizeof(*gline_tmp));

    if (gline_tmp == NULL)
    {
        result = globus_error_put(globus_error_wrap_errno_error(
            GLOBUS_GSI_GSS_ASSIST_MODULE,
            errno,
            GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
            __FILE__,
            _function_name_,
            __LINE__,
            _GASL("Could not allocate enough memory")));
        goto error_exit;
    }

    gline_tmp->dn = parsed_dn;
    gline_tmp->user_ids = userids;

    *gline = gline_tmp;
  
    goto exit;

 error_exit:

    if (parsed_dn)
    {
        free(parsed_dn);
    }

    if (userids)
    {
	char **userids_tmp = userids;

	while (*userids_tmp != NULL)
        {
            free(*userids_tmp++);
        }

	free(userids);
    }

 exit:

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return result;
} 
/* gridmap_parse_line() */
/* @} */

/**
 * @name globus_i_gsi_gss_assist
 */
/* @{ */
/**
 * @ingroup globus_i_gsi_gss_assist
 * Frees all memory allocated to a gridmap_line_t structure.
 *
 * @param gline
 *        pointer to structure to be freed.
 * 
 * @return
 *        void
 */
static
void
globus_i_gss_assist_gridmap_line_free(
    globus_i_gss_assist_gridmap_line_t *                    
                                        gline)
{
    static char *                       _function_name_ =
        "globus_i_gss_assist_gridmap_line_free";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    if (gline != NULL)
    {
        if (gline->dn != NULL)
        {
            free(gline->dn);
        }
        
        if (gline->user_ids != NULL)
        {
            char **                           userids_tmp = gline->user_ids;
            
            while (*userids_tmp != NULL)
            {
                free(*userids_tmp++);
            }
            
            free(gline->user_ids);
        }
        
        free(gline);
    }
} 
/* gridmap_free_gridmap_line() */
/* @} */

/**
 * @name Gridmap Parse Globusid
 */
/* @{ */
/**
 * @ingroup globus_i_gsi_gss_assist
 * Given a pointer to a string containing the globusid from the
 * gridmap file, return a pointer to a string containing the
 * parsed from of the id.
 *
 * Specifically handle backslashed characters - e.g. '\\',
 * '\x4a' or '\37'.
 *
 * @param unparsed
 *        the unparsed globusid
 * @param pparsed
 *        the resulting parsed string - this should be freed when
 *        no longer needed
 * @result
 *        0 on success, otherwise an error object identifier is returned.
 *        use globus_error_get to get the error object from the id.  The
 *        resulting error object must be freed using globus_object_free
 *        when it is no longer needed.
 *
 * @see globus_error_get
 * @see globus_object_free
 */
static
globus_result_t
globus_i_gss_assist_gridmap_parse_globusid(
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
    char			        unparsed_char;

    globus_result_t                     result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "globus_i_gss_assist_gridmap_parse_globusid";

    static char *                       hexdigit = "0123456789ABCDEF";

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    /*
     * Check input parameters for legality
     */
    if ((unparsed == NULL) ||
	(pparsed == NULL))
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_ARGUMENTS,
            (_GASL("Arguments passed to function are NULL.")));
        goto exit;
    }

    buffer_len = strlen(unparsed);
    buffer = malloc(buffer_len);

    if (buffer == NULL)
    {
        globus_error_put(globus_error_wrap_errno_error( 
            GLOBUS_GSI_GSS_ASSIST_MODULE, 
            errno, 
            GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO, 
            __FILE__,
            _function_name_,
            __LINE__,
            _GASL("Could not allocate enough memory")));
        goto exit;
    }

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
		    (globus_i_gss_assist_xdigit_to_value(*unparsed) << 4) +
		    globus_i_gss_assist_xdigit_to_value(*(unparsed + 1));
	
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

	while ((buffer_index + 4) >= buffer_len)
	{
	    /* Grow buffer */
	    char *tmp_buffer;

	    buffer_len *= 2;

	    tmp_buffer = realloc(buffer, buffer_len);

	    if (tmp_buffer == NULL)
	    {
		free(buffer);
		globus_error_put(globus_error_wrap_errno_error(
                    GLOBUS_GSI_GSS_ASSIST_MODULE,
                    errno,
                    GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
                    __FILE__,
                    _function_name_,
                    __LINE__,
                    _GASL("Could not allocate enough memory")));
                goto exit;
	    }
            
	    buffer = tmp_buffer;
	}

	if ((unparsed_char < ' ') || (unparsed_char > '~'))
	{
	    buffer[buffer_index++] = '\\';
	    buffer[buffer_index++] = 'x';
	    buffer[buffer_index++] = hexdigit[(unparsed_char >> 4) & 0x0f];
	    buffer[buffer_index++] = hexdigit[unparsed_char & 0x0f];
	}
	else
	{
	    buffer[buffer_index++] = unparsed_char;
	}
	buffer[buffer_index] = NUL;

	escaped = 0;
    }
    
    /* XXX What if escaped == 1 here? */
    /* Success */
    
    *pparsed = buffer;
    
 exit:
    
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return result;
} 
/* gridmap_parse_globusid() */
/* @} */

/**
 * @name Hexadecimal Digit to Integer
 */
/* @{ */
/**
 * @ingroup globus_i_gsi_gss_assist
 * Convert an ascii character representing a hexadecimal digit
 * into an integer.
 *
 * @param xdigit
 *        character contianing the hexidecimal digit
 *
 * @return
 *        the value in the xdigit, or -1 if error
 */
static int
globus_i_gss_assist_xdigit_to_value(
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
} 
/* xdigit_to_value() */
/* @} */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */


/**
 * @brief Look up all Grid IDs associated with a local user ID
 * @ingroup globus_gsi_gss_assist
 *
 * @details
 * The @a globus_gss_assist_lookup_all_globusid() function parses a 
 * gridmap file and finds all Grid IDs that map to a local user ID.
 * The @a dns parameter is modified to point to an array of Grid ID
 * strings from the gridmap file, and the @a dn_count parameter is
 * modified to point to the number of Grid ID strings in the array.
 * The caller is responsible for freeing the array using the macro
 * @a GlobusGssAssistFreeDNArray().
 *
 * By default, @a globus_gss_assist_lookup_all_globusid() looks for the default
 * gridmap file defined by the value of the GRIDMAP environment variable. If
 * that is not set, it falls back to $HOME/.gridmap.
 *
 * @param username
 *     The local username to look up in the gridmap file.
 * @param dns
 *     A pointer to an array of strings. This function modifies this
 *     to point to a newly allocated array of strings. The
 *     caller must use the macro @a GlobusGssAssistFreeDNArray() to free
 *     this memory.
 * @param dn_count
 *     A pointer to an integer that is modified to contain the number of 
 *     entries in the array returned via the @a dns parameter.
 *
 * @return
 *     On success, @a globus_gss_assist_lookup_all_globusid() returns
 *     GLOBUS_SUCCESS and modifies its @a dns and @a dn_count parameters as
 *     described above. If an error occurs,
 *     @a globus_gss_assist_lookup_all_globusid() returns a globus_result_t
 *     that can be resolved to an error object and the values
 *     pointed to by @a dns and @a dn_count are undefined.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_ARGUMENTS
 *     Error with arguments
 * @retval GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP
 *     Invalid path to gridmap
 * @retval GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO
 *     System error
 */
globus_result_t
globus_gss_assist_lookup_all_globusid(
    char *                                      username,
    char **                                     dns[],
    int *                                       dn_count)
{
    char *                                      line;
    size_t                                      line_len;
    int                                         i;
    int                                         max_ndx = 512;
    int                                         ndx = 0;
    char **                                     l_dns;
    globus_i_gss_assist_gridmap_line_t *        gline;
    char *                                      gridmap_filename = NULL;
    globus_result_t                             res = GLOBUS_SUCCESS;
    FILE *                                      gmap_stream = NULL;
    static char *                       _function_name_ =
        "globus_gss_assist_lookup_all_globusid";

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    /* Check arguments */
    if(dns == NULL ||
       username == NULL ||
       dn_count == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            res,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_ARGUMENTS,
            (_GASL("An argument passed to function is NULL.")));

        goto exit;
    }

    res = GLOBUS_GSI_SYSCONFIG_GET_GRIDMAP_FILENAME(&gridmap_filename);
    if(res != GLOBUS_SUCCESS)
    {
        gridmap_filename = NULL;
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            res,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP);

        goto exit;
    }

    gmap_stream = fopen(gridmap_filename, "r");

    if (gmap_stream == NULL)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            res,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
            (_GASL("Couldn't open gridmap file: %s for reading."),
             gridmap_filename));

        goto exit;
    }

    ndx = 0;
    l_dns = (char **)globus_malloc(sizeof(char *) * max_ndx);

    while (!feof(gmap_stream))
    {
        res = globus_l_gss_assist_line_length(gmap_stream, &line_len);
        if (res != GLOBUS_SUCCESS || line_len == 0)
        {
            break;
        }

        line = malloc(++line_len);
        if (line == NULL)
        {
            res = globus_error_put(globus_error_wrap_errno_error(
                GLOBUS_GSI_GSS_ASSIST_MODULE,
                errno,
                GLOBUS_GSI_GSS_ASSIST_ERROR_ERRNO,
                __FILE__,
                _function_name_,
                __LINE__,
                _GASL("Could not allocate enough memory")));
            break;
        }

        if (fgets(line, line_len, gmap_stream) == NULL)
    {
            free(line);
            break;
        }

        res = globus_i_gss_assist_gridmap_parse_line(line, &gline);

        if(res == GLOBUS_SUCCESS &&
           gline != NULL &&
           gline->user_ids != NULL)
        {
            for (i = 0; gline->user_ids[i] != NULL; i++)
            {
                if(strcmp(gline->user_ids[i], username) == 0)
                {
                    l_dns[ndx] = strdup(gline->dn);
                    ndx++;
                    if(ndx >= max_ndx)
                    {
                        max_ndx *= 2;
                        l_dns = (char **)globus_libc_realloc(l_dns,
                                             sizeof(char *) * max_ndx);
                    }
                    break;
                }
            }
        }
        free(line);
    }
    l_dns[ndx] = NULL;
    *dns = l_dns;
    *dn_count = ndx;

    fclose(gmap_stream);
    gmap_stream = NULL;

 exit:

    if(gridmap_filename != NULL)
    {
        free(gridmap_filename);
    }

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;

    return res;
}
/* globus_gss_assist_lookup_all_globusid() */


/**
 * @brief Authorize the peer of a security context to use a service
 * @ingroup globus_gsi_gss_assist
 *
 * @details
 * The globus_gss_assist_map_and_authorize() function attempts to authorize
 * the peer of a security context to use a particular service. If
 * the @a desired_identity parameter is non-NULL, the authorization will
 * succeed only if the peer is authorized for that identity. Otherwise,
 * any valid authorized local user name will be used. If authorized, the
 * local user name will be copied to the string pointed to by the
 * @a identity_buffer parameter, which must be at least as long as the
 * value passed as the @a identity_buffer_length parameter.
 *
 * If authorization callouts are defined in the callout configuration
 * file, @a globus_gss_assist_map_and_authorize() will invoke both the
 * GLOBUS_GENERIC_MAPPING_TYPE callout and the GLOBUS_GENERIC_AUTHZ_TYPE
 * callout; otherwise the default gridmap file will be used for mapping
 * and no service-specific authorization will be done.
 *
 * If @a globus_gss_assist_map_and_authorize() uses a gridmap file, it
 * first looks for a file defined by the value of the GRIDMAP environment
 * variable. If that is not set, it falls back to $HOME/.gridmap.
 *
 * @param context
 *     Security context to inspect for peer identity information.
 * @param service
 *     A NULL-terminated string containing the name of the service that
 *     an authorization decision is being made for.
 * @param desired_identity
 *     Optional. If non-NULL, perform an authorization to act as the 
 *     local user named by this NULL-terminated string.
 * @param identity_buffer
 *     A pointer to a string buffer into which will be copied the
 *     local user name that the peer of the context is authorized to
 *     act as.
 * @param identity_buffer_length
 *     Length of the @a identity_buffer array.
 *
 * @return
 *     On success, @a globus_gss_assist_map_and_authorize() returns
 *     GLOBUS_SUCCESS and copies the authorized local identity to the
 *     @a identity_buffer parameter. If an error occurs,
 *     @a globus_gss_assist_map_and_authorize() returns a globus_result_t
 *     that can be resolved to an error object.
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_CALLOUT_CONFIG
 *     Invalid authorization configuration file
 * @retval GLOBUS_CALLOUT_ERROR_WITH_HASHTABLE     
 *     Hash table operation failed.
 * @retval GLOBUS_CALLOUT_ERROR_CALLOUT_ERROR
 *     The callout itself returned a error.
 * @retval GLOBUS_CALLOUT_ERROR_WITH_DL
 *     Dynamic library operation failed.
 * @retval GLOBUS_CALLOUT_ERROR_OUT_OF_MEMORY
 *     Out of memory
 * @retval GLOBUS_GSI_GSS_ASSIST_GSSAPI_ERROR
 *     A GSSAPI function returned an error
 * @retval GLOBUS_GSI_GSS_ASSIST_GRIDMAP_LOOKUP_FAILED
 *     Gridmap lookup failure
 * @retval GLOBUS_GSI_GSS_ASSIST_BUFFER_TOO_SMALL
 *     Caller provided insufficient buffer space for local identity
 */
globus_result_t
globus_gss_assist_map_and_authorize(
    gss_ctx_id_t                        context,
    char *                              service,
    char *                              desired_identity,
    char *                              identity_buffer,
    unsigned int                        identity_buffer_length)
{
    globus_object_t *                   error;
    globus_result_t                     result = GLOBUS_SUCCESS;
    static globus_bool_t                initialized = GLOBUS_FALSE;
    static globus_callout_handle_t      authz_handle = NULL;

    static char *                       _function_name_ =
        "globus_gss_assist_map_and_authorize";
    
    globus_mutex_lock(&globus_i_gsi_gss_assist_mutex);
    {
        if(initialized == GLOBUS_FALSE)
        {
            char *                      filename;
            result = GLOBUS_GSI_SYSCONFIG_GET_AUTHZ_CONF_FILENAME(&filename);
            
            if(result != GLOBUS_SUCCESS)
            {
                error = globus_error_get(result);
        
                if(globus_error_match(
                       error,
                       GLOBUS_GSI_SYSCONFIG_MODULE,
                       GLOBUS_GSI_SYSCONFIG_ERROR_GETTING_AUTHZ_FILENAME)
                   == GLOBUS_TRUE)
                {
                    globus_object_free(error);
                }
                else
                {
                    result = globus_error_put(error);
                    globus_mutex_unlock(&globus_i_gsi_gss_assist_mutex);
                    return result;
                }
            }
            else
            {
                result = globus_callout_handle_init(&authz_handle);
            
                if(result != GLOBUS_SUCCESS)
                {
                    free(filename);
                    GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
                        result,
                        GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_CALLOUT_CONFIG);
                    globus_mutex_unlock(&globus_i_gsi_gss_assist_mutex);
                    return result;
                }
            
                result = globus_callout_read_config(authz_handle, filename);

                free(filename);
            
                if(result != GLOBUS_SUCCESS)
                {
                    GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
                        result,
                        GLOBUS_GSI_GSS_ASSIST_ERROR_INITIALIZING_CALLOUT_HANDLE);
                    globus_callout_handle_destroy(authz_handle);
                    globus_mutex_unlock(&globus_i_gsi_gss_assist_mutex);
                    return result;
                }
            }
            initialized = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&globus_i_gsi_gss_assist_mutex);

    
    if(authz_handle == NULL)
    {
        return globus_l_gss_assist_gridmap_lookup(
            context,
            service,
            desired_identity,
            identity_buffer,
            identity_buffer_length);
    }
    else
    {            
        result = globus_callout_call_type(authz_handle,
                                          GLOBUS_GENERIC_MAPPING_TYPE,
                                          context,
                                          service,
                                          desired_identity,
                                          identity_buffer,
                                          identity_buffer_length);
        
        if(result != GLOBUS_SUCCESS)
        {
            error = globus_error_get(result);
            
            if(globus_error_match(
                   error,
                   GLOBUS_CALLOUT_MODULE,
                   GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED)
               == GLOBUS_TRUE)
            {
                globus_object_free(error);
                result = globus_l_gss_assist_gridmap_lookup(
                    context,
                    service,
                    desired_identity,
                    identity_buffer,
                    identity_buffer_length);
                goto error;
            }
            else
            {
                result = globus_error_put(error);
                GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
                    result,
                    GLOBUS_GSI_GSS_ASSIST_CALLOUT_ERROR);
                goto error;
            }
        }

        result = globus_callout_call_type(authz_handle,
                                          GLOBUS_GENERIC_AUTHZ_TYPE,
                                          context,
                                          service);        
        if(result != GLOBUS_SUCCESS)
        {
            error = globus_error_get(result);
            
            if(globus_error_match(
                   error,
                   GLOBUS_CALLOUT_MODULE,
                   GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED)
               == GLOBUS_FALSE)
            {
                result = globus_error_put(error);
                GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
                    result,
                    GLOBUS_GSI_GSS_ASSIST_CALLOUT_ERROR);
                goto error;
            }
            else
            {
                result = GLOBUS_SUCCESS;
            }

            globus_object_free(error);
        }
    }
    

 error:
    return result;
}
/* globus_gss_assist_map_and_authorize */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
static
globus_result_t
globus_l_gss_assist_gridmap_lookup(
    gss_ctx_id_t                        context,
    char *                              service,
    char *                              desired_identity,
    char *                              identity_buffer,
    unsigned int                        identity_buffer_length)
{
    gss_name_t                          peer;
    gss_buffer_desc                     peer_name_buffer;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 initiator;
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 rc;
    char *                              local_identity;
    static char *                       _function_name_ =
        "globus_l_gss_assist_gridmap_lookup";
    
    major_status = gss_inquire_context(&minor_status,
                                       context,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       &initiator,
                                       GLOBUS_NULL);

    if(GSS_ERROR(major_status))
    {
        result =  minor_status;
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_GSSAPI_ERROR);
        goto error;
    }

    major_status = gss_inquire_context(&minor_status,
                                       context,
                                       initiator ? GLOBUS_NULL : &peer,
                                       initiator ? &peer : GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL);

    if(GSS_ERROR(major_status))
    {
        result =  minor_status;
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_GSSAPI_ERROR);
        goto error;
    }
    
    major_status = gss_display_name(&minor_status,
                                    peer,
                                    &peer_name_buffer,
                                    GLOBUS_NULL);
    if(GSS_ERROR(major_status))
    {
        result =  minor_status;
        GLOBUS_GSI_GSS_ASSIST_ERROR_CHAIN_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_GSSAPI_ERROR);
        gss_release_name(&minor_status, &peer);
        goto error;
    }

    gss_release_name(&minor_status, &peer);        
    
    if(desired_identity == NULL)
    {
        rc = globus_gss_assist_gridmap(
            peer_name_buffer.value, 
            &local_identity);
        
        if(rc != 0)
        {
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_GRIDMAP_LOOKUP_FAILED,
                (_GASL("Could not map %s\n"), peer_name_buffer.value));
            gss_release_buffer(&minor_status, &peer_name_buffer);
            goto error;
        }

        if(strlen(local_identity) + 1 > identity_buffer_length)
        {
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_BUFFER_TOO_SMALL,
                (_GASL("Local identity length: %d Buffer length: %d\n"),
                 strlen(local_identity), identity_buffer_length));
        }
        else
        {
            strcpy(identity_buffer, local_identity);
        }
        free(local_identity);
    }
    else
    {
        rc = globus_gss_assist_userok(peer_name_buffer.value,
                                      desired_identity);
        if(rc != 0)
        {
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_GRIDMAP_LOOKUP_FAILED,
                (_GASL("Could not map %s to %s\n"),
                 peer_name_buffer.value,
                 desired_identity));
            goto error;
        }

        if(strlen(desired_identity) + 1 > identity_buffer_length)
        {
            GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
                result,
                GLOBUS_GSI_GSS_ASSIST_BUFFER_TOO_SMALL,
                (_GASL("Desired identity length: %d Buffer length: %d\n"),
                 strlen(desired_identity), identity_buffer_length));
        }
        else
        {
            strcpy(identity_buffer, desired_identity);
        }
    }

    gss_release_buffer(&minor_status, &peer_name_buffer);

 error:
    return result;
}

/**
 * Determine length of the next line on the file stream
 *
 * Scans the input stream to determine the length of the next line
 * ending with \n or the length until the end of the file. The
 * value is returned in the integer pointed to by @a len. If the file
 * pointer is currently at end-of-file, *len will be set to 0.
 * 
 * @param fp
 *     File pointer to inspect
 * @param len
 *     Pointer to be set to the length
 *
 * @retval GLOBUS_SUCCESS
 *     Success
 * @retval GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP
 *     Error with gridmap
 */
static
globus_result_t
globus_l_gss_assist_line_length(
    FILE *                              fp,
    size_t *                            len)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    fpos_t                              pos;
    int                                 line_len;
    int                                 rc;
    static char *                       _function_name_ =
        "globus_l_gss_assist_line_length";

    *len = 0;

    rc = fgetpos(fp, &pos);
    if (rc < 0)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
            (_GASL("Couldn't determine position in file.")));
        goto fgetpos_failed;
    }

    rc = fscanf(fp, "%*[^\n]%*1[\n]%n", &line_len);
    if (rc < 0 && !feof(fp))
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
            (_GASL("Couldn't determine end of line in file.")));
        goto fscanf_failed;
    }
    else if (feof(fp))
    {
        /* Assume end-of-file without newline */
        clearerr(fp);
        line_len = ftell(fp);
    }

    rc = fsetpos(fp, &pos);
    if (rc < 0)
    {
        GLOBUS_GSI_GSS_ASSIST_ERROR_RESULT(
            result,
            GLOBUS_GSI_GSS_ASSIST_ERROR_WITH_GRIDMAP,
            (_GASL("Couldn't set position in file.")));
        goto fsetpos_failed;
    }

    *len = line_len;

fsetpos_failed:
fscanf_failed:
fgetpos_failed:
    return result;
}
/* globus_l_gss_assist_line_length() */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
