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

/******************************************************************************
globus_tilde_expand.c
 
Description:
    Contain only the function globus_tilde_expand which can be use to expand
    ~ or ~user.

 
CVS Information:
 
  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/
 
/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_tilde_expand.h"
#include "globus_libc.h"

/******************************************************************************
Function: globus_tilde_expand()

Description: 

  Expand the leading ~ (or ~user) characters from inpath to the home directory
  path of the current user (or user specified in ~user); the result is stored
  in a newly allocated buffer *outpath (which will need to be freed by a call
  to globus_free.) The string following the ~/or ~user/ is copied verbatim to
  the output string.

Parameters: 

  options:
    The expansion is conditioned by the options as defined in
    globus_tilde_expand.h:
  
     if GLOBUS_TILDE_EXPAND is set in the option, ~ will be expanded
     if GLOBUS_TILDE_USER_EXPAND is set in the option, ~user will be expanded
     Otherwise, the corresponding form is not expanded (just copied int the
     output path)
     
  url_form  True if the inpath follows an URL format (/~)
            Used when expanding an url (for : <sheme>://host[:port][/path]
	    were /path  can be of the form /~[user][/...]
	    Otherwise, the form ~[user][/...] is expected.
  
  inpath
     Input string to expand. 

  outpath
     Output string; Need to be freed when not used anymore.

Returns: 
******************************************************************************/
#if defined(TARGET_ARCH_WIN32)
int
globus_tilde_expand(
    unsigned long options,
    globus_bool_t url_form,
    char *inpath,
    char **outpath)
{
    return -1;
}

#else /* WIN32 */

int
globus_tilde_expand(
    unsigned long options,
    globus_bool_t url_form,
    char *inpath,
    char **outpath)
{
    struct passwd pwd;
    char buf[1024];

    if (url_form)
    {
	if(strlen(inpath) < 2U ||
	   (((options & GLOBUS_TILDE_EXPAND) == 0UL) &&
	    ((options & GLOBUS_TILDE_USER_EXPAND) == 0UL)))
	{
	    goto notilde;
	}
	if(inpath[1] == '~')
	{
	    int pos = 2;
	    char *username;
	    struct passwd *pw;

	    while(isalnum(inpath[pos]))
	    {
		pos++;
	    }
	    if(pos == 2)
	    {
		if((options & GLOBUS_TILDE_EXPAND) == 0UL)
		{
		    goto notilde;
		}
		/* expand ~ to home of current user */
		globus_libc_getpwuid_r(getuid(),
				       &pwd,
				       buf,
				       1024,
				       &pw);
	    }
	    else
	    {
		if((options & GLOBUS_TILDE_USER_EXPAND) == 0UL)
		{
		    goto notilde;
		}
		/* expand ~ to home of current user */
		username = globus_malloc(pos-1);
		strncpy(username,
			&inpath[2], /* skip initial /~ */
			pos-2);
		username[pos-2] = '\0';

		globus_libc_getpwnam_r(username,
				       &pwd,
				       buf,
				       1024,
				       &pw);
		globus_free(username);
	    }
	    if(pw != NULL)
	    {
		size_t path_length = 0;
		path_length += strlen(pw->pw_dir);
		path_length += strlen(inpath)-pos+1;
		path_length += 1;
	    
		*outpath = globus_malloc(path_length);
		strcpy(*outpath, pw->pw_dir);
		strcat(*outpath, &inpath[pos]);
	    }
	    else
	    {
		*outpath = globus_malloc(strlen(inpath)+1);
		strcpy(*outpath, inpath);
	    }
	}
	else
	{
	    goto notilde;
	}
	return GLOBUS_SUCCESS;
    }
    else
    {
	if(strlen(inpath) < 1U ||
	   (((options & GLOBUS_TILDE_EXPAND) == 0UL) &&
	    ((options & GLOBUS_TILDE_USER_EXPAND) == 0UL)))
	{
	    goto notilde;
	}
	
	if(inpath[0] == '~')
	{
	    int pos = 1;
	    char *username;
	    struct passwd *pw=NULL;

	    while(isalnum(inpath[pos]))
	    {
		pos++;
	    }
	    if(pos == 1)
	    {
		if((options & GLOBUS_TILDE_EXPAND) == 0UL)
		{
		    goto notilde;
		}
		/* expand ~ to home of current user */
		globus_libc_getpwuid_r(getuid(),
				       &pwd,
				       buf,
				       1024,
				       &pw);
	    }
	    else
	    {
		if((options & GLOBUS_TILDE_USER_EXPAND) == 0UL)
		{
		    goto notilde;
		}
		/* expand ~ to home of specified user */
		username = globus_malloc(pos);/* pos - 1 characters not
						 counting the tilde, plus 1 for
						 the trailing '\0'. */
		strncpy(username,
			&inpath[1],
			pos-1);
		username[pos-1] = '\0';

		globus_libc_getpwnam_r(username,
				       &pwd,
				       buf,
				       1024,
				       &pw);
		globus_free(username);
	    }
	    if(pw != NULL)
	    {
		size_t path_length = 0;
		path_length += strlen(pw->pw_dir);
		path_length += strlen(inpath)-pos+1; /* +1 to move past the
							initial  ~ */ 
		path_length += 1; /* trailing '\0' */
	    
		*outpath = globus_malloc(path_length);
		strcpy(*outpath, pw->pw_dir);
		strcat(*outpath, &inpath[pos]);
	    }
	    else
	    {
		*outpath = globus_malloc(strlen(inpath)+1);
		strcpy(*outpath, inpath);
	    }
	}
	else
	{
	    goto notilde;
	}
	return GLOBUS_SUCCESS;
    }
notilde:
    *outpath = globus_malloc(strlen(inpath)+1);
    strcpy(*outpath, inpath);
    return GLOBUS_SUCCESS;
} /* globus_tilde_expand() */

#endif /* WIN32 */


