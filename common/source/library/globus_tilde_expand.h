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

/******************************************************************************
globus_tilde_expand.h
 
Description:
   Contain only the function globus_tilde_expand.
 
******************************************************************************/
#ifndef GLOBUS_INCLUDE_GLOBUS_TILDE_EXPAND_H_
#define GLOBUS_INCLUDE_GLOBUS_TILDE_EXPAND_H_ 1
 
#include "globus_common_include.h"
 
EXTERN_C_BEGIN
 
#define GLOBUS_TILDE_EXPAND             2UL
#define GLOBUS_TILDE_USER_EXPAND        4UL

/******************************************************************************
Function: globus_tilde_expand()

Description: 

  Expand the leading ~ (or ~user) characters from inpath to the home directory
  path of the current user (or user specified in ~user); the result is stored
  in a newly allocated buffer *outpath (which will need to be freed but a call
  to globus_free.) The string following the ~/or ~user/ is also transmitted in
  the output string.

Parameters: 

  options:
    The expansion is conditionned by the options as defined in
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
int
globus_tilde_expand(
    unsigned long options,
    globus_bool_t url_form,  /* True if the inpath follows an URL format (/~)*/
    char *inpath,
    char **outpath);

EXTERN_C_END
 
#endif


