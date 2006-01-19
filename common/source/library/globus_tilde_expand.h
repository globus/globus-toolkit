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


