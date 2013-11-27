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

globus_gatekeeper_utils.h

Description:
	Header file for some common gatekeeper routines

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$
******************************************************************************/

#ifndef GLOBUS_GATEKEEPER_UTILS_H
#define GLOBUS_GATEKEEPER_UTILS_H

int
globus_gatekeeper_util_globusxmap(
    char *					file,
    char *					index,
    char **					params);

int
globus_gatekeeper_util_tokenize(
    char *					command,
    char **					args,
    int *					n,
    char *					sep);

int
globus_gatekeeper_util_envsub(
    char **					arg);

int
globus_gatekeeper_util_exec(
    char *					args[],
    struct passwd *				pw,
    char *					userid,
    char **					errmsg);

int 
globus_gatekeeper_util_trans_to_user(
    struct passwd *				pw, 
    char *					userid,
    char **					errmsg);

#endif /* GLOBUS_GATEKEEPER_UTILS_H */
