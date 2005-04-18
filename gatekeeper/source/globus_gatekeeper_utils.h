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
