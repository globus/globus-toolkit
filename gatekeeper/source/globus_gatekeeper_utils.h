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
