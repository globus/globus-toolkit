/*
 * globus_rsl_assist.h
 *
 * Description:
 *
 *   This header contains the interface prototypes for the rsl_assist library.
 *   
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#ifndef _GLOBUS_RSL_ASSIST_INCLUDE_GLOBUS_RSL_ASSIST_H_
#define _GLOBUS_RSL_ASSIST_INCLUDE_GLOBUS_RSL_ASSIST_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_common.h"
#include "globus_rsl.h"

char*
globus_rsl_assist_get_rm_contact(char* resource);
int
globus_rsl_assist_replace_manager_name(globus_rsl_t * rsl);

#endif
