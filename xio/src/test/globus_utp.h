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

/**********************************************************************
globus_utp.h

Public declarations for the Unnamed Timing Package (UTP).
**********************************************************************/

#ifndef GLOBUS_UTP_INCLUDE
#define GLOBUS_UTP_INCLUDE

#include "globus_common.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/**********************************************************************
Publicly-accessible functions.
**********************************************************************/

extern int
globus_utp_init(unsigned numTimers, int mode);

extern void
globus_utp_write_file(const char *outFilename);

extern void
globus_utp_set_attribute(const char *keyStr,
			 const char *keyArg,
			 const char *valueStr,
			 ...);

extern void
globus_utp_start_timer(unsigned timerNumber);

extern void
globus_utp_stop_timer(unsigned timerNumber);

extern void
globus_utp_reset_timer(unsigned timerNumber);

extern void
globus_utp_disable_timer(unsigned timerNumber);

extern void
globus_utp_enable_timer(unsigned timerNumber);

extern void
globus_utp_disable_all_timers(void);

extern void
globus_utp_enable_all_timers(void);

extern const char *
globus_utp_name_timer(unsigned timerNumber,
		      const char *nameStr,
		      ...);

extern void
globus_utp_get_accum_time(unsigned timerNumber,
			  double *time,
			  int *precision);


/**********************************************************************
Publicly-accessible definitions.
**********************************************************************/

/*
 * Initialization modes.
 */
#define GLOBUS_UTP_MODE_SHARED  0	/* Pick one of these. */
#define GLOBUS_UTP_MODE_PRIVATE 1

/*
 * Strings for timer names and attribute keys and
 * values must be shorter than this.
 */
#define GLOBUS_UTP_MAX_NAME_LENGTH 240

#define GLOBUS_UTP_DEFAULT_TIMER_NAME ""

/******************************************************************************
			  Module activation structure
******************************************************************************/
extern globus_module_descriptor_t	globus_i_utp_module;

#define GLOBUS_UTP_MODULE (&globus_i_utp_module)


EXTERN_C_END
#endif /* #ifndef GLOBUS_UTP_INCLUDE */

