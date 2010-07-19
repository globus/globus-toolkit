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
globus_utp_private.h

Private declarations for the Unnamed Timing Package (UTP).
**********************************************************************/

#ifndef GLOBUS_UTP_PRIVATE_INCLUDE
#define GLOBUS_UTP_PRIVATE_INCLUDE

#include "globus_utp.h"

/**********************************************************************
Machine-dependent definitions.
**********************************************************************/

/*
Supported machine types are as follows:

UNIX : generic Unix; assumes BSD 4.3-compatible gettimeofday(2) and
	"struct timeval" from <sys/time.h>.  I have not yet seen a modern
	Unix worksation which doesn't have this.

RS6000 : IBM RS6000 running AIX 3.2 or higher.  Relies on the gettimer()
	routine, which is supposed to be a standard (yet the IBM "info"
	pages say it may change!).  Clock frequency is supposed to be
	256 nanosec.
*/

/*
Check that at least one supported machine type macro was defined.
*/

#define UNIX
#if !defined(UNIX) && !defined(RS6000) && !defined(SOLHR) && \
	!defined(SPARCSUNOS41) && !defined(PARAGON)
#error "No machine type was defined."
#endif


/*
globus_utp_TimeValue_t is a machine-dependent type representing a time, at the
highest resolution available.
*/

#if defined(UNIX) || defined(SPARCSUNOS41)

#include <sys/time.h>

#if 0
#ifdef BSDGETTIMEOFDAY
extern int
BSDgettimeofday(struct timeval *tvp, struct timezone *tzp);
#else
extern int
gettimeofday(struct timeval *tvp, struct timezone *tzp);
#endif
#endif

typedef struct timeval globus_utp_TimeValue_t;

#endif /* #ifdef UNIX */


#ifdef RS6000

/*
See also comments on RS6000 version of globus_utp_readTime() in globus_utp_main.c.
*/

#include <sys/time.h>

typedef struct timestruc_t globus_utp_TimeValue_t;

#endif	/* #ifdef RS6000 */


#ifdef SOLHR

#include <sys/time.h>

typedef hrtime_t globus_utp_TimeValue_t;

#endif


#ifdef PARAGON

#include <nx.h>

typedef double globus_utp_TimeValue_t;

#endif


/**********************************************************************
Machine-independent definitions.
**********************************************************************/

extern int errno;		/* These are needed for all systems. */
#if ! defined(TARGET_ARCH_LINUX) & ! defined(TARGET_ARCH_BSD)
extern char *sys_errlist[];
#endif

/*
globus_utp_TimerState represents the current state of a timer.  A timer which is
either "stopped" or "running" is implicitly enabled.
*/

typedef enum _globus_utp_TimerState {
	GLOBUS_UTP_TIMER_STOPPED,
	GLOBUS_UTP_TIMER_RUNNING,
	GLOBUS_UTP_TIMER_DISABLED
} globus_utp_TimerState;


/*
globus_utp_Timer_t contains all data associated with a timer.
*/

typedef struct _globus_utp_Timer_t {
	globus_utp_TimerState state;
	globus_utp_TimeValue_t startTime;/* If running, when did it start? */
					/* Total time accumulated. */
	globus_utp_TimeValue_t accumulatedTime;
	unsigned long numEvents;	/* Number of timed events
					   accumulated into the timer. */
	char *name;			/* Human-readable name. */
} globus_utp_Timer_t;


/*
Attributes (key/value pairs) are stored in a linked-list structure.
*/

struct _globus_utp_Attribute_t;		/* Forward declaration. */

typedef struct _globus_utp_Attribute_t {
	char *key;
	char *value;
	struct _globus_utp_Attribute_t *next;
} globus_utp_Attribute_t;


/*
Masks to select fields of the globus_utp_init "mode" parameter.
*/

#define GLOBUS_UTP_MODE_SHARING_FIELD 0x1


/**********************************************************************
Private but global functions, to be used only internally by the UTP
package.
**********************************************************************/

/*
Read current clock time, in a machine-dependent way; store result in *tv.
*/

extern void
globus_utp_readTime(globus_utp_TimeValue_t *tv);

/*
Place elapsed time between *start and *end into *diff (machine-dependent).
It is permissible for start and/or end to be identical to diff.
*/

extern void
globus_utp_timeDifference(globus_utp_TimeValue_t *diff, const globus_utp_TimeValue_t *start,
		   const globus_utp_TimeValue_t *end);

/*
Accumulate *newElapsed time into *oldElapsed (machine-dependent).
*/

extern void
globus_utp_timeAdd(globus_utp_TimeValue_t *oldElapsed,
	    const globus_utp_TimeValue_t *newElapsed);

/*
Set *tv to time zero (machine-dependent).
*/

extern void
globus_utp_timeZero(globus_utp_TimeValue_t *tv);


/*
Convert *tv to its double-precision floating-point representation; store it
in *time, store number of significant digits after the decimal place in
*precision.  Machine-dependent.
*/

extern void
globus_utp_timeToDouble(double *time, int *precision, const globus_utp_TimeValue_t *tv);


/*
Convert *tv to its floating-point string representation, with seconds as
the units; store result in timeString.  Machine-dependent.
*/

extern void
globus_utp_timeToString(char timeString[], const globus_utp_TimeValue_t *tv);


/*
Emit the warning message messageStr in some appropriate way.  messageStr is
a printf()-format output specfier string; the "..." represents data to be
printed using the specifier.
*/

extern void
globus_utp_warn(const char *messageStr, ...);


/**********************************************************************
Private but global variables, to be used only internally by the UTP
package.
**********************************************************************/

extern char *globus_utp_outFilename;		/* Name of output dump file. */
extern unsigned globus_utp_numTimers;		/* Number of timers in use. */
extern globus_utp_Timer_t *globus_utp_timers;		/* Array for the timers. */
extern globus_utp_Attribute_t *globus_utp_attributes;	/* Key/value pairs (comments). */


#endif /* #ifndef GLOBUS_UTP_PRIVATE_INCLUDE */

