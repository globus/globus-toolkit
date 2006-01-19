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

#include "globus_common_include.h"
#include "globus_time.h"
#include "globus_libc.h"

const globus_abstime_t        globus_i_abstime_infinity = 
{
    GLOBUS_I_TIME_INFINITY_SEC,
    GLOBUS_I_TIME_INFINITY_NSEC,
};

const globus_abstime_t        globus_i_abstime_zero =
{
    0,
    0,
};

const globus_reltime_t        globus_i_reltime_infinity = 
{
    GLOBUS_I_TIME_INFINITY_SEC,
    GLOBUS_I_TIME_INFINITY_NSEC,
};

const globus_reltime_t        globus_i_reltime_zero =
{
    0,
    0,
};

globus_bool_t
globus_time_has_expired(
    const globus_abstime_t *                     abstime)
{
    globus_abstime_t                       time_now;

    GlobusTimeAbstimeGetCurrent(time_now);     

    if(globus_abstime_cmp(abstime, &time_now) < 0)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

globus_bool_t
globus_time_abstime_is_infinity(
    const globus_abstime_t *                     abstime)
{
    if(abstime->tv_sec == GLOBUS_I_TIME_INFINITY_SEC &&
       abstime->tv_nsec == GLOBUS_I_TIME_INFINITY_NSEC)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

globus_bool_t
globus_time_reltime_is_infinity(
    const globus_reltime_t *                     reltime)
{
    if(reltime->tv_sec == GLOBUS_I_TIME_INFINITY_SEC &&
       reltime->tv_usec == GLOBUS_I_TIME_INFINITY_NSEC)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

int
globus_abstime_cmp(
    const globus_abstime_t *                     abstime_1,
    const globus_abstime_t *                     abstime_2)
{
    long                                         tv_sec1;
    long                                         tv_sec2;
    
    tv_sec1 = abstime_1->tv_sec;
    tv_sec2 = abstime_2->tv_sec;
    
    if(tv_sec1 > tv_sec2)
    {
		return 1;
    }
    else if(tv_sec1 < tv_sec2)
    {
	    return -1;
    }
    else
    {
        long                                     tv_nsec1;
        long                                     tv_nsec2;
        
        tv_nsec1 = abstime_1->tv_nsec;
        tv_nsec2 = abstime_2->tv_nsec;
    
        /* look at nanosecs */
        if(tv_nsec1 > tv_nsec2)
		{
            return 1;
		}
		else if(tv_nsec1 < tv_nsec2)
		{
            return -1;
		}
		else
		{
            return 0;
		}
    }
}

int
globus_reltime_cmp(
    const globus_reltime_t *                     reltime_1,
    const globus_reltime_t *                     reltime_2)
{
    long                                         tv_sec1;
    long                                         tv_sec2;
    
    tv_sec1 = reltime_1->tv_sec;
    tv_sec2 = reltime_2->tv_sec;
    
    if(tv_sec1 > tv_sec2)
    {
	    return 1;
    }
    else if(tv_sec1 < tv_sec2)
    {
	    return -1;
    }
    else
    {
        long                                     tv_usec1;
        long                                     tv_usec2;
        
        tv_usec1 = reltime_1->tv_usec;
        tv_usec2 = reltime_2->tv_usec;
    
        /* look at microosecs */
        if(tv_usec1 > tv_usec2)
		{
            return 1;
		}
		else if(tv_usec1 < tv_usec2)
		{
            return -1;
		}
		else
		{
            return 0;
		}
    }
}


