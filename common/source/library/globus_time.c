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
    globus_abstime_t *                     abstime)
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
    globus_abstime_t *                     abstime)
{
    if(abstime == GLOBUS_NULL)
    {
	    return GLOBUS_FALSE;
    }

    if(abstime->tv_sec == GLOBUS_I_TIME_INFINITY_SEC &&
       abstime->tv_nsec == GLOBUS_I_TIME_INFINITY_NSEC)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

globus_bool_t
globus_time_reltime_is_infinity(
    globus_reltime_t *                     reltime)
{
    if(reltime == GLOBUS_NULL)
    {
	    return GLOBUS_FALSE;
    }

    if(reltime->tv_sec == GLOBUS_I_TIME_INFINITY_SEC &&
       reltime->tv_usec == GLOBUS_I_TIME_INFINITY_NSEC)
    {
        return GLOBUS_TRUE;
    }

    return GLOBUS_FALSE;
}

int
globus_abstime_cmp(
    globus_abstime_t *                     abstime_1,
    globus_abstime_t *                     abstime_2)
{
    int                                    rc;

    if(abstime_1 == GLOBUS_NULL ||
       abstime_2 == GLOBUS_NULL)
    {
	    return GLOBUS_FALSE;
    }

    if(abstime_1->tv_sec > abstime_2->tv_sec)
    {
	    rc = 1;
    }
    else if(abstime_1->tv_sec < abstime_2->tv_sec)
    {
	    rc = -1;
    }
    else
    {
        /* look at nanosecs */
        if(abstime_1->tv_nsec > abstime_2->tv_nsec)
	    {
            rc = 1;
	    }
	    else if(abstime_1->tv_nsec < abstime_2->tv_nsec)
	    {
            rc = -1;
	    }
	    else
	    {
            rc = 0;
	    }
    }

    return rc;
}

int
globus_reltime_cmp(
    globus_reltime_t *                     reltime_1,
    globus_reltime_t *                     reltime_2)
{
    int                                    rc;

    if(reltime_1 == GLOBUS_NULL ||
       reltime_2 == GLOBUS_NULL)
    {
	    return GLOBUS_FALSE;
    }

    if(reltime_1->tv_sec > reltime_2->tv_sec)
    {
	    rc = 1;
    }
    else if(reltime_1->tv_sec < reltime_2->tv_sec)
    {
	    rc = -1;
    }
    else
    {
        /* look at nanosecs */
        if(reltime_1->tv_usec > reltime_2->tv_usec)
	    {
            rc = 1;
	    }
	    else if(reltime_1->tv_usec < reltime_2->tv_usec)
	    {
            rc = -1;
    	}
	    else
	    {
            rc = 0;
	    }
    }

    return rc;
}

/**/

