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
globus_strptime.c

Description:
    Contain only the function globus_strptime which can be used to parse
    and validate date strings.


CVS Information:

  $Source: /home/globdev/CVS/globus-1998_04_16/Globus/Miscellaneous/common/libra
ry/globus_strptime.c,v $
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common_include.h"
#include "globus_libc.h"

/******************************************************************************
Function: globus_strptime()

Description: 

  Parse and validate a date string (pointed to by parameter 1) based on a
  supplied format string (pointed to by parameter 2), putting the parsed and
  validated date values in a tm struct (pointed to by parameter 3).
  See description of the parameter "format_str" for a description of the
  parsing and validation rules.

Parameters: 

  date_str:
    Points to the date string that is to be parsed and validated.

  format_str:
    Contains zero or more conversion specifications. (See description below.)

  time_ptr:
    A pointer to a struct tm  for returning the parsed and validated date data.

Returns:
  pointer to character
    On successful completion:
        pointer to the first character of buffer that was not
        used in evaluating the format string.
    On unsuccessful completion:
        NULL pointer.


Format specification:
    Each specification is composed of a '%' (percent) character followed by a
    conversion character specifying the required conversion.
    One or more white space characters may (optionally) precede or follow any
    conversion specification.
    Non-white space characters that are not part of a conversion specification
    may be included in the format string, and must be matched exactly
    (including case for letters) in the date_str. '%' (percent) can be
    specified as a character to match by using "%%".
    Multiple occurences of conversions for a given component of the date/time
    (second, minute, hour, day, day of month, month, year, century) is
    detected as an error.
    White space in the date_str will terminate a numeric value, but is
    otherwise skipped and ignored.
    All numeric fields are taken as decimal, must begin with a digit,
    and are matched up to a maximum number of digits (or the first
    non-digit).
    Note the the year returned in the tm_year field of the tm struct is
    relative to 1900 (e.g., 58 means year 1958, -8 means year 1892).
    Also, if the year is specified, but not the century, then values
    50-99 are taken as 20th century, 00-49 are taken as 21st century.

    The following conversion specifications are recognized:
      %a %A         day of week  (3 character abbreviation or full name)
                    Validated as Sun-Sat, not validated as correct for
                    any specified date.
      %b %h %B      month name  (3 character abbreviation or full name)
      %C            century number  (Up to 2 digits)
      %d %e         day of month  (Up to 2 digits)
                    Validated as 1-31. If month is provided, further
                    validated as not 31 for February, April, June,
                    September, or November, nor 30 for February.
                    If year and month provided then validated as not 29
                    for February in a non-leap year.
      %D            date as %m/%d/%y
      %H            hour (0-23)  (Up to 2 digits)
                    Error if %p is used.
      %I            hour (1-12)  (Up to 2 digits)
                    Converted to 24 hour clock when put in struct tm.
                    Assumed AM unless %p flag is used.
      %m            month (1-12)  (Up to 2 digits)
                    Returned in the tm struct as (0-11).
      %M            minute (0-59)  (Up to 2 digits)
      %n            white space  (White space is ignored.)
      %p            AM or PM or A.M. or P.M. (case independent)
                    (Error if %I is used.)
      %R            %H:%M
      %S            seconds (0-61) allows for 1 or 2 leap seconds
                    (Up to 2 digits)
      %t            white space  (White space is ignored.)
      %T            %H:%M:%S
      %y            year within century  (Up to 2 digits)
      %Y            year with century  (Up to 4 digits)
  
    Any whitespace in format is ignored.
    Any whitespace in buffer serves to delimit numeric fields
        (such as second, minute, hour, day, month, year) but
        is otherwise ignored.
        (I.e., a run of spaces, tabs, etc. is matched by any
         run of spaces, tabs, etc. even if the corresponding
         characters are are not identical or the counts
         are not the same.)
    Characters that are not whitespace and are not preceded by '%'
        must match exactly.
    Allows %% as literal '%' in buffer.
    The buffer is matched to the end of the format and no further.
  

******************************************************************************/
char*
globus_strptime(
    char*       date_str,
    char*       format_str,
    struct tm*  time_ptr )
{
/*
**  struct tm from time.h,
**  documentation: man ctime
**  struct tm {
**         int     tm_sec;
**         int     tm_min;
**         int     tm_hour;
**         int     tm_mday;
**         int     tm_mon;
**         int     tm_year;
**         int     tm_wday;
**         int     tm_yday;
**         int     tm_isdst;
**  };
*/
    int         got_tm_sec = 0;
    int         got_tm_min = 0;
    int         got_hour_12 = 0;
    int         got_hour_24 = 0;
    int         got_ampm = 0;
    int         got_tm_mday = 0;
    int         got_tm_mon = 0;
    int         got_century = 0;
    int         got_century_year = 0;
    int         got_year = 0;
    int         got_tm_wday = 0;

    int         hour_wk = 0;
    int         century_wk = 0;
    int         year_wk = 0;
    int         leap_wk = 0;

    int         i;

    char*       date_wk_ptr             = GLOBUS_NULL;
    char*       format_wk_ptr           = GLOBUS_NULL;

    time_ptr->tm_sec = 0;
    time_ptr->tm_min = 0;
    time_ptr->tm_hour = 0;
    time_ptr->tm_mday = 0;
    time_ptr->tm_mon = 0;
    time_ptr->tm_year = 0;
    time_ptr->tm_wday = 0;
    time_ptr->tm_yday = 0;
/*
**  Initialize Datelight Savings Time to -1
**  so mktime() will set/use the appropriate value (0 or 1).
*/
    time_ptr->tm_isdst = -1;

    format_wk_ptr = format_str;
    date_wk_ptr = date_str;

    while( isspace( *format_wk_ptr ))
    {
        format_wk_ptr++;
    }
    while( isspace( *date_wk_ptr ))
    {
        date_wk_ptr++;
    }
    while( *format_wk_ptr != '\0' )
    {
        if( *format_wk_ptr != '%' )
        {
            if( *date_wk_ptr != *format_wk_ptr )
            {
                return GLOBUS_NULL;
            }
            date_wk_ptr++;
            format_wk_ptr++;
        }
        else
        {
            format_wk_ptr++;

            switch ( *format_wk_ptr )
            {
                case '%':
                    if( *date_wk_ptr != '%' )
                    {
                        return GLOBUS_NULL;
                    }
                    date_wk_ptr++;

                    break;

                case 'a':
                case 'A':
                /*  Day of week: 3,4 character abbreviation or full.  */
                    if( got_tm_wday )
                    {
                        return GLOBUS_NULL;
                    }
                    got_tm_wday = 1;

                    if( !globus_libc_strncasecmp( date_wk_ptr, "Sun", 3 ))
                    {
                        time_ptr->tm_wday = 0;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "day", 3 ))
                        {
                            date_wk_ptr += 3;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Mon", 3 ))
                    {
                        time_ptr->tm_wday = 1;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "day", 3 ))
                        {
                            date_wk_ptr += 3;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Tue", 3 ))
                    {
                        time_ptr->tm_wday = 2;
                        date_wk_ptr += 3;
                        if(   ( *date_wk_ptr == 's' )
                           || ( *date_wk_ptr == 'S' ))
                        {
                            date_wk_ptr++;
                            if( !globus_libc_strncasecmp( date_wk_ptr, "day", 3 ))
                            {
                                date_wk_ptr += 3;
                            }
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Wed", 3 ))
                    {
                        time_ptr->tm_wday = 3;
                        date_wk_ptr += 3;
                        if(   ( *date_wk_ptr == 'n' )
                           || ( *date_wk_ptr == 'N' ))
                        {
                            date_wk_ptr++;
                            if( !globus_libc_strncasecmp( date_wk_ptr, "esday", 5 ))
                            {
                                date_wk_ptr += 5;
                            }
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Thu", 3 ))
                    {
                        time_ptr->tm_wday = 4;
                        date_wk_ptr += 3;
                        if(   ( *date_wk_ptr == 'r' )
                           || ( *date_wk_ptr == 'R' ))
                        {
                            date_wk_ptr++;
                            if( !globus_libc_strncasecmp( date_wk_ptr, "sday", 4 ))
                            {
                                date_wk_ptr += 4;
                            }
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Fri", 3 ))
                    {
                        time_ptr->tm_wday = 5;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "day", 3 ))
                        {
                            date_wk_ptr += 3;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Sat", 3 ))
                    {
                        time_ptr->tm_wday = 6;
                        date_wk_ptr += 3;
                        if(   ( *date_wk_ptr == 'u' )
                           || ( *date_wk_ptr == 'U' ))
                        {
                            date_wk_ptr++;
                            if( !globus_libc_strncasecmp( date_wk_ptr, "rday", 4 ))
                            {
                                date_wk_ptr += 4;
                            }
                        }
                    }
                    else
                    {
                        return GLOBUS_NULL;
                    }

                    break;

                case 'b':
                case 'B':
                /*  Month: 3 character abbreviation or full.  */
                    if( got_tm_mon )
                    {
                        return GLOBUS_NULL;
                    }
                    got_tm_mon = 1;

                    if( !globus_libc_strncasecmp( date_wk_ptr, "Jan", 3 ))
                    {
                        time_ptr->tm_mon = 0;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "uary", 4 ))
                        {
                            date_wk_ptr += 4;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Feb", 3 ))
                    {
                        time_ptr->tm_mon = 1;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "ruary", 5 ))
                        {
                            date_wk_ptr += 5;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Mar", 3 ))
                    {
                        time_ptr->tm_mon = 2;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "ch", 2 ))
                        {
                            date_wk_ptr += 2;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Apr", 3 ))
                    {
                        time_ptr->tm_mon = 3;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "il", 2 ))
                        {
                            date_wk_ptr += 2;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "May", 3 ))
                    {
                        time_ptr->tm_mon = 4;
                        date_wk_ptr += 3;
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Jun", 3 ))
                    {
                        time_ptr->tm_mon = 5;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "e", 1 ))
                        {
                            date_wk_ptr += 1;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Jul", 3 ))
                    {
                        time_ptr->tm_mon = 6;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "y", 1 ))
                        {
                            date_wk_ptr += 1;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Aug", 3 ))
                    {
                        time_ptr->tm_mon = 7;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "ust", 3 ))
                        {
                            date_wk_ptr += 3;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Sep", 3 ))
                    {
                        time_ptr->tm_mon = 8;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "tember", 6 ))
                        {
                            date_wk_ptr += 6;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Oct", 3 ))
                    {
                        time_ptr->tm_mon = 9;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "ober", 4 ))
                        {
                            date_wk_ptr += 4;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Nov", 3 ))
                    {
                        time_ptr->tm_mon = 10;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "ember", 5 ))
                        {
                            date_wk_ptr += 5;
                        }
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "Dec", 3 ))
                    {
                        time_ptr->tm_mon = 11;
                        date_wk_ptr += 3;
                        if( !globus_libc_strncasecmp( date_wk_ptr, "ember", 5 ))
                        {
                            date_wk_ptr += 5;
                        }
                    }
                    else
                    {
                        return GLOBUS_NULL;
                    }

                    if( got_tm_mday )
                    {
                        if( time_ptr->tm_mon == 1 ) /* February */
                        {
                            if( time_ptr->tm_mday > 29 )
                            {
                                time_ptr->tm_mon = 0;
                                return GLOBUS_NULL;
                            }
                        }
                        else if(   ( time_ptr->tm_mon == 3 )
                                || ( time_ptr->tm_mon == 5 )
                                || ( time_ptr->tm_mon == 8 )
                                || ( time_ptr->tm_mon == 10 ))
                        {
                            if( time_ptr->tm_mday > 30 )
                            {
                                time_ptr->tm_mon = 0;
                                return GLOBUS_NULL;
                            }
                        }
                    }

                    break;

                case 'C':
                /*  Century  */
                    if(   ( got_century )
                       || ( got_century_year ))
                    {
                        return GLOBUS_NULL;
                    }
                    got_century = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    century_wk = ((int) *date_wk_ptr) - ((int) '0');
                    date_wk_ptr++;
                    if( isdigit( *date_wk_ptr ))                    
                    {
                        century_wk *= 10;
                        century_wk += ((int) *date_wk_ptr) - ((int) '0');
                        date_wk_ptr++;
                    }
                    century_wk *= 100;
                    time_ptr->tm_year += century_wk - 1900;

                    break;

                case 'D':
                /*  date as %m/%d/%y  */
                case 'm':
                /*  month (1-12) */
                    if( got_tm_mon )
                    {
                        return GLOBUS_NULL;
                    }
                    got_tm_mon = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    time_ptr->tm_mon = ((int) *date_wk_ptr) - ((int) '0');
                    date_wk_ptr++;
                    if( isdigit( *date_wk_ptr ))                    
                    {
                        time_ptr->tm_mon *= 10;
                        time_ptr->tm_mon += ((int) *date_wk_ptr) - ((int) '0');
                        date_wk_ptr++;
                    }
                    time_ptr->tm_mon--;
                    if(   ( time_ptr->tm_mon < 0 )
                       || ( time_ptr->tm_mon > 11 ))
                    {
                        time_ptr->tm_mon = 0;
                        return GLOBUS_NULL;
                    }

                    if( got_tm_mday )
                    {
                        if( time_ptr->tm_mon == 1 ) /* February */
                        {
                            if( time_ptr->tm_mday > 29 )
                            {
                                time_ptr->tm_mon = 0;
                                return GLOBUS_NULL;
                            }
                        }
                        else if(   ( time_ptr->tm_mon == 3 )
                                || ( time_ptr->tm_mon == 5 )
                                || ( time_ptr->tm_mon == 8 )
                                || ( time_ptr->tm_mon == 10 ))
                        {
                            if( time_ptr->tm_mday > 30 )
                            {
                                time_ptr->tm_mon = 0;
                                return GLOBUS_NULL;
                            }
                        }
                    }

                    if( *format_wk_ptr != 'D' )
                    {
                        break;
                    }

                    while( isspace( *date_wk_ptr ))
                    {
                        date_wk_ptr++;
                    }
                    if( *date_wk_ptr != '/' )
                    {
                        time_ptr->tm_mon = 0;
                        return GLOBUS_NULL;
                    }
                    date_wk_ptr++;
                    while( isspace( *date_wk_ptr ))
                    {
                        date_wk_ptr++;
                    }

                case 'd':
                case 'e':
                /*  day of month  */
                    if( got_tm_mday )
                    {
                        return GLOBUS_NULL;
                    }
                    got_tm_mday = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    time_ptr->tm_mday = ((int) *date_wk_ptr) - ((int) '0');
                    date_wk_ptr++;
                    if( isdigit( *date_wk_ptr ))                    
                    {
                        time_ptr->tm_mday *= 10;
                        time_ptr->tm_mday += ((int) *date_wk_ptr) - ((int) '0');
                        date_wk_ptr++;
                    }
                    if(   ( time_ptr->tm_mday < 1 )
                       || ( time_ptr->tm_mday > 31 ))
                    {
                        time_ptr->tm_mday = 0;
                        return GLOBUS_NULL;
                    }

                    if( got_tm_mon )
                    {
                        if( time_ptr->tm_mon == 1 ) /* February */
                        {
                            if( time_ptr->tm_mday > 29 )
                            {
                                time_ptr->tm_mday = 0;
                                return GLOBUS_NULL;
                            }
                        }
                        else if(   ( time_ptr->tm_mon == 3 )
                                || ( time_ptr->tm_mon == 5 )
                                || ( time_ptr->tm_mon == 8 )
                                || ( time_ptr->tm_mon == 10 ))
                        {
                            if( time_ptr->tm_mday > 30 )
                            {
                                time_ptr->tm_mday = 0;
                                return GLOBUS_NULL;
                            }
                        }
                    }

                    if( *format_wk_ptr != 'D' )
                    {
                        break;
                    }

                    while( isspace( *date_wk_ptr ))
                    {
                        date_wk_ptr++;
                    }
                    if( *date_wk_ptr != '/' )
                    {
                        time_ptr->tm_mday = 0;
                        return GLOBUS_NULL;
                    }
                    date_wk_ptr++;
                    while( isspace( *date_wk_ptr ))
                    {
                        date_wk_ptr++;
                    }

                case 'y':
                /*  year within century  */
                    if(   ( got_year )
                       || ( got_century_year ))
                    {
                        return GLOBUS_NULL;
                    }
                    got_year = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    year_wk = ((int) *date_wk_ptr ) - ((int) '0');
                    date_wk_ptr++;
                    if( isdigit( *date_wk_ptr ))                    
                    {
                        year_wk *= 10;
                        year_wk += ((int) *date_wk_ptr ) - ((int) '0');
                        date_wk_ptr++;
                    }
                    time_ptr->tm_year += year_wk;

                    break;

                case 'I':
                /*  hour (1-12)  */
                    if(   ( got_hour_12 )
                       || ( got_hour_24 ))
                    {
                        return GLOBUS_NULL;
                    }
                    got_hour_12 = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    hour_wk += ((int) *date_wk_ptr ) - ((int) '0');
                    date_wk_ptr++;
                    if( isdigit( *date_wk_ptr ))                    
                    {
                        hour_wk *= 10;
                        hour_wk += ((int) *date_wk_ptr ) - ((int) '0');
                        date_wk_ptr++;
                    }
                    if(   ( hour_wk < 1 )
                       || ( hour_wk > 12 ))
                    {
                        return GLOBUS_NULL;
                    }
                    if( hour_wk == 12 )
                    {
                        hour_wk = 0;
                    }

                    time_ptr->tm_hour += hour_wk;

                    break;

                case 'n':
                case 't':
                /*  white space is already skipped  */

                    break;

                case 'p':
                /*  AM or PM or A.M. or P.M.  */
                    if(   ( got_ampm )
                       || ( got_hour_24 ))
                    {
                        return GLOBUS_NULL;
                    }
                    got_ampm = 1;

                    if( !globus_libc_strncasecmp( date_wk_ptr, "AM", 2 ))
                    {
                        date_wk_ptr += 2;
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "A.M.", 4 ))
                    {
                        date_wk_ptr += 4;
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "PM", 2 ))
                    {
                        time_ptr->tm_hour += 12;
                        date_wk_ptr += 2;
                    }
                    else if( !globus_libc_strncasecmp( date_wk_ptr, "P.M.", 4 ))
                    {
                        time_ptr->tm_hour += 12;
                        date_wk_ptr += 4;
                    }
                    else
                    {
                        time_ptr->tm_hour = 0;
                        return GLOBUS_NULL;
                    }

                    break;

                case 'T':
                /*  %T = %H:%M:%S  */
                case 'R':
                /*  %R = %H:%M     */
                case 'H':
                /*  hour (0-23)  */
                    if(   ( got_ampm )
                       || ( got_hour_12 )
                       || ( got_hour_24 ))
                    {
                        return GLOBUS_NULL;
                    }
                    got_hour_24 = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    time_ptr->tm_hour += ((int) *date_wk_ptr ) - ((int) '0');
                    date_wk_ptr++;
                    if( isdigit( *date_wk_ptr ))                    
                    {
                        time_ptr->tm_hour *= 10;
                        time_ptr->tm_hour += ((int) *date_wk_ptr ) - ((int) '0');
                        date_wk_ptr++;
                    }
                    if(   ( time_ptr->tm_hour < 0 )
                       || ( time_ptr->tm_hour > 23 ))
                    {
                        time_ptr->tm_hour = 0;
                        return GLOBUS_NULL;
                    }

                    if(   ( *format_wk_ptr != 'R' )
                       && ( *format_wk_ptr != 'T' ))
                    {
                        break;
                    }

                    while( isspace( *date_wk_ptr ))
                    {
                        date_wk_ptr++;
                    }
                    if( *date_wk_ptr != ':' )
                    {
                        time_ptr->tm_hour = 0;
                        return GLOBUS_NULL;
                    }
                    date_wk_ptr++;
                    while( isspace( *date_wk_ptr ))
                    {
                        date_wk_ptr++;
                    }

                case 'M':
                /*  minute (0-59) */
                    if( got_tm_min )
                    {
                        return GLOBUS_NULL;
                    }
                    got_tm_min = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    time_ptr->tm_min = ((int) *date_wk_ptr ) - ((int) '0');
                    date_wk_ptr++;
                    if( isdigit( *date_wk_ptr ))                    
                    {
                        time_ptr->tm_min *= 10;
                        time_ptr->tm_min += ((int) *date_wk_ptr ) - ((int) '0');
                        date_wk_ptr++;
                    }
                    if(   ( time_ptr->tm_min < 0 )
                       || ( time_ptr->tm_min > 59 ))
                    {
                        time_ptr->tm_min = 0;
                        return GLOBUS_NULL;
                    }

                    if( *format_wk_ptr != 'T' )
                    {
                        break;
                    }

                    while( isspace( *date_wk_ptr ))
                    {
                        date_wk_ptr++;
                    }
                    if( *date_wk_ptr != ':' )
                    {
                        time_ptr->tm_min = 0;
                        return GLOBUS_NULL;
                    }
                    date_wk_ptr++;
                    while( isspace( *date_wk_ptr ))
                    {
                        date_wk_ptr++;
                    }

                case 'S':
                /*  seconds (0-61), allowing for up to 2 leap seconds  */
                    if( got_tm_sec )
                    {
                        return GLOBUS_NULL;
                    }
                    got_tm_sec = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    time_ptr->tm_sec = ((int) *date_wk_ptr ) - ((int) '0');
                    date_wk_ptr++;
                    if( isdigit( *date_wk_ptr ))                    
                    {
                        time_ptr->tm_sec *= 10;
                        time_ptr->tm_sec += ((int) *date_wk_ptr ) - ((int) '0');
                        date_wk_ptr++;
                    }
                    if(   ( time_ptr->tm_sec < 0 )
                       || ( time_ptr->tm_sec > 61 ))
                    {
                        time_ptr->tm_sec = 0;
                        return GLOBUS_NULL;
                    }

                    break;

                case 'Y':
                /*  year with century  */
                    if(   ( got_century_year )
                       || ( got_century )
                       || ( got_year ))
                    {
                        return GLOBUS_NULL;
                    }
                    got_century_year = 1;

                    if( !isdigit( *date_wk_ptr ))
                    {
                        return GLOBUS_NULL;
                    }
                    for( i = 0; i < 4; i++ )
                    {
                        if( isdigit( *date_wk_ptr ))                    
                        {
                            time_ptr->tm_year *= 10;
                            time_ptr->tm_year += ((int) *date_wk_ptr ) - ((int) '0' );
                            date_wk_ptr++;
                        }
                    }
                    time_ptr->tm_year -= 1900;

                    break;

                default:
                /*  Invalid character  */
                    return GLOBUS_NULL;

            }
            format_wk_ptr++;
        }
        while( isspace( *format_wk_ptr ))
        {
            format_wk_ptr++;
        }
        while( isspace( *date_wk_ptr ))
        {
            date_wk_ptr++;
        }
    }
/*
**  Now have all the input values.
**  Need to check if century was specified with year,
**  if not then 50-99 => 20th century, 00-49 => 21st century.
**  Only remaining validation is for Feb 29 -- it a leap year?
*/
    if(   ( got_year )
       && ( !got_century ))
    {
        if( time_ptr->tm_year < 50 )
        {
            time_ptr->tm_year += 100;
        }
    }

    if(   ( got_tm_mon )
       && ( got_tm_mday )
       && ( time_ptr->tm_mon == 1 )
       && ( time_ptr->tm_mday == 29 )
       && (   ( got_century )
           || ( got_century_year )
           || ( got_year )))
    {
        leap_wk = time_ptr->tm_year +1900;
        if( leap_wk % 4 != 0 )
        {
        /*  Year not divisible by 4 => NOT a leap year  */
            return GLOBUS_NULL;
        }
        /*  Year is divisible by 4 => MIGHT be a leap year  */
        if(   ( leap_wk % 100 == 0 )
           && ( leap_wk % 400 != 0 ))
        {
        /*  Year divisible by 100 but not 400 => NOT a leap year  */
            return GLOBUS_NULL;
        }
    }

    return date_wk_ptr;
}

