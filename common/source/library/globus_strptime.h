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
globus_strptime.h
 
Description:
   Contains only the function globus_strptime.
 
******************************************************************************/
#ifndef GLOBUS_INCLUDE_GLOBUS_STRPTIME_H_
#define GLOBUS_INCLUDE_GLOBUS_STRPTIME_H_ 1
 
#include "globus_common_include.h"
 
 
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

EXTERN_C_BEGIN

char*
globus_strptime(
    char*       date_str,
    char*       format_str,
    struct tm*  time_ptr );

EXTERN_C_END
 
#endif


