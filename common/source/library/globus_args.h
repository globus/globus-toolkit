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

#ifndef GLOBUS_ARGS_H
#define GLOBUS_ARGS_H

EXTERN_C_BEGIN

#include "globus_module.h"
#include "globus_list.h"

#define GLOBUS_ARGS_HELP        -2  /* for -help and -usage */
#define GLOBUS_ARGS_VERSION     -3  /* for -version and -versions */


/*  globus_args.h : a Globus-style argument option parser

    The API implements the following behavior:

    (1) Valid flags are detected as one '-' followed by any character that is
        not '-'.

    (2) A flag may have zero or more predicates (values) associated with it,
        but for any given flag the number of those (the arity) is fixed.

    (3) If a flag has arity of k>0, then the k arguments following the flag
        are taken verbatim as the predicates associated with the flag,
	including leading '-', if any.

    (4) Flagged arguments must not be combined (i.e., "-fg" is never the same
        as "-f -g".

    (5) The end of flagged arguments will be detected either implicitly (with
        the first unrecognized or non-flagged argument) or explicitly (when
	"--" is detected when scanning for the next argument flag).

    (6) When scanning for the next argument flag, an error is detected if the
        detected argument begins with "--*", where '*' is any character.

    (7) The argument flags "-help", "-usage", "-version", and "-versions" are 
        reserved, and if they are detected the library will create an 
        appropriate message and signal an error.

    (8) If an error is detected, then the library will create an error message.

    (9) A created error message will be written to stderr, unless dictated
        otherwise by the user (in which case the error message will be passed
	back to the user).
*/


/*   prototype definition of the predicate test function */

typedef int (*globus_args_valid_predicate_t) (char *    arg_value,
                                              void *    validation_value,
                                              char **   error_msg); 


/*  option specification datatype

    An option can have several names: "-foo" or "-f" for short, etc.
    The parsing library therefore identifies an option trough its
    id_number. The user must ensure that the id_number is unique for
    each descriptor_t.

    The arity of an option is defined as its number of predicates
    (following arguments): "-debug" has arity 0, "-foo xyz 123"
    has arity 2, etc.

    The array of predicate test functions, "tests", may be or contain
    GLOBUS_NULL. Any non-null entry in the tests array must have a
    non-null entry in the "test_parms" array.
*/

typedef struct globus_args_option_descriptor_s
{
    int                              id_number;    /* unique integer */
    char **                          names;        /* null-terminated array */
    int                              arity;        /* number of arguments */
    globus_args_valid_predicate_t *  tests;        /* array of size "arity" */ 
    void **                          test_parms;   /* test function parms */
} globus_args_option_descriptor_t;


/*  option instance datatype 

    when a correctly specified argument option is found, an instance of it
    is recorded and returned on the format specified in this struct. The
    'arity' is provided for user-level consistency checks.

    'value' is an array of pointers to the option's predicates: these are
    pointers to entries in argv[], and should therefore be treated as
    read-only, to conform with POSIX standard.
*/

typedef struct globus_args_option_instance_s
{ 
    int        id_number; 
    int        arity; 
    char **    values;
} globus_args_option_instance_t; 



/*  globus_args_scan() -- the parsing function 

    This function scans the argument list 'argv', validates the
    arguments as appropriate, and builds an ordered list with the
    successfully validated argument options.
    
    An option is successfully validated if it is found in the
    'options' array, and the predicate values associated with it
    passes the predicate test functions associated with the same
    option.

    If 'error_msg' is null, messages will be written to
    stderr. Otherwise, it will be pointed to an allocated buffer which
    must be freed by the user, containing the error message.

    A 'reserved option' is one of the 0-arity options "-help",
    "-usage", "-version", or "-versions". When detected, a message is created
    (and written to stderr if error_msg is null), containing the
    appropriate information. A reserved option will terminate the
    argument scanning and return.

    The successfully validated options are removed from the 'argv' list
    unless an error is detected. 'argc' is updated accordingly. The
    argc/argv convention with argv[0] being the name of the executable
    is maintained.

    Returns:
    -> The number of successfully identified and validated options.
    -> -1 if an error was detected
    -> GLOBUS_ARGS_HELP or GLOBUS_ARGS_VERSION
       if the corresponding reserved option was detected
       (all < 0)

*/

int 
globus_args_scan( int  *                                argc,
		  char ***                              argv,
		  int                                   option_count,
		  globus_args_option_descriptor_t  *    options,
		  const char *                          name,
		  const globus_version_t *              version,
		  const char *                          oneline_usage,
		  const char *                          long_usage,
		  globus_list_t **                      options_found,
		  char **                               error_msg    ); 


/* globus_args_destroy_option_instance_list()

   globus_args_destroy_option_instance_list() correctly destroys the
   list of globus_args_option_instance_t, created by
   globus_args_scan(). It takes into account the dynamically allocated
   elements in the struct : just calling globus_list_destroy() will
   cause memory leaks.

   */

void
globus_args_option_instance_list_free( globus_list_t **  list );


/*  provided predicate functions */


int
globus_validate_int( char *         value,
                     void *         parms,
                     char **        error_msg ); 

/*  globus_args_validate_int() verifies that value is a valid integer (in
    octal, decimal, or hexadecimal format) and does further validation based
    on the values in *parms, which is of the following range check type */

#define GLOBUS_VALIDATE_INT_NOCHECK  0x00
#define GLOBUS_VALIDATE_INT_MIN      0x01
#define GLOBUS_VALIDATE_INT_MAX      0x02
#define GLOBUS_VALIDATE_INT_MINMAX   0x03    /* 3 == (min | max) */

typedef struct globus_validate_int_parms_s
{
    int     range_type;        /* one of GLOBUS_VALIDATE_INT_*  */
    int     range_min;         /* inclusive min value */
    int     range_max;         /* inclusive max value */
} globus_validate_int_parms_t;



/*  globus_validate_filename() verifies that value is a valid file (and
    path), based on *parms, which is an int with one or several values of
    the standard O_RDONLY, O_RDWR, O_CREAT, O_WRONLY, O_APPEND.

    NOTE: the validation is done by actually trying to open the file in
    the mode described by *parms. */

int
globus_validate_filename( char *    value,
                          void *    parms,
                          char **   error_msg );


/* ----------------------------------------------------------------------------
    globus_bytestr_to_num()

    converts a string such as 40M, 256K, 2G to an equivalent off_t.  
    Valid multipliers are  G,g, M,m, K,k, B,b.
    
    Returns 0 on success, nonzero on error.

*/
int
globus_args_bytestr_to_num( 
    const char *                        str,
    globus_off_t *                      out);

EXTERN_C_END

#endif /* ifndef GLOBUS_ARGS_H */


