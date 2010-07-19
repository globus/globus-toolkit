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
globus_i_thread.h

Description:
   Internal Macros for Globus threads library.

CVS Information:
   $Source$
   $Date$
   $Revision$
   $State$
   $Author$
******************************************************************************/

#if !defined(GLOBUS_INCLUDE_GLOBUS_I_THREAD)
#define GLOBUS_INCLUDE_GLOBUS_I_THREAD 1

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common_include.h"

#define GLOBUS_L_LIBC_MAX_ERR_SIZE 512

#define GlobusThreadMalloc(Func, Var, Type, Size) \
{ \
    if ((Size) > 0) \
    { \
	if (((Var) = (Type) globus_malloc (Size)) == (Type) NULL) \
	{ \
	    globus_fatal(\
		"%s: malloc of size %d failed for %s %s in file %s line %d\n",\
                #Func, (Size), #Type, #Var, __FILE__, __LINE__); \
	} \
    } \
    else \
    { \
	(Var) = (Type) NULL; \
    } \
}

#define GlobusThreadFree(Ptr) \
{ \
    if ((Ptr) != NULL) \
    { \
	globus_macro_free(Ptr); \
    } \
}    

EXTERN_C_BEGIN

/*
 * globus_i_thread_report_bad_rc()
 */
void
globus_i_thread_report_bad_rc(int rc,
			      char *message );

#define globus_i_thread_test_rc( a, b )				\
    do								\
    {                                                   	\
	if( a != GLOBUS_SUCCESS && a != EINTR )			\
	{							\
	    globus_i_thread_report_bad_rc( a, b );		\
	}							\
	else							\
	{							\
	    a = GLOBUS_SUCCESS;;				\
	}							\
    } while(0)

int globus_i_thread_ignore_sigpipe(void);



#define MAX_ERR_SIZE			80
#define GLOBUS_I_THREAD_GRAN 		256
#define GLOBUS_I_THREAD_USER_THREAD 	0

#ifndef GLOBUS_THREAD_DEFAULT_STACK_SIZE
#define GLOBUS_THREAD_DEFAULT_STACK_SIZE 0
#endif


EXTERN_C_END

#endif


