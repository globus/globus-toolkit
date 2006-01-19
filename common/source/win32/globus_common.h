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

/******-*- C -*-**************************************************************
globus_common.h

Description:
  Headers common to all of Globus

CVS Information:

  $Source$
  $Date$
  $State$
  $Author$
******************************************************************************/

#if !defined(GLOBUS_INCLUDE_GLOBUS_COMMON_H)
#define GLOBUS_INCLUDE_GLOBUS_COMMON_H 1


/******************************************************************************
		      Include globus_common header files
******************************************************************************/
#include "globus_common_include.h"
#include "globus_args.h"
#include "globus_callback.h"
#include "globus_debug.h"
#include "globus_error.h"
#include "globus_error_errno.h"
#include "globus_error_generic.h"
#include "globus_error_hierarchy.h"
#include "globus_error_string.h"
#include "globus_fifo.h"
#include "globus_handle_table.h"
#include "globus_hashtable.h"
#include "globus_libc.h"
#include "globus_list.h"
#include "globus_memory.h"
#include "globus_module.h"
#include "globus_object.h"
#include "globus_object_cache.h"
#include "globus_object_hierarchy.h"
#include "globus_print.h"
#include "globus_priority_q.h"
#include "globus_strptime.h"
#include "globus_symboltable.h"
#include "globus_thread_common.h" 
#include GLOBUS_THREAD_INCLUDE
#include "globus_thread_pool.h"
#include "globus_tilde_expand.h"
#include "globus_time.h"
#include "globus_url.h"

# if !defined(alloca)
/* AIX requires this to be the first thing in the file.  */
#ifdef __GNUC__
# define alloca __builtin_alloca
#else
# if HAVE_ALLOCA_H
#  include <alloca.h>
# else
#  ifdef _AIX
#pragma alloca
#  else
#   ifndef alloca /* predefined by HP cc +Olibcalls */
#     ifndef _CRAYT3E
char *alloca ();
#     endif
#   endif
#  endif
# endif
#endif
#endif

#if !defined(MAXPATHLEN) 
#   include <sys/param.h>
#   define MAXPATHLEN PATH_MAX
#endif
EXTERN_C_BEGIN

/* most network-related functions (getpeername, getsockname,...) have
   an int* as argument, except AIX which uses size_t*. This will
   masquerade the difference. */
#define globus_netlen_t int

/*
 * globus_barrier_t
 *
 * A generic barrier structure */
typedef struct globus_barrier_s
{
    globus_mutex_t      mutex;
    globus_cond_t       cond;
    int                 count;
} globus_barrier_t;

/******************************************************************************
			       Define constants
******************************************************************************/
 
/******************************************************************************
			  Module activation structure
******************************************************************************/
extern globus_module_descriptor_t	globus_i_common_module;

#define GLOBUS_COMMON_MODULE (&globus_i_common_module)


/******************************************************************************
		   Install path discovery functions
******************************************************************************/

globus_result_t
globus_location (  char **   bufp );

/* returns value of GLOBUS_LOCATION in the deploy dir config file */
globus_result_t
globus_common_get_attribute_from_config_file( 
	char *                                         deploy_path,
    char *                                         file_location,
	char *                                         attribute,
	char **                                        value);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_COMMON_H */
