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
globus_memory.h

Description:

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

#if !defined(GLOBUS_INCLUDE_GLOBUS_MEMORY_H)
#define GLOBUS_INCLUDE_GLOBUS_MEMORY_H 

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common_include.h"
#include GLOBUS_THREAD_INCLUDE

EXTERN_C_BEGIN

/******************************************************************************
			       Type definitions
******************************************************************************/

struct globus_memory_s;
typedef struct globus_memory_s *                globus_memory_t;

globus_bool_t
globus_i_memory_pre_activate();

/**
 *  Initialize the globus memory management structure.
 *
 *  Before using any functions associate with a memory structure
 *  this function must be called.
 *
 *  @param mem_info
 *          The memory management datatype
 *
 *  @param node_size
 *          The size of the memory to allocated with each pop.
 *
 *  @param node_count
 *          The initial number of nodes allocated with the memory
 *          management structure.  If it is exceded more will be 
 *          allocated.
 */
globus_bool_t
globus_memory_init(
    globus_memory_t *             mem_info,
    int                           node_size,
    int                           node_count);

/**
 *  pop a chunk of memory out of the memory management structure.
 *  Equalent of a malloc.
 */
void *
globus_memory_pop_node(
    globus_memory_t *                           mem_info);

/**
 *  push a chunk of memory back into the meory managemnt structure.
 *  equalvalent to a free.
 */
globus_bool_t
globus_memory_push_node(
    globus_memory_t *          mem_info,
    void *                      buf);

/**
 *  Free all the mmory associated with the memory management structure.
 *  For every call to globus_memory_init() there should be a call to
 *  globus_memory_destroy() or else memory will leak.
 */
globus_bool_t
globus_memory_destroy(
    globus_memory_t *                           mem_info);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_MEMORY_H */
