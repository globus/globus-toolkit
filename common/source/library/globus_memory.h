/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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
