/******************************************************************************
globus_callback.h

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

#define DEFAULT_FREE_PTRS_SIZE 16
/******************************************************************************
			       Type definitions
******************************************************************************/
/* memory management stuff */

extern globus_mutex_t                           globus_i_memory_mutex;

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
    globus_memory_t *                           mem_info,
    int                                         node_size,
    int                                         node_count);

/**
 *  pop a chunk of memory out of the memory management structure.
 *  Equalent of a malloc.
 */
globus_byte_t *
globus_memory_pop_node(
    globus_memory_t *                           mem_info);

/**
 *  push a chunk of memory back into the meory managemnt structure.
 *  equalvalent to a free.
 */
globus_bool_t
globus_memory_push_node(
    globus_memory_t *                           mem_info,
    globus_byte_t *                             buf);

/**
 *  Free all the mmory associated with the memory management structure.
 *  For every call to globus_memory_init() there should be a call to
 *  globus_memory_destroy() or else memory will leak.
 */
globus_bool_t
globus_memory_destroy(
    globus_memory_t *                           mem_info);

/*
 * module macro
 */
#define GLOBUS_CALLBACK_MODULE (&globus_i_callback_module)

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_CALLBACK */


