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
#include "globus_common.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/******************************************************************************
			       Type definitions
******************************************************************************/

typedef struct globus_memory_s
{
    int                        total_size;
    int                        node_size;
    int                        nodes_used;
    int                        node_count;
    int                        node_count_per_malloc;

    globus_bool_t              destroyed;
    globus_mutex_t             lock;

    globus_byte_t *            first;
    globus_byte_t **           free_ptrs;
    int                        free_ptrs_size;
    int                        free_ptrs_offset;
} globus_memory_t;

globus_bool_t
globus_i_memory_pre_activate();

globus_bool_t
globus_memory_init(
    globus_memory_t *             mem_info,
    int                           node_size,
    int                           node_count);

void *
globus_memory_pop_node(
    globus_memory_t *           mem_info);

globus_bool_t
globus_memory_push_node(
    globus_memory_t *          mem_info,
    void *                      buf);

globus_bool_t
globus_memory_destroy(
    globus_memory_t *          mem_info);

EXTERN_C_END

#endif
