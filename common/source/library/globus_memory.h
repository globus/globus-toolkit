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

#define DEFAULT_FREE_PTRS_SIZE 16
/******************************************************************************
			       Type definitions
******************************************************************************/
/* memory management stuff */

extern globus_mutex_t          globus_i_memory_mutex;

typedef struct globus_l_memory_header_s
{
    globus_byte_t *            next;
} globus_l_memory_header_t;

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

globus_bool_t
globus_memory_create_list(
    globus_memory_t *           mem_info);

globus_byte_t *
globus_memory_pop_node(
    globus_memory_t *           mem_info);

globus_bool_t
globus_memory_push_node(
    globus_memory_t *          mem_info,
    globus_byte_t *              buf);

globus_bool_t
globus_memory_destroy(
    globus_memory_t *          mem_info);

#define GLOBUS_CALLBACK_MODULE (&globus_i_callback_module)

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_CALLBACK */
