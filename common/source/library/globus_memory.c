/******************************************************************************
globus_callback.c

Description:

  A general polling infrastructure

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common.h"

#include <assert.h>

globus_mutex_t                     globus_i_memory_mutex;

#define I_ALIGN_SIZE               sizeof(long)

globus_bool_t
globus_i_memory_pre_activate(void)
{
    globus_mutex_init(
        &globus_i_memory_mutex,
        GLOBUS_NULL);
    return globus_i_list_pre_activate();
}

globus_bool_t
globus_memory_init(
    globus_memory_t *         mem_info,
    int                       node_size,
    int                       node_count)
{
    int                       pad;

    pad = node_size % I_ALIGN_SIZE;

    mem_info->total_size = node_count * (node_size + pad);

    mem_info->node_size = node_size + pad;
    mem_info->node_count = node_count;
    mem_info->nodes_used = 0;
    mem_info->node_count_per_malloc = node_count;
    mem_info->free_ptrs_size = DEFAULT_FREE_PTRS_SIZE;
    mem_info->free_ptrs = (globus_byte_t **)malloc(DEFAULT_FREE_PTRS_SIZE * 
                                 sizeof(globus_byte_t *));
    mem_info->free_ptrs_offset = -1;

    globus_mutex_init(
        &mem_info->lock,
        (globus_mutexattr_t *) GLOBUS_NULL);
    mem_info->destroyed = GLOBUS_FALSE;

    return(globus_memory_create_list(
				mem_info)); 
}

/*
 * this is calledlocked
 */
globus_bool_t
globus_memory_create_list(
    globus_memory_t * mem_info)
{
    int                          ctr;
    globus_l_memory_header_t *   header;
    globus_byte_t *              buf;
    globus_byte_t *              tmp_buf;
    int                          tmp_size;
    
    mem_info->first = globus_malloc(
                          mem_info->node_size * 
                          mem_info->node_count_per_malloc);

    mem_info->free_ptrs_offset++;
    if(mem_info->free_ptrs_offset == mem_info->free_ptrs_size)
    {
        tmp_size = mem_info->free_ptrs_size + DEFAULT_FREE_PTRS_SIZE;
        mem_info->free_ptrs = realloc(mem_info->free_ptrs, 
                  tmp_size * sizeof(globus_byte_t *));
        mem_info->free_ptrs_size = tmp_size;
    }

    mem_info->free_ptrs[mem_info->free_ptrs_offset] = mem_info->first;
    if(mem_info->first == GLOBUS_NULL)
    {
	return GLOBUS_FALSE;
    }

    buf = mem_info->first;
    for(ctr = 0; ctr < mem_info->node_count_per_malloc - 1; ctr++)
    {
        header = (globus_l_memory_header_t *) buf;
	buf += mem_info->node_size;
        header->next = buf;
    }
    header = (globus_l_memory_header_t *) buf;
    header->next = GLOBUS_NULL;

    return GLOBUS_TRUE;
}

globus_byte_t *
globus_memory_pop_node(
    globus_memory_t * mem_info)
{
    globus_l_memory_header_t *   header;
    globus_byte_t *              tmp_byte;
   
    globus_mutex_lock(&mem_info->lock);
    { 
        if(mem_info->destroyed)
        {
            globus_mutex_unlock(&mem_info->lock);
            return GLOBUS_FALSE;
        } 
        /* 
         *  test to see if there is memory left.
         */
        if(mem_info->first == GLOBUS_NULL)
        {
	    mem_info->node_count += mem_info->node_count_per_malloc;
   
            globus_memory_create_list(mem_info);
        }
    
        header = (globus_l_memory_header_t *) mem_info->first;
        tmp_byte = mem_info->first;
        mem_info->first = header->next;
        mem_info->nodes_used++;
    }
    globus_mutex_unlock(&mem_info->lock);

    return tmp_byte;
}

globus_bool_t
globus_memory_push_node(
    globus_memory_t *          mem_info,
    globus_byte_t *              buf)
{
    globus_l_memory_header_t *   header;
    
    globus_mutex_lock(&mem_info->lock);
    { 
        if(mem_info->destroyed)
        {
            globus_mutex_unlock(&mem_info->lock);
            return GLOBUS_FALSE;
        } 
        header = (globus_l_memory_header_t *) (buf);

        header->next = mem_info->first;
        mem_info->first = (globus_byte_t *)header;
        mem_info->nodes_used--;
    } 
    globus_mutex_unlock(&mem_info->lock);

    return GLOBUS_TRUE;
}

globus_bool_t
globus_memory_destroy(
    globus_memory_t * mem_info)
{
/* TODO: fail if memory not freed correctly */
    globus_byte_t *     tmp_byte;
    int                 ctr;

    globus_mutex_lock(&mem_info->lock);
    {
        if(mem_info->nodes_used > 0)
        {
        }
        for(ctr = 0; ctr <= mem_info->free_ptrs_offset; ctr++)
        {
            free(mem_info->free_ptrs[ctr]);
        }
        free(mem_info->free_ptrs);
    }
    globus_mutex_unlock(&mem_info->lock);

    globus_mutex_destroy(&mem_info->lock);
    return GLOBUS_TRUE;
}
