/**
 * @file globus_thread_common.h Common Thread Interface
 *
 * $Source$<br />
 * $Date$<br />
 * $Revision$<br />
 * $Author$<br />
 */

/******************************************************************************
globus_common_thread

Description:

CVS Information:
******************************************************************************/

#ifndef GLOBUS_THREAD_COMMON_H
#define GLOBUS_THREAD_COMMON_H

#include "globus_common_include.h"
#include "globus_module.h"
#include "globus_callback.h"

EXTERN_C_BEGIN


extern globus_module_descriptor_t       globus_i_thread_common_module;

#define GLOBUS_THREAD_COMMON_MODULE     (&globus_i_thread_common_module)

/******************************************************************************
			     Include header files
******************************************************************************/

typedef int                                   globus_thread_callback_index_t;

/**************************************************************************
*  function prototypes
**************************************************************************/
typedef
void
(*globus_thread_blocking_func_t)(
    globus_thread_callback_index_t      ndx,
    globus_callback_space_t             space,
    void *                              user_args);

#define globus_thread_blocking_callback_push(f, u, i)                       \
    globus_thread_blocking_space_callback_push(                             \
        (f), (u), GLOBUS_CALLBACK_GLOBAL_SPACE, (i))
        
int
globus_thread_blocking_space_callback_push(
    globus_thread_blocking_func_t       func,
    void *                              user_args,
    globus_callback_space_t             space,
    globus_thread_callback_index_t *    i);

int
globus_thread_blocking_callback_pop(
    globus_thread_callback_index_t *    i);

int 
globus_thread_blocking_callback_enable(
    globus_thread_callback_index_t *    i);


int 
globus_thread_blocking_callback_disable(
    globus_thread_callback_index_t *    i);

#define globus_thread_blocking_will_block()                             \
    globus_thread_blocking_space_will_block(GLOBUS_CALLBACK_GLOBAL_SPACE)

int 
globus_thread_blocking_space_will_block(
    globus_callback_space_t             blocking_space);

void
globus_thread_prefork();

void
globus_thread_postfork();

void
globus_thread_blocking_reset();

void thread_print(char * s, ...);

/* common documentation goes here */

/**
 * @defgroup globus_common_thread Globus Thread API
 *
 *
 */
/* @{ */

/** 
 * @fn int globus_condattr_setspace(globus_condattr_t * attr, globus_callback_space_t space)
 *  
 * Use this function to associate a space with a cond attr.
 * This will allow globus_cond_wait to poll the appropriate space
 * (if applicable)
 *
 * A condattr's default space is GLOBUS_CALLBACK_GLOBAL_SPACE
 *
 *  @param attr
 *         attr to associate space with.
 *
 *  @param space
 *         a previously initialized space
 *
 *  @return 
 *         - 0 on success
 *
 * @see globus_callback_spaces
 */

/** 
 * @fn int globus_condattr_getspace(globus_condattr_t * attr, globus_callback_space_t * space)
 *  
 * Use this function to retrieve the space associated with a condattr
 *
 *  @param attr
 *         attr to associate space with.
 *
 *  @param space
 *         storarage for the space to be passed back
 *
 *  @return 
 *         - 0 on success
 *
 * @see globus_callback_spaces
 */

/* @} */

EXTERN_C_END

#endif


