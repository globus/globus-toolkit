/******************************************************************************
globus_common_thread

Description:

CVS Information:
******************************************************************************/

#ifndef GLOBUS_THREAD_COMMON_H
#define GLOBUS_THREAD_COMMON_H

#include "globus_common_include.h"
#include "globus_module.h"

EXTERN_C_BEGIN


extern globus_module_descriptor_t       globus_i_thread_common_module;

#define GLOBUS_THREAD_COMMON_MODULE     (&globus_i_thread_common_module)

/******************************************************************************
			     Include header files
******************************************************************************/

typedef int                                   globus_thread_result_t;
typedef int                                   globus_thread_callback_index_t;

/**************************************************************************
*  function prototypes
**************************************************************************/
typedef
void *
(*globus_thread_blocking_func_t)(
    globus_thread_callback_index_t      ndx,
    void *                              user_args);

globus_thread_result_t
globus_thread_blocking_callback_push(
    globus_thread_blocking_func_t        func,
    void *                               user_args,
    globus_thread_callback_index_t *     i);

globus_thread_result_t
globus_thread_blocking_callback_pop(
    globus_thread_callback_index_t *     i);

globus_thread_result_t 
globus_thread_blocking_callback_enable(
    globus_thread_callback_index_t *  i);


globus_thread_result_t 
globus_thread_blocking_callback_disable(
    globus_thread_callback_index_t *  i);

globus_thread_result_t 
globus_thread_blocking_will_block();

void
globus_thread_prefork();

void
globus_thread_postfork();

void
globus_thread_blocking_reset();

void thread_print(char * s, ...);

EXTERN_C_END

#endif


