#if !defined(GLOBUS_THREAD_POOL_H)
#define GLOBUS_THREAD_POOL_H 1

#include "globus_common_include.h"
#include GLOBUS_THREAD_INCLUDE

EXTERN_C_BEGIN

int
globus_i_thread_pool_activate(void);

int
globus_i_thread_pool_deactivate(void);

void
globus_i_thread_start(
    globus_thread_func_t                func,
    void *                              user_arg);
int
globus_thread_pool_key_create(  
    globus_thread_key_t *                 key,     
    globus_thread_key_destructor_func_t   func);

/******************************************************************************
                               Module definition
******************************************************************************/
extern globus_module_descriptor_t       globus_i_thread_pool_module;

#define GLOBUS_THREAD_POOL_MODULE (&globus_i_thread_pool_module)

EXTERN_C_END

#endif


