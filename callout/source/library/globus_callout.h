#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_callout.c
 * Globus Callout Infrastructure
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef _GLOBUS_CALLOUT_H_
#define _GLOBUS_CALLOUT_H_

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN

#include <globus_common.h>

/** 
 * @defgroup globus_callout_activation Activation
 *
 * Globus Callout API uses standard Globus module activation and
 * deactivation.  Before any Globus Callout API functions are called, the
 * following function must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_CALLOUT_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if Globus Callout API was
 * successfully initialized, and you are therefore allowed to
 * subsequently call Globus Callout API functions.  Otherwise, an error
 * code is returned, and Globus GSI Credential functions should not be
 * subsequently called. This function may be called multiple times.
 *
 * To deactivate Globus Callout API, the following function must be called:
 *
 * @code
 *    globus_module_deactivate(GLOBUS_CALLOUT_MODULE)
 * @endcode
 *
 * This function should be called once for each time Globus Callout API
 * was activated. 
 *
 */

/** Module descriptor
 * @ingroup globus_callout_activation
 * @hideinitializer
 */
#define GLOBUS_CALLOUT_MODULE    (&globus_i_callout_module)

extern 
globus_module_descriptor_t              globus_i_callout_module;


typedef struct globus_i_callout_s * globus_callout_handle_t;

typedef globus_result_t (*globus_callout_function_t)(
    va_list                             ap);

globus_result_t
globus_callout_handle_init(
    globus_callout_handle_t *           handle,
    char *                              filename);

globus_result_t
globus_callout_handle_destroy(
    globus_callout_handle_t             handle);

globus_result_t
globus_callout_call_type(
    globus_callout_handle_t             handle,
    char *                              type,
    ...);


EXTERN_C_END

#endif
