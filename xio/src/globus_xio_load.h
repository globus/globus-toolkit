#ifndef GLOBUS_XIO_SYSTEM_INCLUDE
#define GLOBUS_XIO_SYSTEM_INCLUDE

#include "globus_xio.h"

EXTERN_C_BEGIN

typedef
globus_result_t
(*globus_xio_driver_load_t)(
    globus_xio_driver_t *               out_driver,
    va_list                             ap);

typedef
globus_result_t
(*globus_xio_driver_unload_t)(
    globus_xio_driver_t                 driver);

typedef struct
{
    const char *                        name;
    globus_module_descriptor_t *        module;
    globus_xio_driver_load_t            load;
    globus_xio_driver_unload_t          unload;
} globus_xio_driver_hook_t;

globus_result_t
globus_xio_driver_load(
    const char *                        name,
    globus_xio_driver_t *               out_driver,
    ...);

globus_result_t
globus_xio_driver_unload(
    globus_xio_driver_t                 driver);

/**
 * GlobusXIODefineDriver(
 *      const char *                    driver_name,
 *      globus_module_descriptor_t *    module,
 *      globus_xio_driver_load_t        load_func,
 *      globus_xio_driver_unload_t      unload_func)
 */
#define GlobusXIODefineDriver(driver_name, module, load_func, unload_func)  \
globus_xio_driver_hook_t globus_i_xio_##driver_name##_hook =                \
{                                                                           \
    driver_name,                                                            \
    module,                                                                 \
    load_func,                                                              \
    unload_func                                                             \
};

EXTERN_C_END

#endif
