#ifndef GLOBUS_XIO_LOAD_INCLUDE
#define GLOBUS_XIO_LOAD_INCLUDE

#include "globus_xio.h"

EXTERN_C_BEGIN

typedef
globus_result_t
(*globus_xio_driver_init_t)(
    globus_xio_driver_t *               out_driver,
    va_list                             ap);

typedef
void
(*globus_xio_driver_destroy_t)(
    globus_xio_driver_t                 driver);

typedef struct
{
    const char *                        name;
    globus_module_descriptor_t *        module;
    globus_xio_driver_init_t            load;
    globus_xio_driver_destroy_t         unload;
} globus_xio_driver_hook_t;

globus_result_t
globus_xio_driver_load(
    const char *                        driver_name,
    globus_xio_driver_t *               out_driver,
    ...);

globus_result_t
globus_xio_driver_unload(
    globus_xio_driver_t                 driver);

globus_bool_t
globus_xio_driver_error_match(
    globus_xio_driver_t                 driver,
    globus_object_t *                   error,
    int                                 type);

/**
 * GlobusXIODefineDriver(
 *      label                           driver_name,
 *      globus_module_descriptor_t *    module,
 *      globus_xio_driver_init_t        init_func,
 *      globus_xio_driver_destroy_t     destroy_func)
 * 
 *  NOTE: driver_name is not a string.  Just put the unquoted name there.
 */
#define GlobusXIODefineDriver(driver_name, module, init_func, destroy_func) \
globus_xio_driver_hook_t globus_i_xio_##driver_name##_hook =                \
{                                                                           \
    #driver_name,                                                           \
    module,                                                                 \
    init_func,                                                              \
    destroy_func                                                            \
};


/* internal activate funcs */
int
globus_i_xio_load_init(void);

int
globus_i_xio_load_destroy(void);
    
EXTERN_C_END

#endif
