
#ifndef GLOBUS_DEBUG_H
#define GLOBUS_DEBUG_H


#include "globus_common_include.h"

 
EXTERN_C_BEGIN
 

/* MACRO to instantiate a module-specific debug interface declaration */
/* each module will get a set of functions:
 *   extern void module_name_set_diagnostics_file (FILE *fp);
 *   extern int  module_name_diagnostics_vprintf (const char *format,
 *                                                va_list ap);
 *   extern int  module_name_diagnostics_printf (const char *format,
 *                                               ...); */
#define globus_declare_debug_interface(module_name)                        \
extern void                                                                \
module_name##_set_diagnostics_file (FILE *file);                           \
extern int                                                                 \
module_name##_diagnostics_vprintf (const char *format, va_list ap);        \
extern int                                                                 \
module_name##_diagnostics_printf (const char *format, /* args */ ...);

/* for all *_set_diagnostic_file (FILE *file) routines:
 *
 * default at process start is same as file==stderr
 * send messages after call returns to  file
 * file==NULL means disable diagnostics
 */

globus_declare_debug_interface(globus)

globus_declare_debug_interface(duroc_runtime)
globus_declare_debug_interface(duroc_control)
globus_declare_debug_interface(duroc_bootstrap)
globus_declare_debug_interface(duroc)

globus_declare_debug_interface(gram_client)
globus_declare_debug_interface(gram)

globus_declare_debug_interface(globus_thread)

/* ADD ADDITIONAL MODULE INTERFACES HERE... */


EXTERN_C_END


#endif /* GLOBUS_DEBUG_H */



