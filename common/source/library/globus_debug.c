#include "globus_debug.h"
#include "globus_libc.h"

/* MACRO to instantiate module-specific static storage */
#define globus_implement_debug_interface_storage(module_name) \
static FILE *module_name##_diagnostics_file = NULL; \
static int   module_name##_diagnostics_file_is_initialized = 0;

globus_implement_debug_interface_storage(globus)

globus_implement_debug_interface_storage(duroc_runtime)
globus_implement_debug_interface_storage(duroc_control)
globus_implement_debug_interface_storage(duroc_bootstrap)
globus_implement_debug_interface_storage(duroc)

globus_implement_debug_interface_storage(gram_client)
globus_implement_debug_interface_storage(gram)

globus_implement_debug_interface_storage(globus_thread)

/* ADD ADDITIONAL MODULE STORAGE INSTANTIATIONS HERE... */


/* MACROS to instantiate module-specific debug redirection interface */
#define globus_implement_debug_interface_set_file_begin(module_name)     \
void module_name##_set_diagnostics_file (FILE *file)                     \
{                                                                        \
  module_name##_diagnostics_file = file;                                 \
  module_name##_diagnostics_file_is_initialized = 1;                     \
                                                                         \
  /* set diagnostics file for sub-systems */

#define globus_implement_debug_interface_set_file_subsystem(subsystem)   \
  subsystem##_set_diagnostics_file (file);

#define globus_implement_debug_interface_set_file_end(module_name)       \
} /* module_name##_set_diagnostics_file() */


globus_implement_debug_interface_set_file_begin (globus)
  globus_implement_debug_interface_set_file_subsystem (duroc)
  globus_implement_debug_interface_set_file_subsystem (gram)
  globus_implement_debug_interface_set_file_subsystem (globus_thread)
globus_implement_debug_interface_set_file_end (globus)


globus_implement_debug_interface_set_file_begin (duroc)
  globus_implement_debug_interface_set_file_subsystem (duroc_runtime)
  globus_implement_debug_interface_set_file_subsystem (duroc_control)
  globus_implement_debug_interface_set_file_subsystem (duroc_bootstrap)
globus_implement_debug_interface_set_file_end (duroc)

globus_implement_debug_interface_set_file_begin (duroc_runtime)
globus_implement_debug_interface_set_file_end (duroc_runtime)

globus_implement_debug_interface_set_file_begin (duroc_control)
globus_implement_debug_interface_set_file_end (duroc_control)

globus_implement_debug_interface_set_file_begin (duroc_bootstrap)
globus_implement_debug_interface_set_file_end (duroc_bootstrap)


globus_implement_debug_interface_set_file_begin (gram)
  globus_implement_debug_interface_set_file_subsystem (gram_client)
globus_implement_debug_interface_set_file_end (gram)

globus_implement_debug_interface_set_file_begin (gram_client)
globus_implement_debug_interface_set_file_end (gram_client)

globus_implement_debug_interface_set_file_begin (globus_thread)
globus_implement_debug_interface_set_file_end (globus_thread)


/* ADD ADDITIONAL MODULE DEBUG REDIRECTION INSTANTIATIONS HERE... */


/* MACRO to instantiate a module-specific set of output routines */
#define globus_implement_debug_interface_output_functions(module_name)    \
int module_name##_diagnostics_vprintf (const char *format, va_list ap)    \
{                                                                         \
  FILE *fp;                                                               \
  int res;                                                                \
                                                                          \
  if ( module_name##_diagnostics_file_is_initialized )                    \
    fp = module_name##_diagnostics_file;                                  \
  else                                                                    \
    fp = stderr;                                                          \
                                                                          \
  if ( fp != NULL ) {                                                     \
    res = globus_libc_vfprintf (fp, format, ap);                          \
                                                                          \
    return res;                                                           \
  }                                                                       \
  else {                                                                  \
    return 0;                                                             \
  }                                                                       \
}                                                                         \
                                                                          \
int module_name##_diagnostics_printf (const char *format, /* args */ ... ) \
{                                                                         \
  va_list ap;                                                             \
  int res;                                                                \
                                                                          \
  va_start(ap, format);                                                   \
  res = module_name##_diagnostics_vprintf (format, ap);                   \
  va_end(ap);                                                             \
                                                                          \
  return res;                                                             \
}


globus_implement_debug_interface_output_functions (globus)

globus_implement_debug_interface_output_functions (duroc_runtime)
globus_implement_debug_interface_output_functions (duroc_control)
globus_implement_debug_interface_output_functions (duroc_bootstrap)
globus_implement_debug_interface_output_functions (duroc)

globus_implement_debug_interface_output_functions (gram_client)
globus_implement_debug_interface_output_functions (gram)

globus_implement_debug_interface_output_functions (globus_thread)

/* ADD ADDITIONAL MODULE OUTPUT FUNCTION INSTANTIATIONS HERE... */

