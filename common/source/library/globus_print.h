#if !defined(GLOBUS_INCLUDE_GLOBUS_PRINT_H)
#define GLOBUS_INCLUDE_GLOBUS_PRINT_H 1

#include "config.h"  
#include "globus_common_internal.h"

EXTERN_C_BEGIN

/**
 */
extern void globus_fatal(char *msg, ...);
/**
 */
extern void globus_silent_fatal(void);
/**
 */
extern void globus_error(char *msg, ...);
/**
 */
extern void globus_warning(char *msg, ...);
/**
 */
extern void globus_notice(char *msg, ...);
/**
 */
extern void globus_perror(char *msg, ...);
/**
 */
extern void globus_fatal_perror(char *msg, ...);
/**
 */
extern char *globus_assert_sprintf(char *msg, ...);
/**
 */
extern char *globus_get_unique_session_string(void);

EXTERN_C_END

#endif
