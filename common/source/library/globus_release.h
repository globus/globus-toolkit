#include "globus_config.h"

#ifndef GLOBUS_RELEASE_H
#define GLOBUS_RELEASE_H


/* I have made these routines as macros                    */
/* since you have to include the header file, anyways.     */
/* The only reason why they should be functions is if      */
/* you expect the linker to fill in the appropriate values */
/* but then the user needs to include the prototypes.      */
#define  globus_release_major()    GLOBUS_RELEASE_MAJOR
#define  globus_release_minor()    GLOBUS_RELEASE_MINOR
#define  globus_release_patch()    GLOBUS_RELEASE_PATCH
#define  globus_release_beta()     GLOBUS_RELEASE_BETA

#ifdef GLOBUS_RELEASE_STRING
#define  globus_release_string()   GLOBUS_RELEASE_STRING
#else
#define  globus_release_string()   ""
#endif


#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif
 


#endif /* GLOBUS_DEBUG_H */



