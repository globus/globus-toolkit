/******************************************************************************
globus_gass_file_api.h
 
Description:
    This header contains the GASS File Access API definitions
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_FILE_API_H
#ifndef SWIG
#define _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_FILE_API_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include <stdio.h>

EXTERN_C_BEGIN

/*endif SWIG */
#endif

/*
  SWIG does not support variable number of arguments
  For The time being, let make it simple, I will see how this ca be modified
  (I gess we could have 2 functions ? or may be newer version of swig do
  support variable number of arguments ?)
 */
#ifndef SWIG
int globus_gass_open(char *file, int oflags, ...);
#else
int globus_gass_open(char *file, int oflags);
/*endif SWIG */
#endif


FILE *globus_gass_fopen(char *file, char *mode);
int globus_gass_close(int fd);
int globus_gass_fclose(FILE *f);

#ifndef SWIG

/******************************************************************************
 *                    Module Definition
 *****************************************************************************/
extern globus_module_descriptor_t globus_i_gass_file_module;
#define GLOBUS_GASS_FILE_MODULE (&globus_i_gass_file_module)

EXTERN_C_END

/*endif SWIG */
#endif

#endif
