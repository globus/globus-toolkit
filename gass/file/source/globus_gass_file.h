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

int globus_gass_open(char *file, int oflags, ...);
FILE *globus_gass_fopen(char *file, char *mode);
int globus_gass_close(int fd);
int globus_gass_fclose(FILE *f);

/******************************************************************************
 *                    Module Definition
 *****************************************************************************/
extern int
globus_i_gass_file_activate(void);

extern int
globus_i_gass_file_deactivate(void);

#define GLOBUS_GASS_FILE_MODULE (&globus_gass_file_module)

static globus_module_descriptor_t globus_gass_file_module =
{
    "globus_gass_file",
    globus_i_gass_file_activate,
    globus_i_gass_file_deactivate,
    GLOBUS_NULL
};
EXTERN_C_END

#endif
