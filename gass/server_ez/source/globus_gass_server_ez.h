/******************************************************************************
globus_gass_server_ez.h
 
Description:
    Simple wrappers around globus_gass_server API for server functionality.
    Implements the following:
        Write access to local files, with optional line buffering
	Write access to stdout and stderr
	Shutdown callback, so client can stop the server
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_SIMPLE_SERVER_H_
#define _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_SIMPLE_SERVER_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_gass_server.h"

EXTERN_C_BEGIN

#define GLOBUS_GASS_SERVER_EZ_LINE_BUFFER              1
#define GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND             2
#define GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND        5
#define GLOBUS_GASS_SERVER_EZ_READ_ENABLE              8
#define GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE             16
#define GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE            32
#define GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE            64
#define GLOBUS_GASS_SERVER_EZ_CLIENT_SHUTDOWN_ENABLE   128

typedef void (*globus_gass_server_ez_client_shutdown_t) (void);

int
globus_gass_server_ez_init(unsigned short *port,
		    char **url,
		    unsigned long options,
		    globus_gass_server_ez_client_shutdown_t callback);
int
globus_gass_server_ez_shutdown(unsigned short port);

#define globus_gass_server_ez_poll() globus_gass_server_poll()
/******************************************************************************
 *                    Module Definition
 *****************************************************************************/
#define GLOBUS_GASS_SERVER_EZ_MODULE (&globus_gass_server_ez_module)

static globus_module_descriptor_t globus_gass_server_ez_module =
{
    "globus_gass_server_ez",
    GLOBUS_NULL,
    GLOBUS_NULL,
    GLOBUS_NULL
};


EXTERN_C_END

#endif
