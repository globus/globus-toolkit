/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/**********************************************************************
winglue.h:

Description:
	This header file used with WIN32 apps to define a number of 
	Windows only routines
	routines

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

#ifndef _WINGLUE_H
#define _WINGLUE_H
#ifdef	__cplusplus
extern "C" {
#endif

/**********************************************************************
                             Include header files
**********************************************************************/

#include <windows.h>

#if 0
#include <stdio.h>
#include <stdlib.h>
#include "ssl.h"
#include "err.h"
#include "bio.h"
#include "pem.h"
#include "x509.h"
#include "stack.h"
#endif
/**********************************************************************
                               Define constants
**********************************************************************/



/**********************************************************************
                               Type definitions
**********************************************************************/



/**********************************************************************
                               Global variables
**********************************************************************/

/**********************************************************************
                               Function prototypes
**********************************************************************/

int
ERR_print_errors_MessageBox(HWND hwnd, char * title);

void
save_instance(HINSTANCE hinst);

int 
read_passphrase_win32(char *buf, int num, int w);

int
read_passphrase_win32_prompt(char * prompt);

#ifdef __cplusplus
} 
#endif

#endif /* _WINGLUE_H */
