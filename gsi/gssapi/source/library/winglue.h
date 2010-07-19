/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
