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

/*
 *  This is a modified (mostly condensed) version of the UNICOS
 *  extensions to SSH -- see original comments below for details
 *  on this source.
 *
 *  Mod Author: Brent Milne (BMilne@lbl.gov)
 *              September 1998
 */ 


/*
 *  $Source$
 *  $Revision$
 *  $Date$
 *
 *  Purpose:
 *      Define prototypes for UNICOS unicos routines.
 *
 *  Author:		Randy Bremmer, March 1998
 *			Los Alamos National Laboratory
 *  Modification $Author$
 *  Maintenance and modification 
 *	$Log$
 *	Revision 1.3  2006/01/19 15:44:48  bester
 *	Exciting new license!
 *	
 *	Revision 1.2  2005/04/18 21:33:07  smartin
 *	added license statements before the 4.0.0 release
 *	
 *	Revision 1.1  1998/12/07 17:05:50  bester
 *	added Cray MLS security code from NERSC
 *	
 *	Revision 1.1  1998/12/07 17:03:34  bester
 *	added unicos MLS security code from NERSC
 *
 *	Revision 1.6  1998-06-18 15:46:59-06  rrb
 *	Change definition of mls_validate to include the havepty
 *	argument.
 *
 *	Revision 1.5  1998-05-27 15:23:03-06  rrb
 *	LANL modifications.
 *	Include ssh-lanl.h.
 *
 *	Revision 1.3  1998-05-18 15:29:35-06  rrb
 *	Remove crayuser_disallowed.
 *	Add unicos_access_denied.
 *
 *	Revision 1.3  1998-05-18 14:45:51-06  rrb
 *	Replace crayuser_disallowed with unicos_access_denied.
 *
 *	Revision 1.2  1998-05-14 09:12:34-06  rrb
 *	Intermediate check-in.
 *	Fixed definition of FLAGREG and TmpDir.
 *	Add "const" in function prototypes where appropriate.
 *
 *	Revision 1.1  1998-05-13 14:49:49-06  rrb
 *	Initial revision
 *
 */
#ifndef	__gatekeeper_unicos_
#define	__gatekeeper_unicos_

#ifdef	TARGET_ARCH_CRAYT3E
/* Function prototypes */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/usrv.h>


#define TRUE 1
#define FALSE 0
typedef int logical;
#define FLAGREG register logical

#if defined(__STDC__) || defined(__cplusplus)
# define P_(s) s
#else
# define P_(s) ()
#endif

int	cray_setup		P_(( uid_t user_uid, const char *user_name ));
void	get_udbent		P_(( const char* user ));
void	get_unicos_connect_info	P_(( int sfd ));
void	set_seclabel		P_(( void ));
void	mls_validate		P_(( logical havepty ));
void	set_unicos_sockopts	P_(( int sfd ));
void	showusrv		P_(( const struct usrv* secval ));
void	showprivs		P_(( void ));
logical	unicos_access_denied	P_(( void ));
int	unicos_init		P_(( void ));
void    set_connection_hostname P_(( const char* hostname ));
void	update_udb		P_(( uid_t uid, const char *user, \
				     const char *ttyname));
int	unicos_get_gid		P_(( void ));

# endif	/* TARGET_ARCH_CRAYT3E */
#endif	__gatekeeper_unicos_
