/****************************************************************************  
 
  Copyright (c) 1999,2000 WU-FTPD Development Group.  
  All rights reserved.
  
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994
    The Regents of the University of California.
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.
  Portions Copyright (c) 1998 Sendmail, Inc.
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.
  Portions Copyright (c) 1997 by Stan Barber.
  Portions Copyright (c) 1997 by Kent Landfield.
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997
    Free Software Foundation, Inc.  
 
  Use and distribution of this software and its source code are governed 
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 
  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.org/license.html.
 
  $Id$
 
****************************************************************************/
/*
 * Definitions for FTP
 * See RFC-765
 */

/*
 * Reply codes.
 */
#define PRELIM		1	/* positive preliminary */
#define COMPLETE	2	/* positive completion */
#define CONTINUE	3	/* positive intermediate */
#define TRANSIENT	4	/* transient negative completion */
#define ERROR		5	/* permanent negative completion */

/*
 * Type codes
 */
#define	TYPE_A		1	/* ASCII */
#define	TYPE_E		2	/* EBCDIC */
#define	TYPE_I		3	/* image */
#define	TYPE_L		4	/* local byte size */

#ifdef FTP_NAMES
char *typenames[] =
{"0", "ASCII", "EBCDIC", "Image", "Local"};
#endif

/*
 * Form codes
 */
#define	FORM_N		1	/* non-print */
#define	FORM_T		2	/* telnet format effectors */
#define	FORM_C		3	/* carriage control (ASA) */
#ifdef FTP_NAMES
char *formnames[] =
{"0", "Nonprint", "Telnet", "Carriage-control"};
#endif

/*
 * Structure codes
 */
#define	STRU_F		1	/* file (no record structure) */
#define	STRU_R		2	/* record structure */
#define	STRU_P		3	/* page structure */
#ifdef FTP_NAMES
char *strunames[] =
{"0", "File", "Record", "Page"};
#endif

/*
 * Mode types
 */
#define	MODE_S		1	/* stream */
#define	MODE_B		2	/* block */
#define	MODE_C		3	/* compressed */
#define	MODE_E		4	/* extened block */
#ifdef FTP_NAMES
char *modenames[] =
{"0", "Stream", "Block", "Compressed", "Extended Block"};
#endif

/*
 * Record Tokens
 */
#define	REC_ESC		'\377'	/* Record-mode Escape */
#define	REC_EOR		'\001'	/* Record-mode End-of-Record */
#define REC_EOF		'\002'	/* Record-mode End-of-File */

/*
 * Block Header
 */
#define	BLK_EOR		0x80	/* Block is End-of-Record */
#define	BLK_EOF		0x40	/* Block is End-of-File */
#define BLK_ERRORS	0x20	/* Block is suspected of containing errors */
#define	BLK_RESTART	0x10	/* Block is Restart Marker */

#define	BLK_BYTECOUNT	2	/* Bytes in this block */


/*
 * Protection levels
 */
#define	PROT_C		1	/* clear */
#define	PROT_S		2	/* safe */
#define	PROT_P		3	/* private */
#define	PROT_E		4	/* confidential */

#ifdef FTP_NAMES
char *levelnames[] =  {"0", "Clear", "Safe", "Private", "Confidential" };
#endif
