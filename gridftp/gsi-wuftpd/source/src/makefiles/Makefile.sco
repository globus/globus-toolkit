#
# Copyright (c) 1999,2000 WU-FTPD Development Group.
# All rights reserved.
# 
# Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994 
#    The Regents of the University of California.  
# Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.  
# Portions Copyright (c) 1989 Massachusetts Institute of Technology.  
# Portions Copyright (c) 1998 Sendmail, Inc.
# Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P. Allman.  
# Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.  
# Portions Copyright (C) 1991, 1992, 1993, 1994, 1995 1996, 1997 
#    Free Software Foundation, Inc.  
# Portions Copyright (c) 1997 Stan Barber.  
# Portions Copyright (c) 1997 Kent Landfield.
# 
# Use and distribution of this software and its source code are governed by 
# the terms and conditions of the WU-FTPD Software License ("LICENSE").
# 
# If you did not receive a copy of the license, it may be obtained online at
# http://www.wu-ftpd.org/license.html.
# 
# $Id$
#

#
# Makefile for SCO OpenServer 5
#
# When using gcc or egcs on OpenServer 5 change -belf to -melf in CFLAGS.
#

CC       = cc
IFLAGS   = -I.. -I../support
LFLAGS   = -L../support
CFLAGS   = -belf -O ${IFLAGS}
XOBJS    = 
LIBES    = -lsupport -lsocket -lprot -lx -lm -lcurses -lcrypt
# To build on SCO Unix 3.2v4 remove -belf from CFLAGS and change LIBES:
# 1) If you do not have -lprot, use -lprot_s instead.
# 2) -lcrypt can be used in place of -lcrypt_i. If you do not have any crypt
#    library, get and install ftp.sco.com:/SLS/lng225* (International Crypt
#    Supplement), then use -lcrypt_i.
# 3) Never remove -lc; -lx should always be the last lib.
#LIBES    = -lsupport -lsocket -lprot_s -lcrypt_i -lc_s -lc -lx
#LIBES    = -lsupport -lsocket -lprot -lcrypt_i -lc_s -lc -lx
LINTFLAGS=	
#LKERB    =
XLIBS    = ${LIBES}
XXLIBS   = -lsocket
MKDEP    = ../util/mkdep

