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
# Makefile for Solaris 2.X (SunOS 5.X)
#

CC       = cc

#CC=gcc
#DFLAGS=-DVIRTUAL_DEBUG
#WNOERROR=-Werror
#WARNINGS=$(WNOERROR) -Wall 
#WARNINGS=$(WNOERROR) -Wall -Wpointer-arith -Wcast-align -Wstrict-prototypes -Wmissing-prototypes 

IFLAGS   = -I.. -I../support
LFLAGS   = -L../support
CFLAGS   = -g ${IFLAGS} ${LFLAGS} ${WARNINGS}
XOBJS    = 
# To enable PAM on solaris, add -lpam to the end of LIBES
LIBES    = -lsupport -lsocket -lnsl -lresolv -lgen
LIBC     = /lib/libc.a
LINTFLAGS=	
LKERB    = -lauth -lckrb -lkrb -ldes 
XLIBS    = ${LIBES}
MKDEP    = makedepend

