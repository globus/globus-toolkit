/***************************************************************************
                          my_utility.h  -  description
                             -------------------
    begin                : Fri Nov 2 2001
    copyright            : (C) MySQL AB 1995-2002, www.mysql.com
    author               : venu ( venu@mysql.com )
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *        MySQL ODBC 3.51 Driver - samples utility header                  *
 *                                                                         *
 ***************************************************************************/

#ifndef __TMYODBC_UTILITY_H__
#define __TMYODBC_UTILITY_H__

#ifdef HAVE_CONFIG_H
#include <myconf.h>
#endif

#ifdef WIN32
#include <windows.h>
#endif 

/* STANDARD C HEADERS */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* ODBC HEADERS */
#include <sql.h>
#include <sqlext.h>

#ifndef NULL
#define NULL 0
#endif

#ifndef ushort
#define ushort unsigned short
#endif

#ifndef bool
#define bool unsigned char
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#define MAX_NAME_LEN 95
#define MAX_COLUMNS 255
#define MAX_ROW_DATA_LEN 255
/* PROTOTYPE */
int myerror(SQLRETURN rc,SQLSMALLINT htype, SQLHANDLE handle);

/* UTILITY MACROS */
#define myenv(henv,r)  \
        if ( ((r) != SQL_SUCCESS) )  \
            return myerror(r, 1,henv);
        //assert( ((r) == SQL_SUCCESS) || ((r) == SQL_SUCCESS_WITH_INFO) ) 

#define myenv_err(henv,r,rc)  \
        if ( rc == SQL_ERROR || rc == SQL_SUCCESS_WITH_INFO )  \
            return myerror(rc, 1, henv) ;
        //assert( r ) 

#define mycon(hdbc,r)  \
        if ( ((r) != SQL_SUCCESS) )  \
            return myerror(r, 2, hdbc);
        //assert( ((r) == SQL_SUCCESS) || ((r) == SQL_SUCCESS_WITH_INFO) ) 

#define mycon_err(hdbc,r,rc)  \
        if ( rc == SQL_ERROR || rc == SQL_SUCCESS_WITH_INFO )  \
            return myerror(rc, 2, hdbc); 
        //assert( r ) 

#define mystmt(hstmt,r)  \
        if ( ((r) != SQL_SUCCESS) )  \
            return myerror(r, 3, hstmt) ;
        //assert( ((r) == SQL_SUCCESS) || ((r) == SQL_SUCCESS_WITH_INFO) ) 

#define mystmt_err(hstmt,r,rc)  \
        if ( rc == SQL_ERROR || rc == SQL_SUCCESS_WITH_INFO ) { \
            return myerror(rc, 3, hstmt);
        //assert( r ) 

int mystmt_wrap(SQLHSTMT h, SQLRETURN r); //wrapper for mystmt macro
/********************************************************
* MyODBC 3.51 error handler                             *
*********************************************************/
int myerror(SQLRETURN rc, SQLSMALLINT htype, SQLHANDLE handle);

/********************************************************
* MyODBC 3.51 connection handler                        *
*********************************************************/
int myconnect(SQLHENV *henv,SQLHDBC *hdbc, SQLHSTMT *hstmt);

/********************************************************
* MyODBC 3.51 closes the connection                     *
*********************************************************/
void mydisconnect(SQLHENV *henv,SQLHDBC *hdbc, SQLHSTMT *hstmt);

#endif /* __TMYODBC_UTILITY_H__ */


