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

SQLCHAR *mydsn = "myodbc3";
SQLCHAR *myuid = "venu";
SQLCHAR *mypwd = "venu";

/* PROTOTYPE */
void myerror(SQLRETURN rc,SQLSMALLINT htype, SQLHANDLE handle);

/* UTILITY MACROS */
#define myenv(henv,r)  \
        if ( ((r) != SQL_SUCCESS) ) \
            myerror(r, 1,henv); \
        assert( ((r) == SQL_SUCCESS) || ((r) == SQL_SUCCESS_WITH_INFO) )

#define myenv_err(henv,r,rc)  \
        if ( rc == SQL_ERROR || rc == SQL_SUCCESS_WITH_INFO ) \
            myerror(rc, 1, henv); \
        assert( r )

#define mycon(hdbc,r)  \
        if ( ((r) != SQL_SUCCESS) ) \
            myerror(r, 2, hdbc); \
        assert( ((r) == SQL_SUCCESS) || ((r) == SQL_SUCCESS_WITH_INFO) )

#define mycon_err(hdbc,r,rc)  \
        if ( rc == SQL_ERROR || rc == SQL_SUCCESS_WITH_INFO ) \
            myerror(rc, 2, hdbc); \
        assert( r )

#define mystmt(hstmt,r)  \
        if ( ((r) != SQL_SUCCESS) ) \
            myerror(r, 3, hstmt); \
        assert( ((r) == SQL_SUCCESS) || ((r) == SQL_SUCCESS_WITH_INFO) )

#define mystmt_err(hstmt,r,rc)  \
        if ( rc == SQL_ERROR || rc == SQL_SUCCESS_WITH_INFO ) \
            myerror(rc, 3, hstmt); \
        assert( r )

/********************************************************
* MyODBC 3.51 error handler                             *
*********************************************************/
void myerror(SQLRETURN rc, SQLSMALLINT htype, SQLHANDLE handle)
{
  SQLRETURN lrc;

  if( rc == SQL_ERROR || rc == SQL_SUCCESS_WITH_INFO ) 
  {
    SQLCHAR     szSqlState[6],szErrorMsg[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER  pfNativeError;
    SQLSMALLINT pcbErrorMsg;
    
    lrc = SQLGetDiagRec(htype, handle,1,    
                        (SQLCHAR *)&szSqlState,
                        (SQLINTEGER *)&pfNativeError,
                        (SQLCHAR *)&szErrorMsg,
                         SQL_MAX_MESSAGE_LENGTH-1,
                        (SQLSMALLINT *)&pcbErrorMsg);
    if(lrc == SQL_SUCCESS || lrc == SQL_SUCCESS_WITH_INFO)
      printf("\n [%s][%d:%s]\n",szSqlState,pfNativeError,szErrorMsg);
  }
}

/********************************************************
* MyODBC 3.51 connection handler                        *
*********************************************************/
void myconnect(SQLHENV *henv,SQLHDBC *hdbc, SQLHSTMT *hstmt)
{
  SQLRETURN rc;
  
  printf("\nmyconnect:\n");

    rc = SQLAllocHandle(SQL_HANDLE_ENV,SQL_NULL_HANDLE,henv);
    myenv(*henv,rc);   
  
    rc = SQLSetEnvAttr(*henv,SQL_ATTR_ODBC_VERSION,(SQLPOINTER)SQL_OV_ODBC3,0);
    myenv(*henv,rc);   

    rc = SQLAllocHandle(SQL_HANDLE_DBC,*henv, hdbc);
    myenv(*henv,rc);    

    printf(" connecting to '%s' with user name '%s'...\n",mydsn,myuid);
    rc = SQLConnect(*hdbc, mydsn, SQL_NTS, myuid, SQL_NTS,  mypwd, SQL_NTS);
    mycon(*hdbc,rc);

    rc = SQLSetConnectAttr(*hdbc,SQL_ATTR_AUTOCOMMIT,(SQLPOINTER)SQL_AUTOCOMMIT_ON,0);
    mycon(*hdbc,rc);

    rc = SQLAllocHandle(SQL_HANDLE_STMT,*hdbc,hstmt);
    mycon(*hdbc,rc);
    printf(" success!!\n");
}

/********************************************************
* MyODBC 3.51 closes the connection                     *
*********************************************************/
void mydisconnect(SQLHENV *henv,SQLHDBC *hdbc, SQLHSTMT *hstmt)
{
  SQLRETURN rc;

  printf("\nmydisconnect:\n");

    rc = SQLFreeStmt(*hstmt, SQL_DROP);
    mystmt(*hstmt,rc);

    rc = SQLDisconnect(*hdbc);
    mycon(*hdbc,rc);

    rc = SQLFreeConnect(*hdbc);
    mycon(*hdbc,rc);

    rc = SQLFreeEnv(*henv);
    myenv(*henv,rc);
    printf(" success!!\n");
}

#endif /* __TMYODBC_UTILITY_H__ */


