/**********************************************************************
scutils.h:

Description:
	This header file used internally for smart card access via PKCS11
	For windows we can dynamicly load, and so PKCS#11 support
	can allways be compiled, as we now have the RSA header files
	included from the PKCS#11 2.01 version
	

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

#ifndef _SCUTILS_H
#define _SCUTILS_H

/**********************************************************************
                             Include header files
**********************************************************************/
#ifndef NO_GSSAPI_CONFIG_H
#include "gssapi_config.h"
#endif

#include <stdio.h>
#include "ssl.h"
#include "err.h"
#include "bio.h"
#include "pem.h"
#include "x509.h"
#include "stack.h"
#include "evp.h"
#include "rsa.h"

#include "pkcs11.h"

#ifdef USE_TYPEMAP
#include "typemap.h"
#endif

/**********************************************************************
                               Define constants
**********************************************************************/
/* RSA PKCS#11 says local strings donot include the null,
 * but examples do. Litronics writes the null in their labels
 * and expect them when formating. 
 * The following will be added when writing a label or
 * other local string which might have this problem.
 * If other cards dont require, or this gets fixed, 
 * set this to 0 
 *
 * This was with Litronic before NetSign 2.0
 *
 * We have added code to try with and without the null,
 * So set this to 0 for now. 
 */
#define HACK_PKCS11_LOCAL_STRING_NULL 0

/*
 * We need to store the session and object handles with the key. 
 * In order to avoid changes to SSLeay, for the RSA structire,
 * we will use two of the ex_data fields, by grabing 3 and 4.
 * This may be a problem in future versions. 
 * These are used by the _get_ key routines when creating 
 * the key structure below, and by the sc_RSA_eay routines when
 * they go to use the key. 
 */

#define SC_RSA_EX_DATA_INDEX_SESSION 3
#define SC_RSA_EX_DATA_INDEX_OBJECT  4


/* Location where the SCERR library will be stored */  
#define ERR_USER_LIB_SCERR_NUMBER       ((ERR_LIB_USER) +  1)

/*
 * Use the SSLeay error facility with the ERR_LIB_USER
 */

#define SCerr(f,r) ERR_PUT_error(ERR_USER_LIB_SCERR_NUMBER,(f),(r),ERR_file_name,__LINE__)

/*
 * defines for function codes our minor error codes
 */

#define SCERR_F_RSA_ENCRYPT					100
#define SCERR_F_RSA_DECRYPT            		101
#define SCERR_F_SCINIT						102
#define SCERR_F_CREATE_DATA_OBJ				103
#define SCERR_F_CREATE_CERT_OBJ				104
#define SCERR_F_CREATE_RSA_PRIV_KEY_OBJ 	105
#define SCERR_F_CREATE_PRIV_KEY_OBJ			106
#define SCERR_F_GET_RSA_PRIV_KEY_OBJ		107
#define SCERR_F_GET_PRIV_KEY_OBJ			108
#define SCERR_F_GET_PRIV_KEY_BY_LABEL		109
#define SCERR_F_GET_CERT_OBJ				110
#define SCERR_F_FIND_ONE_OBJ                111
#define SCERR_F_FIND_CERT_BY_LABEL			112
#define SCERR_F_LOAD_DLL					113

/* 
 * defines for reasons 
 */

#define SCERR_R_BASE                            1500

#define SCERR_R_PKCS11_ERROR            SCERR_R_BASE + 1
#define SCERR_R_SIGNINIT                SCERR_R_BASE + 2
#define SCERR_R_SIGN                    SCERR_R_BASE + 3
#define SCERR_R_SIGNRECINIT             SCERR_R_BASE + 4
#define SCERR_R_SIGNREC                 SCERR_R_BASE + 5
#define SCERR_R_INITIALIZE              SCERR_R_BASE + 6
#define SCERR_R_GETSLOTLIST             SCERR_R_BASE + 7
#define SCERR_R_OPENSESSION             SCERR_R_BASE + 8
#define SCERR_R_LOGIN                   SCERR_R_BASE + 9
#define SCERR_R_CREATEOBJ               SCERR_R_BASE + 10
#define SCERR_R_UNSUPPORTED             SCERR_R_BASE + 11
#define SCERR_R_GETATTRVAL              SCERR_R_BASE + 12
#define SCERR_R_FINDOBJINIT             SCERR_R_BASE + 13
#define SCERR_R_FINDOBJ                 SCERR_R_BASE + 14
#define SCERR_R_FOUNDMANY               SCERR_R_BASE + 15
#define SCERR_R_BAD_CERT_OBJ            SCERR_R_BASE + 16
#define SCERR_R_FIND_FAILED             SCERR_R_BASE + 17
#define SCERR_R_NO_PKCS11_DLL           SCERR_R_BASE + 18
/* NOTE: Reason codes are limited to <4096 by openssl error handler */

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                               Global variables
*********************************************************************/

/* The pFunctionList is a pointer to the PKCS11 list
 * of functions which is in the lib or DLL. 
 * It is initialized once on the first call to the
 * sc_init() by sc_get_funct_list()
 */

extern CK_FUNCTION_LIST_PTR pFunctionList;

/**********************************************************************
                               Function prototypes
**********************************************************************/
int
ERR_load_scerr_strings(int i);

char *
sc_ERR_code(CK_RV status);

CK_FUNCTION_LIST_PTR 
sc_get_function_list();

int 
sc_init(CK_SESSION_HANDLE_PTR PsessionHandle,
			char *card,
			CK_SLOT_ID_PTR pslot,
			char * ppin,
			CK_USER_TYPE userType,
			int initialized);

int
sc_init_one(CK_SLOT_ID_PTR pslot);

int
sc_init_info(CK_SLOT_ID_PTR pslot, 
			CK_TOKEN_INFO_PTR ptokenInfo);

int
sc_init_open_login(CK_SESSION_HANDLE_PTR PsessionHandle,
			CK_SLOT_ID_PTR pslot,
			char * ppin,
			CK_USER_TYPE userType);

int 
sc_final(CK_SESSION_HANDLE sessionHandle);


int 
sc_create_data_obj(CK_SESSION_HANDLE sessionHandle,
                  char *mylabel, 
			char *myvalue, 
			int mylen);

int 
sc_create_rsa_priv_key_obj(CK_SESSION_HANDLE sessionHandle,
			char *mylabel,
			RSA  *rkey);

int
sc_create_priv_key_obj(CK_SESSION_HANDLE sessionHandle,
			char *mylabel,
			EVP_PKEY *key);      

int
sc_create_cert_obj(CK_SESSION_HANDLE sessionHandle,
			char *mylabel,
			X509 *ucert);

/**********************/
int		
sc_get_rsa_priv_key_obj(CK_SESSION_HANDLE sessionHandle,
			CK_OBJECT_HANDLE hPrivKey,
			RSA ** nrkey);

int	
sc_get_priv_key_obj(CK_SESSION_HANDLE sessionHandle,
			CK_OBJECT_HANDLE hPrivKey,
			EVP_PKEY ** nkey);

int
sc_get_priv_key_obj_by_label(CK_SESSION_HANDLE sessionHandle,
			char *mylabel,
                        EVP_PKEY ** nkey);

int
sc_get_cert_obj_by_label(CK_SESSION_HANDLE sessionHandle,
			char *mylabel,
			X509 ** ncert);

int
sc_find_one_obj(CK_SESSION_HANDLE sessionHandle,
			CK_ATTRIBUTE_PTR template,
			int ai,
			CK_OBJECT_HANDLE_PTR phObject);

int
sc_find_priv_key_obj_by_label(CK_SESSION_HANDLE sessionHandle,
			char * mylabel,
			CK_OBJECT_HANDLE_PTR phPrivKey);

int
sc_find_cert_obj_by_label(CK_SESSION_HANDLE hSession,
			char * mylabel,
			CK_OBJECT_HANDLE_PTR phCert);

int 
sc_find_cert_obj_by_subject(CK_SESSION_HANDLE hSession,
			X509_NAME * x509name,
			CK_OBJECT_HANDLE_PTR phCert);


/************************************************************************/
/* replacement RSA_PKCS1_SSLeay routines which will use the key on the  */ 
/* smart card We have our own method which will call PKCS11             */
/* These are in sc_rsa_ssleay.c                                         */
/************************************************************************/

RSA_METHOD * sc_RSA_PKCS1_SSLeay();


#endif /* _SCUTILS_H */
