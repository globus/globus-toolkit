/**********************************************************************

scutils.c

Description:
	Routines used internally to work with smart card
	using PKCS11  

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/
#include "config.h"

#ifdef USE_PKCS11

#include "scutils.h"
#include "sslutils.h"

#ifndef WIN32
#define FILE_SEPERATOR "/"
#else
#define FILE_SEPERATOR "\\"
#include <windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifdef USE_PKCS11_DL
#include <dlfcn.h>
#endif
#include "buffer.h"
#include "crypto.h"
#include "objects.h"
#include "asn1.h"
#include "evp.h"
#include "x509.h"
#include "pem.h"
#include "ssl.h"
#include "rsa.h"


/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

static int 
sc_RSA_eay_private_decrypt(int              flen, 
			   unsigned char *  from,
			   unsigned char *  to, 
			   RSA *            rsa, 
			   int              padding);

static int
sc_RSA_eay_private_encrypt(int              flen, 
			   unsigned char *  from,
			   unsigned char *  to,
			   RSA *            rsa,
			   int              padding);

/**********************************************************************
                       Define module specific variables
**********************************************************************/

static ERR_STRING_DATA scerr_str_functs[]=
{
    {ERR_PACK(0,SCERR_F_RSA_ENCRYPT,0),"sc_RSA_private_encrypt"},
    {ERR_PACK(0,SCERR_F_RSA_DECRYPT,0),"sc_RSA_private_decrypt"},
    {ERR_PACK(0,SCERR_F_SCINIT,0),"sc_init"},
    {ERR_PACK(0,SCERR_F_CREATE_DATA_OBJ,0),"sc_create_data_obj"},
    {ERR_PACK(0,SCERR_F_CREATE_CERT_OBJ,0),"sc_create_cert_obj"},
    {ERR_PACK(0,SCERR_F_CREATE_RSA_PRIV_KEY_OBJ,0),"sc_create_rsa_priv_key_obj"},
    {ERR_PACK(0,SCERR_F_CREATE_PRIV_KEY_OBJ,0),"sc_create_priv_key_obj"},
    {ERR_PACK(0,SCERR_F_GET_RSA_PRIV_KEY_OBJ,0),"sc_get_rsa_priv_key_obj"},
    {ERR_PACK(0,SCERR_F_GET_PRIV_KEY_OBJ,0),"sc_get_priv_key_obj"},
    {ERR_PACK(0,SCERR_F_GET_PRIV_KEY_BY_LABEL,0),"sc_get_priv_key_by_label"},
    {ERR_PACK(0,SCERR_F_GET_CERT_OBJ,0),"sc_get_cert_obj"},
    {ERR_PACK(0,SCERR_F_FIND_ONE_OBJ,0),"sc_find_one_obj"},
    {ERR_PACK(0,SCERR_F_FIND_CERT_BY_LABEL,0),"sc_find_cert_by_label"},
    {ERR_PACK(0,SCERR_F_LOAD_DLL,0),"sc_get_function_list"},
    {0,NULL},
};

static ERR_STRING_DATA scerr_str_reasons[]=
{
    {SCERR_R_PKCS11_ERROR, "PKCS11 error"},
    {SCERR_R_SIGNINIT, "C_SignInit"},
    {SCERR_R_SIGN, "C_Sign"},
    {SCERR_R_SIGNRECINIT, "C_SignRecoverInit"},
    {SCERR_R_SIGNREC, "C_SignRecover"},
    {SCERR_R_INITIALIZE, "C_Initialize"},
    {SCERR_R_GETSLOTLIST, "C-GetSlotList"},
    {SCERR_R_OPENSESSION, "C_OpenSession"},
    {SCERR_R_LOGIN, "C_Login"},
    {SCERR_R_CREATEOBJ, "C_CreateObject"},
    {SCERR_R_UNSUPPORTED, "Unsupported feature"},
    {SCERR_R_GETATTRVAL, "C_GetAttributeValue"},
    {SCERR_R_FINDOBJINIT, "C_FindObjectInit"},
    {SCERR_R_FINDOBJ, "C_FindObject"},
    {SCERR_R_FOUNDMANY, "Found more then one matching key"},
    {SCERR_R_FIND_FAILED, "Unable to find object on smart card"},
    {SCERR_R_NO_PKCS11_DLL,"Unable to load the PKCS11 support"},
    {0,NULL},
};

CK_FUNCTION_LIST_PTR pFunctionList = NULL;

#ifdef WIN32
HMODULE h_m_pkcs11 = NULL;
#else
void * h_m_pkcs11 = NULL;
#endif

/**********************************************************************
Function: sc_get_function_list()

Description:
	Get the name of the PKCS11 dll to use from the registry,
	load it, get the entry for the C_GetFunctionList
	call it to set the pFunctionList.

Parameters:

Returns:
	the pFunctionList or NULL 
**********************************************************************/
CK_FUNCTION_LIST_PTR
sc_get_function_list()
{
    CK_RV                               status;
    CK_RV                               (*gfl)(CK_FUNCTION_LIST_PTR_PTR);
	
#ifdef DEBUG
    fprintf (stderr,"sc_get_function_list\n");
#endif
    if (pFunctionList)
    {
	return pFunctionList;
    }
#if defined(USE_PKCS11_DL) || defined(WIN32)

    if (!h_m_pkcs11)
    {
	char * dllname = NULL;
#ifdef WIN32
	HKEY hkDir = NULL;
	char val_dllname[512] = {"NONE"};
	LONG lval;
	DWORD type;
		
	if (!h_m_pkcs11)
	{
		
	    RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
	    lval = sizeof(val_dllname) -1;
	    if (hkDir && (RegQueryValueEx(hkDir,
					  "PKCS11.DLL",
					  0,
					  &type,
					  val_dllname,&lval) == ERROR_SUCCESS))
	    {
		h_m_pkcs11 = LoadLibrary(val_dllname);
	    }
	    
	    if (hkDir)
	    {
		RegCloseKey(hkDir);
	    }
#ifdef DEBUG
	    fprintf(stderr,"LoadLibrary: %s dll:%s\n",
		    h_m_pkcs11?"OK":"zero",
		    val_dllname);
#endif
	    if (!h_m_pkcs11)
	    {
		SCerr(SCERR_F_SCINIT,SCERR_R_NO_PKCS11_DLL);
		ERR_add_error_data(2,"Name of DLL=",
				   dllname? dllname:"NONE");
		return NULL;
	    }
	}
	gfl = (CK_RV (*)(CK_FUNCTION_LIST_PTR *))
	    GetProcAddress(h_m_pkcs11,"C_GetFunctionList");
#else 
	if (!h_m_pkcs11)
	{
	    dllname = getenv("PKCS11_LIB");
	    if (!dllname)
	    {
		dllname = "libDSPKCS.so";
	    }
	    h_m_pkcs11 = dlopen("libDSPKCS.so",RTLD_LAZY);
	}
	if (!h_m_pkcs11)
	{
	    SCerr(SCERR_F_SCINIT,SCERR_R_NO_PKCS11_DLL);
	    ERR_add_error_data(2,"Name of shared library=",
			       dllname);
	    return NULL;
	}

	gfl = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))
	    dlsym(h_m_pkcs11,"C_GetFunctionList");
#endif
	if (!gfl)
	{
	    SCerr(SCERR_F_LOAD_DLL,SCERR_R_NO_PKCS11_DLL);
	    ERR_add_error_data(1,"Cant find C_GetFunctionList");
	    return NULL;

	}
    }
    status = (*gfl)(&pFunctionList);
#else
    status = C_GetFunctionList(&pFunctionList);
#endif /* PKCS11_DYNLOAD */

    if (status != CKR_OK)
    {
	SCerr(SCERR_F_LOAD_DLL,SCERR_R_UNSUPPORTED);
	ERR_add_error_data(1,sc_ERR_code(status));
	return NULL;
    }
#ifdef DEBUG
    fprintf(stderr,"sc_get_function_list:OK\n");
    fprintf(stderr,"Version %d %d\n",pFunctionList->version.major,
	    pFunctionList->version.minor);
    fprintf(stderr,"C_initialize: %p\n",
	    pFunctionList->C_Initialize);
#endif
    return pFunctionList;
}

/**********************************************************************
Function: ERR_load_scerr_strings()

Description:
    Sets up the error tables used by SSL and adds ours
    using the ERR_LIB_USER
    Only the first call does anything.

Parameters:
        i should be zero the first time any of the ERR_load_.*_string functions is called and
        non-zero for the rest of the calls.
Returns:
**********************************************************************/

int
ERR_load_scerr_strings(
    int                                 i)
{
    static int                          init=1;

    if (init)
    {
        init=0;

	if (i == 0)
	{
	    SSL_load_error_strings();
	}
        ERR_load_strings(ERR_USER_LIB_SCERR_NUMBER,scerr_str_functs);
        ERR_load_strings(ERR_USER_LIB_SCERR_NUMBER,scerr_str_reasons);
	    i++;
    }
    return i;
}

/********************************************************************/
/*******************************************************************/
/* Temporary function to reuten the error number. Should return char */

char *
sc_ERR_code(
    CK_RV                               status) 
{
    static char                         buf[256];
	
    sprintf(buf,"PKCS#11 return=0x%8.8lx",status);
    return buf;
}

/********************************************************************/

int 
sc_init(
    CK_SESSION_HANDLE_PTR               PsessionHandle, 
    char *                              card,
    CK_SLOT_ID_PTR                      ppslot,
    char *                              ppin,
    CK_USER_TYPE                        userType,
    int                                 initialized)
{
    int                                 rc;
    CK_SLOT_ID                          rslot;
    CK_SLOT_ID_PTR                      pslot;
    CK_TOKEN_INFO                       tokeninfo;
       
    if (ppslot)
    {
	pslot = ppslot;
    }
    else
    {
	pslot = &rslot;
    }
	
    if (!initialized)
    {
	rc = sc_init_one(pslot);
	if (rc)
	{
	    return rc;
	}
    }

/* 
   rc = sc_init_info(pslot, &tokenInfo);
   if (rc) {
   return rc;
   }
*/

    rc = sc_init_open_login(PsessionHandle, pslot, ppin, userType);
    if (rc)
    {
	return rc;
    }
    return 0;

}

/***********************************************************
Function: sc_init_one 

Description:
	get the function list pointer first. 
	initialize and find the slot with the card


***********************************************************/
int
sc_init_one(
    CK_SLOT_ID_PTR                      pslot) 
{
    CK_RV                               status;
    CK_SLOT_ID                          list[20];
    CK_SLOT_ID                          slot;
    CK_SLOT_ID_PTR                      slotList = &list[0];
    CK_TOKEN_INFO                       tokeninfo;
    CK_ULONG                            count = 0;
    CK_C_Initialize                     pC_Initialize;

    if (!sc_get_function_list())
    {
	return SCERR_R_INITIALIZE;
    }

    pC_Initialize = pFunctionList->C_Initialize;
#ifdef DEBUG
    fprintf(stderr,"sc_init_one calling C_initialized\n");
#endif
    status = (*pC_Initialize)(0);
#ifdef DUBUG
    fprintf(stderr,"sc_init_one C_initialized\n");
#endif
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_SCINIT,SCERR_R_INITIALIZE);
	ERR_add_error_data(1,sc_ERR_code(status));
	return SCERR_R_INITIALIZE;
    }
/*
  status = (*(pFunctionList->C_GetSlotList))(FALSE, NULL, &count);
  if (status != CKR_OK) {
  SCerr(SCERR_F_SCINIT,SCERR_R_GETSLOTLIST);
  ERR_add_error_data(1,sc_ERR_code(status));
  return SCERR_R_GETSLOTLIST;
  }
  fprintf(stderr,"Slotlist count = %d\n",count);
*/
    count = 20;

    status = (*(pFunctionList->C_GetSlotList))(FALSE, slotList, &count);
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_SCINIT,SCERR_R_GETSLOTLIST);
	ERR_add_error_data(1,sc_ERR_code(status));
	return SCERR_R_GETSLOTLIST;
    }
    
    if (count == 0)
    {
	SCerr(SCERR_F_SCINIT,SCERR_R_OPENSESSION);
	ERR_add_error_data(1,"\n       No SmartCard readers found");
	return SCERR_R_OPENSESSION;
    }

#ifdef DEBUG2
    fprintf(stderr,"looking at MechanisumList\n");
    {
	CK_RV status;
	CK_ULONG ulCount = 0;
	CK_MECHANISM_TYPE_PTR pMechList;
	int i;
	
	status = (*(pFunctionList->C_GetMechanismList))(list[0],
							NULL_PTR, &ulCount);
	fprintf(stderr,"Mech rc=%x, count=%ld\n", status, ulCount);	
	pMechList = (CK_MECHANISM_TYPE_PTR)
	    malloc(ulCount*sizeof(CK_MECHANISM_TYPE));
	status = (*(pFunctionList->C_GetMechanismList))(list[0],
							pMechList,&ulCount);
	for (i=0;i<(long)ulCount;i++)
	{
	    fprintf(stderr,"Mech[%02d]=0x%8.8x\n",i,pMechList[i]);
	}

    }

    fprintf(stderr,"Slot[0] %d count=%d\n",slotList[0],count);
#endif

    /*
     * need to look at all the slots. 
     * Maybe provide the card label then look for it 
     */

    slot = list[0];
    if (pslot)
    {
	*pslot = slot;
    }
    return 0;
}


/***************************************************************
Function: sc_init_info

Description:
	Read the card info and print debuging

**************************************************************/

int
sc_init_info(
    CK_SLOT_ID_PTR                      pslot,
    CK_TOKEN_INFO_PTR                   ptokenInfo)
{
    CK_RV                               status;


    status = (*(pFunctionList->C_GetTokenInfo))(*pslot, ptokenInfo);
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_SCINIT,SCERR_R_LOGIN);
	ERR_add_error_data(2, "While reading Smart Card Info",
			   sc_ERR_code(status));
	return SCERR_R_LOGIN;
    }

#ifdef DEBUG2
    fprintf(stderr,"Smart Card Info:\n");
    fprintf(stderr," Label:       %.32s\n",ptokenInfo->label);
    fprintf(stderr," Manufacturer:%.32s\n",ptokenInfo->manufacturerID);
    fprintf(stderr," Model:       %.16s\n",ptokenInfo->model);
    fprintf(stderr," SerialNumber:%.16s\n",ptokenInfo->serialNumber);
#endif

    return 0;
}

/*****************************************************************
Function: sc_init_open_login

Description:
	Open a session to the card, and login 

*****************************************************************/

int
sc_init_open_login(
    CK_SESSION_HANDLE_PTR               PsessionHandle,
    CK_SLOT_ID_PTR                      pslot,
    char *                              ppin,
    CK_USER_TYPE                        userType)
{
    int                                 rc;
    CK_RV                               status;
    char *                              pin;
    char                                rpin[256];
    /* could also add CKF_EXCLUSIVE_SESSION */
    int                                 flags =
	CKF_RW_SESSION | CKF_SERIAL_SESSION ;

    status = (*(pFunctionList->C_OpenSession))(*pslot, 
					       flags, 0, NULL, PsessionHandle);
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_SCINIT,SCERR_R_OPENSESSION);
	ERR_add_error_data(1,sc_ERR_code(status));
	return SCERR_R_OPENSESSION;
    }
	
    if (ppin) /* did user provide the pin? */
    { 
	pin = ppin; 
    }
    else
    {
	pin = rpin;
	memset(rpin,0,sizeof(rpin));
#ifdef WIN32
	read_passphrase_win32_prompt(
	    (userType == CKU_USER) ?
	    "Smart Card User PIN:" : "Smart Card SO PIN:",0);
	read_passphrase_win32(rpin,sizeof(rpin),0);
#else
	des_read_pw_string(rpin,sizeof(rpin),
			   (userType == CKU_USER) ? 
			   "Smart Card User PIN:" : "Smart Card SO PIN:",0);
#endif			
	/*DEE should test this too */
    }

#ifdef DEBUG2
    fprintf(stderr,"Logging on to card\n");
#endif
    status = (*(pFunctionList->C_Login))(*PsessionHandle, userType,
					 (CK_CHAR_PTR)pin, strlen(pin));
    memset(rpin,0,sizeof(rpin));
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_SCINIT,SCERR_R_LOGIN);
	ERR_add_error_data(1,sc_ERR_code(status));
	return SCERR_R_LOGIN;
    }

#ifdef DEBUG2
    fprintf(stderr,"Login complete\n");
#endif
    return 0;
}


/*********************************************************************/
int
sc_final(
    CK_SESSION_HANDLE                   sessionHandle)
{
    CK_RV status;
    status = (*(pFunctionList->C_Logout))(sessionHandle);
    status = (*(pFunctionList->C_CloseSession))(sessionHandle);
    return 0;
}


/*******************************************************************/
int
sc_create_data_obj(
    CK_SESSION_HANDLE                   hSession,
    char *                              mylabel,
    char *                              myvalue,
    int                                 mylen)
{
    CK_RV                               status;
    CK_OBJECT_HANDLE                    hData;
    CK_OBJECT_CLASS                     dataClass = CKO_DATA;
    CK_BBOOL                            true = TRUE;
    int                                 ai = 0;
    CK_ATTRIBUTE                        template[20]; 

    template[ai].type = CKA_CLASS;
    template[ai].pValue = &dataClass;
    template[ai].ulValueLen = sizeof(dataClass);
    ai++;

    template[ai].type = CKA_TOKEN;
    template[ai].pValue = &true;
    template[ai].ulValueLen = sizeof(true);
    ai++;

    template[ai].type = CKA_LABEL;
    template[ai].pValue = mylabel;
    template[ai].ulValueLen = strlen(mylabel) + HACK_PKCS11_LOCAL_STRING_NULL;
    ai++;

    template[ai].type = CKA_VALUE;
    template[ai].pValue = myvalue;
    template[ai].ulValueLen = strlen(myvalue);
    ai++;

#ifdef DEBUG
    fprintf(stderr,"Label=%s data=%s\n",mylabel,myvalue);
#endif

    status = (*(pFunctionList->C_CreateObject))(hSession, template, ai, &hData);
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_CREATE_DATA_OBJ,SCERR_R_CREATEOBJ);
	ERR_add_error_data(1,sc_ERR_code(status));
	return SCERR_R_CREATEOBJ;
    }      
    return 0;
}

/*****************************************************************************/

int
sc_create_cert_obj(
    CK_SESSION_HANDLE                   hSession,
    char *                              mylabel,
    X509 *                              ucert)
{
    CK_RV                               status;
    CK_OBJECT_HANDLE                    hCert;    
    CK_OBJECT_CLASS                     class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE                 certType = CKC_X_509;
    CK_BBOOL                            true = TRUE;
    CK_BBOOL                            false = FALSE;
    int                                 ai;
    CK_ATTRIBUTE                        template[30];
    BIO *                               xbio = NULL; 
    unsigned char *                     dsubject = NULL;
    unsigned char *                     tdsubject = NULL;
    int                                 ldsubject;
    unsigned char *                     dcert = NULL;
    unsigned char *                     tdcert = NULL;
    int                                 ldcert;

#ifdef DEBUG
    {
	char *s;
	fprintf(stderr,"Writing certificate to card...\n");
	s = X509_NAME_oneline(ucert->cert_info->subject,NULL,0);
	fprintf(stderr,"Subject=%s\n",s);
	free(s);
    }
#endif
	

    ldcert = i2d_X509(ucert,NULL);
    dcert = (char *)malloc(ldcert);
    tdcert = dcert;
    ldcert = i2d_X509(ucert,&tdcert);

    ldsubject = i2d_X509_NAME(ucert->cert_info->subject,NULL);
    dsubject = (char *) malloc(ldsubject);
    tdsubject = dsubject;
    ldsubject = i2d_X509_NAME(ucert->cert_info->subject,&tdsubject);
 
#ifdef DEBUG2
    {
	fprintf(stderr,"ldcert=%d ldsubject=%d\n",ldcert, ldsubject);
	fprintf(stderr,"dcert=%p dsubject=%p\n", dcert, dsubject); 
    }
#endif

    ai = 0;
    template[ai].type = CKA_CLASS;
    template[ai].pValue = &class;
    template[ai].ulValueLen = sizeof(class);
    ai++;

    template[ai].type = CKA_CERTIFICATE_TYPE;
    template[ai].pValue = &certType;
    template[ai].ulValueLen = sizeof(certType);
    ai++;

    template[ai].type = CKA_TOKEN;
    template[ai].pValue = &true;
    template[ai].ulValueLen = sizeof(true);
    ai++;

    template[ai].type = CKA_LABEL;
    template[ai].pValue = mylabel;
    template[ai].ulValueLen = strlen(mylabel) + HACK_PKCS11_LOCAL_STRING_NULL;
    ai++;

    template[ai].type = CKA_SUBJECT;
    template[ai].pValue = dsubject;
    template[ai].ulValueLen = ldsubject;
    ai++;

    template[ai].type = CKA_VALUE;
    template[ai].pValue = dcert;
    template[ai].ulValueLen = ldcert;
    ai++;


#ifdef DEBUG
    fprintf(stderr,"Label=%s count=%d\n",mylabel,ai);
#endif

    status = (*(pFunctionList->C_CreateObject))(hSession, 
						template, ai, &hCert);
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_CREATE_CERT_OBJ,SCERR_R_CREATEOBJ);
	ERR_add_error_data(1,sc_ERR_code(status));
	free(dcert);
	free(dsubject);
	return 1;
    }

    free(dcert);
    free(dsubject);
    return 0;
}

/*****************************************************************************/

int
sc_create_rsa_priv_key_obj(
    CK_SESSION_HANDLE                   hSession,
    char *                              mylabel,
    RSA  *                              rkey)                        
{
    CK_RV                               status;
    CK_OBJECT_HANDLE                    hPrivKey;
    CK_KEY_TYPE                         keyType = CKK_RSA;
    CK_OBJECT_CLASS                     keyClass = CKO_PRIVATE_KEY;
    CK_BBOOL                            true = TRUE;
    CK_BBOOL                            false = FALSE;
    char *                              bin = NULL;
    int                                 binlen = 0;
    int                                 ai;
    int                                 bi;
    int                                 bl;
    CK_ATTRIBUTE                        template[30]; 

    binlen = BN_num_bytes(rkey->n) +  
	BN_num_bytes(rkey->e) +
	BN_num_bytes(rkey->d) +
	BN_num_bytes(rkey->p) +
	BN_num_bytes(rkey->q) + 
	BN_num_bytes(rkey->dmp1) +
	BN_num_bytes(rkey->dmq1) +
	BN_num_bytes(rkey->iqmp);

    bin = (char *)malloc(binlen);	
    if (!bin)
    {
	SCerr(SCERR_F_CREATE_RSA_PRIV_KEY_OBJ,ERR_R_MALLOC_FAILURE);
	return 1;
    }
    ai = 0;
    bi = 0;

    template[ai].type = CKA_CLASS;
    template[ai].pValue = &keyClass;
    template[ai].ulValueLen = sizeof(keyClass);
    ai++;

    template[ai].type = CKA_TOKEN;
    template[ai].pValue = &true;
    template[ai].ulValueLen = sizeof(true);
    ai++;

    template[ai].type = CKA_PRIVATE;
    template[ai].pValue = &true;
    template[ai].ulValueLen = sizeof(true);
    ai++;

    template[ai].type = CKA_LABEL;
    template[ai].pValue = mylabel;
    template[ai].ulValueLen = strlen(mylabel)+ HACK_PKCS11_LOCAL_STRING_NULL;
    ai++;

    template[ai].type = CKA_KEY_TYPE;
    template[ai].pValue = &keyType;
    template[ai].ulValueLen = sizeof(keyType);
    ai++;

    template[ai].type = CKA_SIGN;
    template[ai].pValue = &true;
    template[ai].ulValueLen = sizeof(true);
    ai++;

    template[ai].type = CKA_SENSITIVE;
#if 0
/* for testing, want to be able to read the key back */
    template[ai].pValue = &false;
#else
    template[ai].pValue = &true;
#endif
    template[ai].ulValueLen = sizeof(false);
    ai++;
/*
  template[ai].type = CKA_EXTRACTABLE;
  template[ai].pValue = &true;
  template[ai].ulValueLen = sizeof(true);
  ai++;
*/
#ifdef DEBUG
    fprintf(stderr,"Loading private key on card...\n");
#endif

/* The actual key */

    bl = BN_bn2bin(rkey->n, &bin[bi]);
    template[ai].type = CKA_MODULUS;
    template[ai].pValue = &bin[bi];
    template[ai].ulValueLen = bl;
    ai++;
    bi += bl;

#ifdef DEBUG2
    fprintf(stderr,"Modulus len=%d starts %x\n", BN_num_bytes(rkey->n), rkey->n->d[0]);
#endif

    bl= BN_bn2bin(rkey->e, &bin[bi]);
    template[ai].type = CKA_PUBLIC_EXPONENT;
    template[ai].pValue = &bin[bi];
    template[ai].ulValueLen = bl;
    ai++;
    bi += bl;

#ifdef DEBUG2
    fprintf(stderr,"Exponent len=%d starts %x\n", BN_num_bytes(rkey->e), rkey->e->d[0]);
#endif

    bl = BN_bn2bin(rkey->d, &bin[bi]);
    template[ai].type = CKA_PRIVATE_EXPONENT;
    template[ai].pValue = &bin[bi];
    template[ai].ulValueLen = bl;
    ai++;
    bi += bl;

    bl = BN_bn2bin(rkey->p, &bin[bi]);
    template[ai].type = CKA_PRIME_1;
    template[ai].pValue = &bin[bi];
    template[ai].ulValueLen = bl;
    ai++;
    bi += bl;

    bl = BN_bn2bin(rkey->q, &bin[bi]);
    template[ai].type = CKA_PRIME_2;
    template[ai].pValue = &bin[bi];
    template[ai].ulValueLen = bl;
    ai++;
    bi += bl;

    bl = BN_bn2bin(rkey->dmp1, &bin[bi]);
    template[ai].type = CKA_EXPONENT_1;
    template[ai].pValue = &bin[bi];
    template[ai].ulValueLen = bl;
    ai++;
    bi += bl;

    bl = BN_bn2bin(rkey->dmq1, &bin[bi]);
    template[ai].type = CKA_EXPONENT_2;
    template[ai].pValue = &bin[bi];
    template[ai].ulValueLen = bl;
    ai++;
    bi += bl;

    bl = BN_bn2bin(rkey->iqmp, &bin[bi]);
    template[ai].type = CKA_COEFFICIENT;
    template[ai].pValue = &bin[bi];
    template[ai].ulValueLen = bl;
    ai++;
    bi += bl;

#ifdef DEBUG
    fprintf(stderr,"Label=%s count=%d\n",mylabel,ai);
#endif

    status = (*(pFunctionList->C_CreateObject))(hSession,
						template,
						ai,
						&hPrivKey);
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_CREATE_RSA_PRIV_KEY_OBJ,SCERR_R_CREATEOBJ);
	ERR_add_error_data(1,sc_ERR_code(status));
	memset(bin,0,binlen);
	free(bin);
	return 1;
    }
        
    memset(bin,0,binlen);
    free(bin);
    return 0;
}

/*****************************************************************************/

int
sc_create_priv_key_obj(
    CK_SESSION_HANDLE                   hSession,
    char *                              mylabel,
    EVP_PKEY *                          key)                        
{
    if (key->type == EVP_PKEY_RSA)
    {
	return sc_create_rsa_priv_key_obj(hSession, mylabel, key->pkey.rsa);
    }
    else
    {
	SCerr(SCERR_F_CREATE_PRIV_KEY_OBJ,SCERR_R_UNSUPPORTED);
	return 1;
    }
}


/*******************************************************************/
/*  find and get data off the card                                 */
/*******************************************************************/

int
sc_get_rsa_priv_key_obj(
    CK_SESSION_HANDLE                   hSession,
    CK_OBJECT_HANDLE                    hPrivKey,
    RSA **                              nrkey)
{
    CK_RV                               sc_status;
    CK_BYTE_PTR                         pModulus = NULL;
    CK_BYTE_PTR                         pExponent = NULL;
    CK_ATTRIBUTE                        template[] =
    {
	{CKA_MODULUS, NULL_PTR, 0},
	{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
    };
    RSA *                               rsa = NULL;
    RSA_METHOD *                        ometh = NULL;
    RSA_METHOD *                        nmeth = NULL;

    rsa = RSA_new();
    /* 
     * set to use our method for this key. i
     * This will use the smart card for this key 
     * But to do this requires us to copy the RSA method, and
     * replace two routines. This is done this way to avoid
     * chanfges to the SSLeay, and since these routines are not
     * exported in the Win32 DLL. 
     */

    nmeth = (RSA_METHOD *)malloc(sizeof(RSA_METHOD));
    if (!nmeth)
    {
	return 1; /* DEE need to fix */
    }
    ometh               = rsa->meth;
    nmeth->name         = ometh->name;
    nmeth->rsa_pub_enc  = ometh->rsa_pub_enc;
    nmeth->rsa_pub_dec  = ometh->rsa_pub_dec;
    nmeth->rsa_priv_enc = sc_RSA_eay_private_encrypt;
    nmeth->rsa_priv_dec = sc_RSA_eay_private_decrypt;
    nmeth->rsa_mod_exp  = ometh->rsa_mod_exp;
    nmeth->bn_mod_exp   = ometh->bn_mod_exp;
    nmeth->init         = ometh->init;
    nmeth->finish       = ometh->finish;
    nmeth->flags        = ometh->flags;
    nmeth->app_data     = ometh->app_data;

    rsa->meth = nmeth; 

	
		

	

    RSA_set_ex_data(rsa,SC_RSA_EX_DATA_INDEX_SESSION,(char *) hSession);
    RSA_set_ex_data(rsa,SC_RSA_EX_DATA_INDEX_OBJECT, (char *) hPrivKey);

    sc_status = (*(pFunctionList->C_GetAttributeValue))
	(hSession, hPrivKey, template, 2);

#ifdef DEBUG2
    fprintf(stderr,"Modulus len = %d\n",
	    template[0].ulValueLen);
    fprintf(stderr,"Exponent len = %d\n",
	    template[1].ulValueLen);
#endif


/* 
 * HACK for the LITRONIC cards, as the RSA PKCS11 says
 * Section 9.7.1, the card must return the Modulus
 */
    if (sc_status == CKR_ATTRIBUTE_TYPE_INVALID)
    {
#ifdef DEBUG2
	fprintf(stderr,"Taking the LITRONIC Hack for Modulus\n");
#endif
	*nrkey = rsa;
	return 0;
    }
		
    if (sc_status == CKR_OK)
    {
	pModulus = (CK_BYTE_PTR) malloc(template[0].ulValueLen);
	template[0].pValue = pModulus;
	pExponent = (CK_BYTE_PTR) malloc(template[1].ulValueLen);
	template[1].pValue = pExponent;

	sc_status = (*(pFunctionList->C_GetAttributeValue))(hSession,
							    hPrivKey,
							    template,
							    1);
#ifdef DEBUG
	fprintf(stderr,"pModulus starts %x, len = %d\n",
		*pModulus, template[0].ulValueLen);
	fprintf(stderr,"pExponent starts %x, len = %d\n",
		*pExponent, template[1].ulValueLen);
#endif
    }

    if (sc_status != CKR_OK)
    {
	SCerr(SCERR_F_GET_RSA_PRIV_KEY_OBJ,SCERR_R_GETATTRVAL);
	ERR_add_error_data(1,sc_ERR_code(sc_status));
	free(pModulus);
	free(pExponent);
	return 1;
    }
    
    rsa->n = BN_bin2bn(pModulus,template[0].ulValueLen,NULL);
    rsa->e = BN_bin2bn(pExponent,template[1].ulValueLen,NULL);

    free(pModulus);
    free(pExponent);

#if 0	 
/* following are the the two extra fields added to the RSA structure */
/* may want to get these out of here so NO SSLeay chnages ! */

    rsa->hSession = hSession;
    rsa->hObject = hPrivKey;
#endif

    *nrkey = rsa;
    return 0;
}
/*******************************************************************/
int
sc_get_priv_key_obj(
    CK_SESSION_HANDLE                   hSession,
    CK_OBJECT_HANDLE                    hPrivKey,
    EVP_PKEY **                         npkey)
{
    int                                 rc;
    CK_RV                               sc_status;
    CK_KEY_TYPE                         keyType = 0;
    CK_ATTRIBUTE                        template[] =
    {
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)}
    };
    RSA *                               newrkey = NULL;
    EVP_PKEY *                          upkey=NULL;
    
    upkey = EVP_PKEY_new();

    /* We should look at the attribute of the key found to 
     * deside if it is RSA or DSA, then call correct routine.
     * For now only support RSA.
     */

    sc_status = (*(pFunctionList->C_GetAttributeValue))(hSession, 
							hPrivKey, template, 1);
    if (sc_status != CKR_OK)
    {
	SCerr(SCERR_F_GET_PRIV_KEY_OBJ,SCERR_R_GETATTRVAL);
	ERR_add_error_data(1,sc_ERR_code(sc_status));
	return 1;
    }
#ifdef DEBUG2
    fprintf(stderr,"sc_get_priv_key_obj keyType=%d\n",keyType);
#endif
    switch (keyType)
    {
    case (CKK_RSA):
	rc = sc_get_rsa_priv_key_obj(hSession,
				     hPrivKey, &newrkey);
	if (rc)
	{
	    return rc;
	}
	EVP_PKEY_assign(upkey, EVP_PKEY_RSA, (char *)newrkey);
	break;

    default:
	SCerr(SCERR_F_GET_PRIV_KEY_OBJ,SCERR_R_UNSUPPORTED);
	return 1;
    }
	
    *npkey = upkey;
    return 0;

}
/*******************************************************************/
int
sc_get_priv_key_obj_by_label(
    CK_SESSION_HANDLE                   hSession,
    char *                              mylabel,
    EVP_PKEY **                         npkey)
{
    int                                 rc;
    CK_OBJECT_HANDLE                    hKey;

    rc = sc_find_priv_key_obj_by_label(hSession,mylabel,&hKey);
    if (rc)
    {
	return rc;
    }
#ifdef DEBUG2
    fprintf(stderr,"sc_get_priv_key_obj_by_label hObject=%d\n",hKey);
#endif
    return sc_get_priv_key_obj(hSession, hKey, npkey);
}     


/*******************************************************************/
int
sc_find_priv_key_obj_by_label(
    CK_SESSION_HANDLE                   hSession,
    char *                              mylabel, 
    CK_OBJECT_HANDLE_PTR                phPrivKey)
{
    CK_RV                               status;
    CK_KEY_TYPE                         keyType = CKK_RSA;
    CK_OBJECT_CLASS                     keyClass = CKO_PRIVATE_KEY;
    CK_BBOOL                            true = TRUE;
    CK_BBOOL                            false = FALSE;
    CK_ATTRIBUTE                        template[20];
    int                                 ai;
    int                                 li = -1;
    int                                 rc;
	
    ai = 0;
    template[ai].type = CKA_CLASS;
    template[ai].pValue = &keyClass;
    template[ai].ulValueLen = sizeof(keyClass);
    ai++;

    template[ai].type = CKA_TOKEN;
    template[ai].pValue = &true;
    template[ai].ulValueLen = sizeof(true);
    ai++;

    if (strlen(mylabel))
    {
	template[ai].type = CKA_LABEL;
	template[ai].pValue = mylabel;
	template[ai].ulValueLen = strlen(mylabel) +
	    HACK_PKCS11_LOCAL_STRING_NULL;
	li = ai;
	ai++;
    }

#if 0
    template[ai].type = CKA_KEY_TYPE;
    template[ai].pValue = &keyType;
    template[ai].ulValueLen = sizeof(keyType);
    ai++;

    template[ai].type = CKA_SIGN;
    template[ai].pValue = &true;
    template[ai].ulValueLen = sizeof(true);
    ai++;
#endif

    rc = sc_find_one_obj(hSession, template, ai,  phPrivKey); 
    /*
     * we may or may not have a null as part of the name,
     * so we will try again this is a modified HACK
     * If we added the NULL to the test, we wont this time.
     * If we did not, we will this time. 
     */
    if (rc && li >= 0)
    {
	template[li].ulValueLen += 1 - 2 * HACK_PKCS11_LOCAL_STRING_NULL;
	rc = sc_find_one_obj(hSession, template, ai,  phPrivKey);
    }


    if (rc)
    {
	SCerr(SCERR_F_GET_PRIV_KEY_BY_LABEL,SCERR_R_FIND_FAILED);
	return 1;
    }
    return 0;
}

/*****************************************************************/
int
sc_find_one_obj(
    CK_SESSION_HANDLE                   hSession,
    CK_ATTRIBUTE_PTR                    template,
    int                                 ai,
    CK_OBJECT_HANDLE_PTR                phObject)
{
    CK_RV                               status;
    CK_ULONG                            ulObjectCount;

    status = (*(pFunctionList->C_FindObjectsInit))(hSession,template,ai);
    if (status != CKR_OK)
    {
	SCerr(SCERR_F_FIND_ONE_OBJ,SCERR_R_FINDOBJINIT);
	ERR_add_error_data(1,sc_ERR_code(status));
	return 1;
    }
    ulObjectCount = 0;
    status = (*(pFunctionList->C_FindObjects))(hSession, 
					       phObject,
					       1,
					       &ulObjectCount);
    (*(pFunctionList->C_FindObjectsFinal))(hSession);
    if (status != CKR_OK)
    { 
	SCerr(SCERR_F_FIND_ONE_OBJ,SCERR_R_FINDOBJ);
	ERR_add_error_data(1,sc_ERR_code(status));
	return 1;
    }
    
    if (ulObjectCount != 1)
    {
	SCerr(SCERR_F_FIND_ONE_OBJ,SCERR_R_FOUNDMANY);
	return 1;
    }

    return 0;
}


/*******************************************************************/
/*  find and get certificates off of card                          */
/*******************************************************************/
int
sc_get_cert_obj(
    CK_SESSION_HANDLE                   hSession,
    CK_OBJECT_HANDLE                    hCert,
    X509 **                             ncert)
{
    CK_RV                               sc_status;
    CK_BYTE_PTR                         pCert = NULL;
    unsigned char *                     tasn1;
    CK_ATTRIBUTE                        template[] =
    {
	{CKA_VALUE, NULL_PTR, 0}
    };
    X509 *                              x509 = NULL;

    sc_status = (*(pFunctionList->C_GetAttributeValue))(hSession, 
							hCert,
							template,
							1);

#ifdef DEBUG2
    fprintf(stderr,"Cert len = %d\n",
	    template[0].ulValueLen);
#endif
    if (sc_status == CKR_OK)
    {
        pCert = (CK_BYTE_PTR) malloc(template[0].ulValueLen);
        template[0].pValue = pCert;
    }

    sc_status = (*(pFunctionList->C_GetAttributeValue))(hSession, 
							hCert,
							template,
							1);

    if (sc_status != CKR_OK)
    {
	SCerr(SCERR_F_GET_CERT_OBJ,SCERR_R_GETATTRVAL);
	ERR_add_error_data(1,sc_ERR_code(sc_status));
        free(pCert);
        return 1;
    }

    tasn1 = pCert;
    x509 = d2i_X509(NULL,&tasn1,template[0].ulValueLen);
    if (x509 == NULL)
    {
	SCerr(SCERR_F_GET_CERT_OBJ,SCERR_R_BAD_CERT_OBJ);
	free(pCert);
	return 1;
    }
#ifdef DEBUG
    {
	char * s;
	fprintf(stderr,"Read certificate\n");
	s = X509_NAME_oneline(x509->cert_info->subject,NULL,0);
	fprintf(stderr,"Subject=%s\n",s);
	free(s);
    }
#endif

    *ncert = x509;
    free(pCert);
    return 0;
}


/*******************************************************************/
int
sc_find_cert_obj_by_label(
    CK_SESSION_HANDLE                   hSession,
    char *                              mylabel,
    CK_OBJECT_HANDLE_PTR                phCert)
{
    CK_RV                               status;
    CK_CERTIFICATE_TYPE                 certType = CKC_X_509;
    CK_OBJECT_CLASS                     certClass = CKO_CERTIFICATE;
    CK_BBOOL                            true = TRUE;
    CK_BBOOL                            false = FALSE;
    CK_ULONG                            ulObjectCount;
    CK_ATTRIBUTE                        template[20];
    int                                 ai;
    int                                 li = -1;
    int                                 rc;

    ai = 0;
    template[ai].type = CKA_CLASS;
    template[ai].pValue = &certClass;
    template[ai].ulValueLen = sizeof(certClass);
    ai++;

    template[ai].type = CKA_CERTIFICATE_TYPE;
    template[ai].pValue = &certType;
    template[ai].ulValueLen = sizeof(certType);
    ai++;

    template[ai].type = CKA_TOKEN;
    template[ai].pValue = &true;
    template[ai].ulValueLen = sizeof(true);
    ai++;

    if (strlen(mylabel))
    {
	template[ai].type = CKA_LABEL;
	template[ai].pValue = mylabel;
	template[ai].ulValueLen = strlen(mylabel) + HACK_PKCS11_LOCAL_STRING_NULL;
	li = ai;
	ai++;
    }

    rc = sc_find_one_obj(hSession, template, ai,  phCert); 

    /*
     * we may or may not have a null as part of the name,
     * so we will try again this is a modified HACK
     * If we added the NULL to the test, we wont this time.
     * If we did not, we will this time. 
     */
    if (rc && li >= 0)
    {
	template[li].ulValueLen += 1 - 2 * HACK_PKCS11_LOCAL_STRING_NULL;
	rc = sc_find_one_obj(hSession, template, ai,  phCert);
    }
    
    if (rc)
    {
	SCerr(SCERR_F_FIND_CERT_BY_LABEL,SCERR_R_FIND_FAILED);
	return 1;
    }
    return 0;
}

/*******************************************************************/
int
sc_get_cert_obj_by_label(
    CK_SESSION_HANDLE                   hSession,
    char *                              mylabel,
    X509 **                             ncert)
{
    int                                 rc;
    CK_OBJECT_HANDLE                    hCert;

    rc = sc_find_cert_obj_by_label(hSession,mylabel,&hCert);
    if (rc)
    {
	return rc;
    }
#ifdef DEBUG2
    fprintf(stderr,"sc_get_cert_obj_by_label hObject=%d\n",hCert);
#endif
    return sc_get_cert_obj(hSession, hCert, ncert);
}     

/****************************************************************/

static int 
sc_RSA_eay_private_encrypt(
    int                                 flen,
    unsigned char *                     from,
    unsigned char *                     to,
    RSA *                               rsa,
    int                                 padding)
{
    CK_ULONG                            ulsiglen;
    CK_MECHANISM_PTR                    pMech = NULL;
    CK_MECHANISM                        m_rsa_pkcs = {CKM_RSA_PKCS, 0,0};
    CK_MECHANISM                        m_rsa_raw = {CKM_RSA_X_509, 0,0};
    CK_RV                               ck_status;
    CK_SESSION_HANDLE                   hSession;
    CK_OBJECT_HANDLE                    hObject;

    hSession = (CK_SESSION_HANDLE )RSA_get_ex_data(
	rsa,
	SC_RSA_EX_DATA_INDEX_SESSION);

    hObject = (CK_OBJECT_HANDLE) RSA_get_ex_data(
	rsa,
	SC_RSA_EX_DATA_INDEX_OBJECT);

#ifdef DEBUG2
    fprintf(stderr,"RSA_dee_private_encrypt\n");
    fprintf(stderr,"hSession=%ld hObject=%ld\n", hSession, hObject);
#endif

    switch (padding)
    {
    case RSA_PKCS1_PADDING:
	pMech = &m_rsa_pkcs;
	break;
    case RSA_NO_PADDING:
	pMech = &m_rsa_raw;
	break;
    case RSA_SSLV23_PADDING:
    default:
	RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
    }

    if (pMech == NULL)
    {
	return 0; 
    }
     
#ifdef DEBUG
    fprintf(stderr,"Signing Proxy Certificate on Smart Card...\n");
#endif

    ck_status = (*(pFunctionList->C_SignInit))(hSession, pMech, hObject);
    if (ck_status != CKR_OK)
    {
	SCerr(SCERR_F_RSA_ENCRYPT,SCERR_R_SIGNINIT);
	ERR_add_error_data(1,sc_ERR_code(ck_status));
	return 0;
    }
    
    ck_status = (*(pFunctionList->C_Sign))(hSession,
					   from, flen, to, &ulsiglen);
    if (ck_status != CKR_OK)
    {
	SCerr(SCERR_F_RSA_ENCRYPT,SCERR_R_SIGN);
	ERR_add_error_data(1,sc_ERR_code(ck_status));
	return 0;
    }  
	
#ifdef DEBUG
    fprintf(stderr,"Signed\n");
#endif

    return ulsiglen;	
}

/***************************************************************/

static int 
sc_RSA_eay_private_decrypt(
    int                                 flen,
    unsigned char *                     from,
    unsigned char *                     to,
    RSA *                               rsa,
    int                                 padding)
{
    CK_ULONG                            ulsiglen;
    CK_MECHANISM_PTR                    pMech = NULL;
    CK_MECHANISM                        m_rsa_pkcs = {CKM_RSA_PKCS, 0,0};
    CK_MECHANISM                        m_rsa_raw = {CKM_RSA_X_509, 0,0};
    CK_RV                               ck_status;
    CK_SESSION_HANDLE                   hSession;
    CK_OBJECT_HANDLE                    hObject;

    hSession = (CK_SESSION_HANDLE )RSA_get_ex_data(
	rsa,
	SC_RSA_EX_DATA_INDEX_SESSION);

    hObject = (CK_OBJECT_HANDLE) RSA_get_ex_data(
	rsa,
	SC_RSA_EX_DATA_INDEX_OBJECT);

#ifdef DEBUG

    /* DEE - Not realy sure where this is used, of if the correct PKCS11 module is
     * being called. It looks. like the SignRecover is equivelent to what is
     * called the private_decrypt
     */

    fprintf(stderr,"RSA_dee_private_decrypt\n");
    fprintf(stderr,"hSession=0x%lx hObject=0x%lx\n", hSession, hObject);
#endif

    switch (padding)
    {
    case RSA_PKCS1_PADDING:
	pMech = &m_rsa_pkcs;
	break;
    case RSA_NO_PADDING:
	pMech = &m_rsa_raw;
	break;
    case RSA_SSLV23_PADDING:
    default:
	RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
    }
    
    if (pMech == NULL)
    {
	return 0; 
    }

    ulsiglen = BN_num_bytes(rsa->n);     

    ck_status = (*(pFunctionList->C_SignRecoverInit))(hSession, 
						      pMech, hObject);
    if (ck_status != CKR_OK)
    {
	SCerr(SCERR_F_RSA_DECRYPT,SCERR_R_SIGNRECINIT);
	ERR_add_error_data(1,sc_ERR_code(ck_status));
	return 0;
    }
    
    ck_status = (*(pFunctionList->C_SignRecover))(hSession,
						  from,
						  flen,
						  to,
						  &ulsiglen);
    if (ck_status != CKR_OK)
    {
	SCerr(SCERR_F_RSA_DECRYPT,SCERR_R_SIGNREC);
	ERR_add_error_data(1,sc_ERR_code(ck_status));
	return 0;
    }  
    return ulsiglen;	
}
#endif /*USE_PKCS11*/


