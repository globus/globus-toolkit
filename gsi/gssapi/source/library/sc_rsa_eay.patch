*** /afs/anl.gov/appl/SSLeay-0.9.0/build/src/crypto/rsa/rsa_eay.c	Thu Apr  9 06:59:29 1998
--- src/sc_rsa_eay.c	Fri Oct 30 10:09:27 1998
***************
*** 62,67 ****
--- 62,70 ----
  #include "rsa.h"
  #include "rand.h"
  
+ #include "scutils.h"
+    
+ 
  #ifndef NOPROTO
  static int RSA_eay_public_encrypt(int flen, unsigned char *from,
  		unsigned char *to, RSA *rsa,int padding);
***************
*** 85,91 ****
  #endif
  
  static RSA_METHOD rsa_pkcs1_eay_meth={
! 	"Eric Young's PKCS#1 RSA",
  	RSA_eay_public_encrypt,
  	RSA_eay_public_decrypt,
  	RSA_eay_private_encrypt,
--- 88,94 ----
  #endif
  
  static RSA_METHOD rsa_pkcs1_eay_meth={
! 	"DEE Modified for use with PKCS#11, Eric Young's PKCS#1 RSA",
  	RSA_eay_public_encrypt,
  	RSA_eay_public_decrypt,
  	RSA_eay_private_encrypt,
***************
*** 98,104 ****
  	NULL,
  	};
  
! RSA_METHOD *RSA_PKCS1_SSLeay()
  	{
  	return(&rsa_pkcs1_eay_meth);
  	}
--- 101,107 ----
  	NULL,
  	};
  
! RSA_METHOD *sc_RSA_PKCS1_SSLeay()
  	{
  	return(&rsa_pkcs1_eay_meth);
  	}
***************
*** 181,191 ****
--- 184,251 ----
  RSA *rsa;
  int padding;
  	{
+ #if 0
  	BIGNUM *f=NULL,*ret=NULL;
  	int i,j,k,num=0,r= -1;
  	unsigned char *buf=NULL;
  	BN_CTX *ctx=NULL;
+ #endif
+ 
+ 	CK_ULONG ulsiglen;
+ 	CK_MECHANISM_PTR pMech = NULL;
+ 	CK_MECHANISM m_rsa_pkcs = {CKM_RSA_PKCS, 0,0};
+         CK_MECHANISM m_rsa_raw = {CKM_RSA_X_509, 0,0};
+ 	CK_RV ck_status;
+ 	CK_SESSION_HANDLE hSession;
+ 	CK_OBJECT_HANDLE hObject;
+ 
+ 	hSession = (CK_SESSION_HANDLE )RSA_get_ex_data(rsa,SC_RSA_EX_DATA_INDEX_SESSION);
+ 	hObject = (CK_OBJECT_HANDLE) RSA_get_ex_data(rsa,SC_RSA_EX_DATA_INDEX_OBJECT);
+ 
+ #ifdef DEBUG2
+ 	fprintf(stderr,"RSA_dee_private_encrypt\n");
+ 	fprintf(stderr,"hSession=%ld hObject=%ld\n", hSession, hObject);
+ #endif
+ 
+ 	switch (padding) {
+ 		case RSA_PKCS1_PADDING:
+ 			pMech = &m_rsa_pkcs;
+ 			break;
+ 		case RSA_NO_PADDING:
+ 			pMech = &m_rsa_raw;
+ 			break;
+ 		case RSA_SSLV23_PADDING:
+ 		default:
+ 			RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
+ 	}
+ 	if (pMech == NULL) {
+ 		return 0; 
+ 	}
+      
+ #ifdef DEBUG
+ 	fprintf(stderr,"Signing Proxy Certificate on Smart Card...\n");
+ #endif
  
+ 	ck_status = C_SignInit(hSession, pMech, hObject);
+ 	if (ck_status != CKR_OK) {
+                 SCerr(SCERR_F_RSA_ENCRYPT,SCERR_R_SIGNINIT);
+ 		ERR_add_error_data(1,sc_ERR_code(ck_status));
+ 		return 0;
+ 	}
+ 	ck_status = C_Sign(hSession,
+ 		from, flen, to, &ulsiglen);
+ 	if (ck_status != CKR_OK) {
+                 SCerr(SCERR_F_RSA_ENCRYPT,SCERR_R_SIGN);
+ 		ERR_add_error_data(1,sc_ERR_code(ck_status));
+ 		return 0;
+ 	}  
+ 	
+ #ifdef DEBUG
+ 	fprintf(stderr,"Signed\n");
+ #endif
+ 
+       return ulsiglen;	
+ #if 0
  	if ((ctx=BN_CTX_new()) == NULL) goto err;
  	num=BN_num_bytes(rsa->n);
  	if ((buf=(unsigned char *)Malloc(num)) == NULL)
***************
*** 249,254 ****
--- 309,315 ----
  		Free(buf);
  		}
  	return(r);
+ #endif
  	}
  
  static int RSA_eay_private_decrypt(flen, from, to, rsa,padding)
***************
*** 258,274 ****
--- 319,395 ----
  RSA *rsa;
  int padding;
  	{
+ #if 0
  	BIGNUM *f=NULL,*ret=NULL;
  	int j,num=0,r= -1;
  	unsigned char *p;
  	unsigned char *buf=NULL;
  	BN_CTX *ctx=NULL;
+ #endif
  
+ 	CK_ULONG ulsiglen;
+ 	CK_MECHANISM_PTR pMech = NULL;
+ 	CK_MECHANISM m_rsa_pkcs = {CKM_RSA_PKCS, 0,0};
+         CK_MECHANISM m_rsa_raw = {CKM_RSA_X_509, 0,0};
+ 	CK_RV ck_status;
+ 	CK_SESSION_HANDLE hSession;
+ 	CK_OBJECT_HANDLE hObject;
+ 
+ 	hSession = (CK_SESSION_HANDLE )RSA_get_ex_data(rsa,SC_RSA_EX_DATA_INDEX_SESSION);
+ 	hObject = (CK_OBJECT_HANDLE) RSA_get_ex_data(rsa,SC_RSA_EX_DATA_INDEX_OBJECT);
+ 
+ #ifdef DEBUG
+ 
+ 	/* DEE - Not realy sure where this is used, of if the correct PKCS11 module is
+ 	 * being called. It looks. like the SignRecover is equivelent to what is
+ 	 * called the private_decrypt
+ 	 */
+ 
+ 	fprintf(stderr,"RSA_dee_private_decrypt\n");
+ 	fprintf(stderr,"hSession=0x%lx hObject=0x%lx\n", hSession, hObject);
+ #endif
+ 
+ 	switch (padding) {
+ 		case RSA_PKCS1_PADDING:
+ 			pMech = &m_rsa_pkcs;
+ 			break;
+ 		case RSA_NO_PADDING:
+ 			pMech = &m_rsa_raw;
+ 			break;
+ 		case RSA_SSLV23_PADDING:
+ 		default:
+ 			RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT,RSA_R_UNKNOWN_PADDING_TYPE);
+ 	}
+ 	if (pMech == NULL) {
+ 		return 0; 
+ 	}
+ 
+       ulsiglen=BN_num_bytes(rsa->n);     
+ 
+         ck_status = C_SignRecoverInit(hSession, pMech, hObject);
+ 	if (ck_status != CKR_OK) {
+                 SCerr(SCERR_F_RSA_DECRYPT,SCERR_R_SIGNRECINIT);
+ 		ERR_add_error_data(1,sc_ERR_code(ck_status));
+ 		return 0;
+ 	}
+ 	ck_status = C_SignRecover(hSession,
+ 		from, flen, to, &ulsiglen);
+ 	if (ck_status != CKR_OK) {
+                 SCerr(SCERR_F_RSA_DECRYPT,SCERR_R_SIGNREC);
+ 		ERR_add_error_data(1,sc_ERR_code(ck_status));
+ 		return 0;
+ 	}  
+       return ulsiglen;	
+ 
+ 
+ #if 0
  	ctx=BN_CTX_new();
  	if (ctx == NULL) goto err;
  
+ 
  	num=BN_num_bytes(rsa->n);
  
+ 
  	if ((buf=(unsigned char *)Malloc(num)) == NULL)
  		{
  		RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,ERR_R_MALLOC_FAILURE);
***************
*** 339,344 ****
--- 460,466 ----
  		Free(buf);
  		}
  	return(r);
+ #endif
  	}
  
  static int RSA_eay_public_decrypt(flen, from, to, rsa, padding)
***************
*** 479,485 ****
--- 601,609 ----
  static int RSA_eay_init(rsa)
  RSA *rsa;
  	{
+ #if 0
  	rsa->flags|=RSA_FLAG_CACHE_PUBLIC|RSA_FLAG_CACHE_PRIVATE;
+ #endif
  	return(1);
  	}
  
