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

scload.c

Description:
	Program used to load a certificate and/or key to the smartcard

CVS Information:

	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

static char *rcsid = "$Header$";

#ifdef USE_PKCS11

/**********************************************************************
                             Include header files
**********************************************************************/

#ifndef NO_GSSAPI_CONFIG_H
#include "gssapi_config.h"
#endif

#ifndef DEFAULT_SECURE_TMP_DIR
#ifndef WIN32
#define DEFAULT_SECURE_TMP_DIR "/tmp"
#else
#define DEFAULT_SECURE_TMP_DIR "c:\\tmp"
#endif /* WIN32 */
#endif /* DEFAULT_SECURE_TMP_DIR */

#ifndef WIN32
#define FILE_SEPERATOR "/"
#else
#define FILE_SEPERATOR "\\"
#endif

#include "scutils.h"
#include "sslutils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "crypto.h"
#include "objects.h"
#include "asn1.h"
#include "evp.h"
#include "x509.h"
#include "pem.h"
#include "ssl.h"

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

CK_FUNCTION_LIST_PTR pFunctionList;

#ifdef WIN32
static int getuid() { return 0;}
#endif
/**********************************************************************
Function: kpcallback()

Description:
	prints the ...+++ durint the key generation 
	Not clear if this assists in randomizing or just to let
	the user know its working

Parameters:

Returns:
**********************************************************************/

static void
kpcallback(int p, int n)
{
    char c='B';

    if (p == 0) c='.';
    if (p == 1) c='+';
    if (p == 2) c='*';
    if (p == 3) c='\n';
    fputc(c,stderr);
}

/****************************************************************
Function: sc_info_print

Description:
	Print the card label to stdout

******************************************************************/
static int
sc_info_print(int info, CK_SLOT_ID_PTR pslot)
{
	int rc;
	CK_TOKEN_INFO tokenInfo;

	rc = sc_init_one(pslot);
	if (rc) {
		fprintf(stderr,"Failed to find card\n");
		return 1;
	}	
	rc = sc_init_info(pslot, &tokenInfo);
	if (rc) {
		return rc;
	}

	printf("%.32s\n",tokenInfo.label);
	return 0;
}
/****************************************************************
Function: sc_initcard

Description:
	Initializal a card. Use the card label, if supplied on the
	command line, use the current/old SO pin, new SO PIN,
	and/or new user PIN. If not supplied, prompt for these. 
	This will allow for batching of these requests to new cards
	from a script for SC98.


*****************************************************************/

static int 
sc_initcard(CK_SLOT_ID_PTR pslot, char * card,
	char ** poldsopin, 	
	char ** psopin,  	
	char ** puserpin,
	FILE * fdlog)
{

	CK_SESSION_HANDLE sessionHandle;
	CK_RV status;
	CK_TOKEN_INFO tokenInfo;
	char label[33];
	char roldsopin[256];
	char rsopin[256];
	char ruserpin[256];
	char * oldsopin;
        char * sopin;
	char * userpin;
	
	int rc;

	rc = sc_init_one(pslot);
	if (rc) {
		fprintf(stderr,"Failed to find card\n");
		return 1;
	}	
		
	rc = sc_init_info(pslot, &tokenInfo);
	if (rc) {
		fprintf(stderr,"Failed to read token label\n");
		return 2;
	}
    printf("Smart Card Info:\n");
    printf(" Label:       %.32s\n",tokenInfo.label);
    printf(" Manufacturer:%.32s\n",tokenInfo.manufacturerID)
;
    printf(" Model:       %.16s\n",tokenInfo.model);
    printf(" SerialNumber:%.16s\n",tokenInfo.serialNumber);

	memset(label,' ',sizeof(label));
	memcpy(label, card, (strlen(card) > 32) ? 32: strlen(card));

	/* get the old SO user PIN */

	if (poldsopin && *poldsopin) {
		oldsopin = *poldsopin;
	} else {
		oldsopin = roldsopin; 
		memset(roldsopin,0,sizeof(roldsopin));
		rc = des_read_pw_string(roldsopin, sizeof(roldsopin),
					"Old SO PIN:", 0);
	    if (rc != 0) {
			fprintf(stderr,"PIN read failed %d\n",rc);
                        return 3;
		}
	}


#ifdef DEBUG
	fprintf(stderr,"Logging on with Old SO PIN...\n");
#endif
	rc = sc_init_open_login(&sessionHandle, pslot, oldsopin ,CKU_SO);
	if (rc) {
		fprintf(stderr,"Open/login failed\n");
		ERR_print_errors_fp(stderr);
		return 4;
	}
	
	/* get the new SO user PIN */

	if (psopin && *psopin) {
		sopin = *psopin;
	} else {
		sopin = rsopin; 
		memset(rsopin,0,sizeof(rsopin));
    readagain1:
		rc = des_read_pw_string(rsopin, sizeof(rsopin),
					"New SO PIN:", 1);
	    if (rc != 0) {
			fprintf(stderr,"PIN read failed\n");
                        goto readagain1;
			return 5;
		}
	}

	if (fdlog) {
		fprintf(fdlog,"Label:%32.32s Serial:%16.16s SOpin:%s\n",
			label,tokenInfo.serialNumber,sopin);
	}

	printf("Initalizing Token...\n");

	status = (*(pFunctionList->C_InitToken))(*pslot, 
				sopin, strlen(sopin), label);

	if (status != CKR_OK) {
		fprintf(stderr, "C_InitToken Failed:0x%8.8lx\n",status);	
		return 7;
	}

#ifdef DEBUG
	fprintf(stderr,"Logging on  with New SO PIN ...\n");
#endif
	rc = sc_init(&sessionHandle, card, pslot, sopin, CKU_SO, 1);
	memset(rsopin,0,sizeof(rsopin));
	if (rc) {
		ERR_print_errors_fp(stderr);
		return 8;
	}

	/* get the new User PIN */

	if (puserpin && *puserpin) {
		userpin = *puserpin;
	} else {
		userpin = ruserpin; 
		memset(ruserpin,0,sizeof(ruserpin));
    readagain2:
		rc = des_read_pw_string(ruserpin, sizeof(ruserpin),
					"New User PIN:", 1);
	    if (rc != 0) {
			fprintf(stderr,"PIN read failed\n");
                        goto readagain2;
			return 6;
		}
		/* if want to returned, return it i.e. puserpin->null */
		if (puserpin) {
			*puserpin = strdup(ruserpin);
		}
	}
	

	printf("Reseting User PIN...\n");

	status = (*(pFunctionList->C_InitPIN))(sessionHandle, 
				userpin, strlen(userpin));
	memset(ruserpin,0,sizeof(ruserpin));
	if (status) {
		fprintf(stderr, "C_InitPIN Failed:0x%8.8lx\n",status);
		return 9;
	}
	
	status = (*(pFunctionList->C_Logout))(sessionHandle);
	if (status) {
		fprintf(stderr, "C_Logout C_InitPIN failed:0x%8.8lx\n",status);
		return 10;
	}
	status = (*(pFunctionList->C_CloseSession))(sessionHandle);
 	if (status) {
		fprintf(stderr, "C_CloseSession C_InitPIN failed:0x%8.8lx\n",status);
		return 11;
	}
	return 0;
}

/************************************************************************************/

int main(int argc, char **argv)
{
	int debug=0;
	int verify=0;
	int mismatch=0;
	char *program;
	int badops=0;
	int initcard = 0;
	int initialized = 0;
	int info = 0;
	char *certfile=NULL;
	char *keyfile=NULL;
	char *outfile=NULL;
	char *certdir=NULL;
	char *logfile=NULL;
	FILE *fdlog = NULL;
	char *home=NULL;
	char *userpin = NULL;
	char *sopin = NULL;
	char *oldsopin = NULL;
	char *mylabel = "Globus";
    char *mydata = NULL;
	char *card = "Globus";
	int rc;
	CK_SESSION_HANDLE sessionHandle = 0;
	CK_SLOT_ID slot = 0; 
	BIO *bio_err;

	X509 *ucert;
	EVP_PKEY *upkey=NULL;

	FILE *fp;

	X509_STORE *cert_ctx=NULL;
	X509_LOOKUP *lookup=NULL;
	
#ifdef WIN32
	CRYPTO_malloc_init();
#endif

	ERR_load_prxyerr_strings(0);
	SSLeay_add_ssl_algorithms();

	if ((bio_err=BIO_new(BIO_s_file())) != NULL) {
        BIO_set_fp(bio_err,stderr,BIO_NOCLOSE);
	}

	program=argv[0];
	argc--;
	argv++;
	while (argc >= 1) {
		if  (strcmp(*argv,"-debug") == 0) {
			debug++;
		}
		else if (strcmp(*argv,"-cert") == 0) {
			if (--argc < 1) goto bad;
			certfile=*(++argv);
		} 
	    else if (strcmp(*argv,"-label") == 0) {
			if (--argc < 1) goto bad;
                        mylabel=*(++argv);
		} 
	    else if (strcmp(*argv,"-log") == 0) {
			if (--argc < 1) goto bad;
                        logfile=*(++argv);
		} 
            else if (strcmp(*argv,"-data") == 0) {
			if (--argc < 1) goto bad;
                        mydata=*(++argv);
		} 
		else if (strcmp(*argv,"-key") == 0) {
			if (--argc < 1) goto bad;
			keyfile=*(++argv);
		} 
		else if (strcmp(*argv,"-card") == 0) {
			if (--argc < 1) goto bad;
			card=*(++argv);
		} 
		else if (strcmp(*argv,"-init") == 0) {
			initcard++;
		} 
		else if (strcmp(*argv,"-userpin") == 0) {
			if (--argc < 1) goto bad;
			userpin=*(++argv);
		} 
		else if (strcmp(*argv,"-sopin") == 0) {
			if (--argc < 1) goto bad;
			sopin=*(++argv);
		} 
		else if (strcmp(*argv,"-oldsopin") == 0) {
			if (--argc < 1) goto bad;
			oldsopin=*(++argv);
		} 
		 else if (strcmp(*argv,"-info") == 0) {
			info++;
		}
		else {
			fprintf(stderr,"unknown option %s\n",*argv);
			badops=1;
			break;
		}
		argc--;
		argv++;
	}

	if (badops) {
bad:
		fprintf(stderr,"%s [options]\n",program);
		fprintf(stderr,"where options  are\n");
		fprintf(stderr," -debug   set debugging on\n");
		fprintf(stderr," -cert    file name of long term certificate\n");
		fprintf(stderr," -key     file name of the key for the certificate\n");
		
		fprintf(stderr," -label   object label for cert and key on card\n");
		fprintf(stderr," -init    Initialize a card. For SO user only\n");
		fprintf(stderr," -card    card label\n");
		fprintf(stderr," -userpin New User PIN\n");
		fprintf(stderr," -sopin   New SO PIN\n");
		fprintf(stderr," -oldsopin Old SO PIN\n");
		fprintf(stderr,"-log      file name of SO User info \n");
		exit(1);
	}
	if (logfile) {
		if ((fdlog = fopen(logfile,"a")) == NULL) {
			fprintf(stderr,"Unable to open logfile\n");
			exit (12);
		}
	}
		
	/*
	 * get DLL loaded and pointers to the pkcs#11 routines 
	 */
	if (!(pFunctionList=sc_get_function_list(&pFunctionList))) {
		fprintf(stderr,"Unable to get PKCS#11 loaded\n");
		exit (14);
	}


	if (info) {
		rc = sc_info_print(info, &slot);
		if (rc) {
			fprintf(stderr,"Unable to get info\n");
			exit (13);
		}
	}
	
	if (initcard) {
		rc = sc_initcard(&slot, card,
					 &oldsopin, &sopin, &userpin ,fdlog);
		if (rc) {
			ERR_print_errors_fp(stderr);
			fprintf(stderr,"Failed to initialize card rc = %d\n",rc);
			exit(2);
		}
		initialized = 1;
	}

	if ( certfile || keyfile ) {

		if (initialized) {
			printf("Logging on with New User PIN...\n");
		}
		rc = sc_init(&sessionHandle, card, &slot, userpin ,CKU_USER, initialized);
		if (rc) {
			ERR_print_errors_fp(stderr);
			exit (3);
		}
   	     if (mydata) {
   	             rc = sc_create_data_obj(sessionHandle,
   	                     mylabel, mydata, strlen(mydata));
   	             if (rc) {
   	                   ERR_print_errors_fp(stderr);
   	                   exit (4);
   	             }
		}
	
		
		if (certfile) {
			fp = fopen (certfile, "r");
			if (fp == NULL) {
				fprintf(stderr," failed to open %s\n",certfile);
		 		exit (5);
			}
	
			ucert = PEM_read_X509 (fp, NULL, OPENSSL_PEM_CB(NULL,NULL));
			fclose (fp);
	
			if (ucert == NULL) {
				ERR_print_errors_fp (stderr);
				exit (6); 
			}
			if (fdlog) {
				char *s;
				s = X509_NAME_oneline(ucert->cert_info->subject,NULL,0);
				fprintf(fdlog,"CERT:%s\n",s);
				OPENSSL_free(s);
			}
		/* now write it */
			rc = sc_create_cert_obj(sessionHandle, mylabel, ucert);
			if (rc) {
				ERR_print_errors_fp(stderr);
				exit(7);
			}
		}
	
		if (keyfile) {
			fp = fopen (keyfile, "r"); 
			if (fp == NULL) {
				fprintf(stderr,"failed to open %s\n",keyfile);
				exit (8);
			}
	
			if ((PEM_read_PrivateKey(fp,&upkey,
					OPENSSL_PEM_CB(NULL,NULL))) == NULL) {
				printf("PEM_read_privateKey failed\n");
				fprintf(stderr,"user key file=%s\n", keyfile);
				ERR_print_errors_fp (stderr);
			 	exit(9);
			}
			fclose (fp);
	
			rc = sc_create_priv_key_obj(sessionHandle, mylabel, upkey);
			if (rc) {
				ERR_print_errors_fp(stderr);
				exit (10);
			}
	
		}
		sc_final(sessionHandle);
	}

	if (fdlog) {
		fclose(fdlog);
	}
	return 0;

}
#else
#include <stdio.h>
int main() {
 fprintf(stderr,"PKCS#11 smart code not compiled. \n");
 exit (1);
}
#endif /* USE_PKCS11 */
