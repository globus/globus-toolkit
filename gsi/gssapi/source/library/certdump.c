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

certdump.c

Description:
	Program used dump the subject name and commonName of a cert

/**********************************************************************
                             Include header files
**********************************************************************/

#ifndef NO_GSSAPI_CONFIG_H
#include "globus_gssapi_config.h"
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

#include "sslutils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/buffer.h"
#include "openssl/crypto.h"
#include "openssl/objects.h"
#include "openssl/asn1.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/rsa.h"

#ifdef USE_PKCS11
#include "scutils.h"
#endif


/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

#ifdef WIN32
static int getuid() { return 0;}
#endif

/********************************************************************/

int main(int argc, char **argv)
{
	int debug=0;
	int verify=0;
	int mismatch=0;
	char *program;
	int badops=0;
	char *certfile=NULL;
	char *out1file=NULL;
	char *out2file=NULL;
	char *home=NULL;
	char *pin=NULL;
	char *argp;
	char *ss;
	BIO *bio_err;
	X509 *ucert;

	FILE *fp;
	FILE *fpout;

#ifdef USE_PKCS11
    CK_SESSION_HANDLE hSession = 0;
#endif


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
		argp = *argv;
		if ( *argp == '-' && *(argp+1) == '-') {
			argp++;
		}
		if  (strcmp(argp,"-debug") == 0) {
			debug++;
		}
		else if (strcmp(argp,"-cert") == 0) {
			if (--argc < 1) goto bad;
			certfile=*(++argv);
		} 
		else if (strcmp(argp,"-out1") == 0) {
			if (--argc < 1) goto bad;
			out1file=*(++argv);
		} 
		else if (strcmp(argp,"-out2") == 0) {
			if (--argc < 1) goto bad;
			out2file=*(++argv);
		} 
		else if (strcmp(argp,"-help") == 0) {
			badops=1;
			break;
		}
		else {
			fprintf(stderr,_GGSL("unknown option %s\n"),*argv);
			badops=1;
			break;
		}
		argc--;
		argv++;
	}

	if (badops) {
bad:
		fprintf(stderr,_GGSL("%s [options]\n"),program);
		fprintf(stderr,_GGSL("where options  are\n"));
		fprintf(stderr,_GGSL(" --help    show this list\n"));
		fprintf(stderr,_GGSL(" --debug   set debugging on\n"));
		fprintf(stderr,_GGSL(" --cert    file name of long term certificate\n"));
		fprintf(stderr,_GGSL(" --out1     file name for name\n"));
		fprintf(stderr,_GGSL(" --out2    file name for commonName\n");
		exit(1);
	}
	home = (char *)getenv("HOME");
	if (home == NULL) {
#ifndef WIN32
		fprintf(stderr,_GGSL("$HOME not defined"));
		exit(1);
#else
		home = "c:\\windows";
#endif
	}

	if (!strncmp(certfile,"SC:",3)) {
#ifdef USE_PKCS11
        char *cp;
        char *kp;
        int rc;
        cp = certfile + 3;
        kp = strchr(cp,':');
        if (kp == NULL) {
            fprintf(stderr,_GGSL("Bad format of cert name, SC:card:cert\n"));
            exit (2);
        }
        kp++; /* skip the : */
        if (hSession == 0) {
            rc = sc_init(&hSession, cp, NULL, pin, CKU_USER, 0);
            if (rc) {
                fprintf(stderr,_GGSL("Failed to open card session\n"));
                ERR_print_errors_fp (stderr);
                exit(2);
            }
        }


        rc = sc_get_cert_obj_by_label(hSession,kp,&ucert);
        if (rc) {
            fprintf(stderr,_GGSL("Failed to find certificate on card \n"));
            ERR_print_errors_fp (stderr);
            exit(2);
        }
#else
        fprintf(stderr,_GGSL("Smart card support not compiled with this program\n"));
            exit (2);
#endif /* USE_PKCS11 */

	} else {
		fp = fopen (certfile, "r");
		if (fp == NULL) {
			fprintf(stderr,_GGSL(" failed to open %s\n",certfile));
	 		exit (1);
		}

		ucert = PEM_read_X509 (fp, NULL, OPENSSL_PEM_CB(NULL, NULL));
		fclose (fp);
}

	if (ucert == NULL) {
		ERR_print_errors_fp (stderr);
		exit (1); 
	}

	if (out1file) {
		if (strcmp("-",out1file)) {
			fpout=fopen(out1file,"w");
		} else {
			fpout = stdout;
		}
		if (fpout == NULL) {
			fprintf (stderr,"Unable to open out1 file:%s\n", out1file);
			exit(4);
		}
		ss = X509_NAME_oneline(ucert->cert_info->subject,NULL,0);
		while (1) {
			if (!strcmp(ss+strlen(ss)-strlen("/CN=limited proxy"),
								"/CN=limited proxy")) {
				*(ss+strlen(ss)-strlen("/CN=limited proxy"))= '\0';
			} else
			if (!strcmp(ss+strlen(ss)-strlen("/CN=proxy"),
					"/CN=proxy")) {
				*(ss+strlen(ss)-strlen("/CN=proxy")) = '\0';
			} else {
				break;
			}
		}
		
		fprintf(fpout,"%s\n",ss);
		OPENSSL_free(ss);

		if (fpout != stdout) {
			fclose(fpout);
		}
	}


	if (out2file) {
		if (strcmp("-",out2file)) {
			fpout=fopen(out2file,"w");
		} else {
			fpout = stdout;
		}
		if (fpout == NULL) {
			fprintf (stderr,"Unable to open out2 file:%s\n", out2file);
			exit(4);
		}
		{
			X509_NAME *subject;
			X509_NAME_ENTRY *ne;
			ASN1_STRING *data;
			X509_NAME_ENTRY *o = NULL;
			X509_NAME_ENTRY *ou1 = NULL;
			X509_NAME_ENTRY *ou2 = NULL;
			int i;
	
			subject=X509_get_subject_name(ucert);
			i = X509_NAME_entry_count(subject)-1;
			while (i > 0) {
				ne=X509_NAME_get_entry(subject,i);
				if (!OBJ_cmp(ne->object,
						OBJ_nid2obj(NID_organizationName))) {
					if (!o) {
						o = ne;
					}
				}
				if (!OBJ_cmp(ne->object,
						OBJ_nid2obj(NID_organizationalUnitName))) {
					if (ou2) { 
						ou1 = ne;
					} else { 
						ou2 = ne;
					}
				}
				if (!OBJ_cmp(ne->object,
						OBJ_nid2obj(NID_commonName))) {
					data=X509_NAME_ENTRY_get_data(ne);
					if ((data->length == 5 &&
							!memcmp(data->data,"proxy",5)) ||
						(data->length == 13 &&
							!memcmp(data->data,"limited proxy",13))) {
							i--;
							continue;
					}
					fprintf(fpout,"%.*s\n",data->length,data->data);
					/* break; */
				}	
				i--;
			} 
			if (o) {
				data=X509_NAME_ENTRY_get_data(o);
				fprintf(fpout,"%.*s\n",data->length,data->data);
			}
			if (ou1) {
				data=X509_NAME_ENTRY_get_data(ou1);
				fprintf(fpout,"%.*s\n",data->length,data->data);
			}
			if (ou2) {
				data=X509_NAME_ENTRY_get_data(ou2);
				fprintf(fpout,"%.*s\n",data->length,data->data);
			}
		} /* inline section */
			

		if (fpout != stdout) {
			fclose(fpout);
		}
	} /* out2file */

	return 0;

}
