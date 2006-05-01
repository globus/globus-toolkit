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

grid_proxy_init.c

Description:
        Program used to get a session "proxy" certificate using
        your long term certificate. This is functionally equivelent 
        to the Kerberos kinit program. 

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


int fix_add_entry_asn1_set_param;
int debug = 0;
int quiet = 0;

/**********************************************************************
                       Define module specific variables
**********************************************************************/

#define SHORT_USAGE_FORMAT \
"\nSyntax: %s [-help][-pwstdin][-limited][-hours H] ...\n"


static char *  LONG_USAGE = \
"\n" \
"    Options\n" \
"    -help, -usage             Displays usage\n" \
"    -version                  Displays version\n" \
"    -debug                    Enables extra debug output\n" \
"        -q                        Quiet mode, minimal output\n" \
"    -verify                   Verifies certificate to make proxy for\n" \
"    -pwstdin                  Allows passphrase from stdin\n" \
"    -limited                  Creates a limited proxy\n" \
"    -hours H                  Proxy is valid for H hours (default:12)\n" \
"    -bits  B                  Number of bits in key {512|1024|2048|4096}\n" \
"\n" \
"    -cert     <certfile>      Non-standard location of user certificate\n" \
"    -key      <keyfile>       Non-standard location of user key\n" \
"    -certdir  <certdir>       Non-standard location of trusted cert dir\n" \
"    -out      <proxyfile>     Non-standard location of new proxy cert\n" \
"\n" \
"    -restriction <file>       Insert a restriction extension into the\n" \
"                              generated proxy.\n" \
"    -trusted-subgroup <grp>   Insert a trusted group extension into the\n" \
"                              generated proxy.\n" \
"    -untrusted-subgroup <grp> Insert a untrusted group extension into the\n" \
"                              generated proxy.\n" \
"\n";



#ifdef WIN32
static int getuid() { return 0;}
#endif
/**********************************************************************
Function: pwstdin_callback()

Description:
        Get the pass-phrase frm stdin. Used by some scripts 
        or graphical interfaces rather then the prompt to the 
        terminal. See SSLeay src/crypto/pem/pem_lib.c for 
        the def_callback(). 

Parameters:
        buf location to store the pass-phrase
        num length of the buf
        w   0 only need to prompt once, 1 verify by asking twice. 
                w is not needed here. 
        

Returns:
        length of pass-phrase returned
        -1 on error
**********************************************************************/

static int
pwstdin_callback(char * buf, int num, int w)
{
    int i;

    if (!(fgets(buf, num, stdin))) {
        fprintf(stderr,"Failed to read pass-phrase from stdin\n");
        return -1;
    }
    i = strlen(buf);
    if (buf[i-1] == '\n') {
        buf[i-1] = '\0';
        i--;
    }
    return i;       

}
/**********************************************************************
Function: kpcallback()

Description:
        prints the ...+++ during the key generation 
        Not clear if this assists in randomizing or just to let
        the user know its working

Parameters:

Returns:
**********************************************************************/

static void
kpcallback(int p, int n)
{
    char c='B';

    if (quiet) return;

    if (p == 0) c='.';
    if (p == 1) c='+';
    if (p == 2) c='*';
    if (p == 3) c='\n';
    if (!debug) c = '.';
    fputc(c,stderr);
}

/********************************************************************/

int
main(
    int                                 argc,
    char **                             argv)
{
    int                                 ret_status  = 0;
    /* default proxy to 512 bits */
    int                                 bits        = 512;
    /* default to a 12 hour cert */
    int                                 hours       = 12;
    /* dont restrict the proxy */
    int                                 verify      = 0;
    int                                 i;
    int                                 j;
    char *                              certfile    = NULL;
    char *                              keyfile     = NULL;
    char *                              outfile     = NULL;
    char *                              certdir     = NULL;
    char *                              certcafile  = NULL;
    char *                              pin         = NULL;
    char *                              filename;
    char *                              argp;
    char *                              program;
    proxy_cred_desc *                   pcd         = NULL;
    proxy_verify_desc                   pvd;
    proxy_verify_ctx_desc               pvxd;
    globus_proxy_type_t                 proxy_type = GLOBUS_FULL_PROXY;
    BIO *                               bio_err;
    X509 *                              xcert;
    time_t                              time_after;
    time_t                              time_now;
    time_t                              time_diff;
    time_t                              time_after_proxy;
    ASN1_UTCTIME *                      asn1_time = NULL;
    char *                              restriction_buf = NULL;
    size_t                              restriction_buf_len = 0;
    char *                              restriction_filename = NULL;
    FILE *                              fp;
    int                                 (*pw_cb)() = NULL;
    char *                              trusted_subgroup = NULL;
    char *                              untrusted_subgroup = NULL;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex = NULL;
    ASN1_OBJECT *                       asn1_obj = NULL;
    ASN1_OCTET_STRING *                 asn1_oct_string = NULL;

    
#ifdef WIN32
    CRYPTO_malloc_init();
#endif

    ERR_load_prxyerr_strings(0);
    SSLeay_add_all_algorithms();

    EVP_set_pw_prompt("Enter GRID pass phrase:");

    if ((bio_err=BIO_new(BIO_s_file())) != NULL)
        BIO_set_fp(bio_err,stderr,BIO_NOCLOSE);


    if (strrchr(argv[0],'/'))
        program = strrchr(argv[0],'/') + 1;
    else
        program = argv[0];

#   define args_show_version() \
    { \
        char buf[64]; \
        sprintf( buf, \
                 "%s-%s", \
                 PACKAGE, \
                 VERSION); \
        fprintf(stderr, "%s", buf); \
        exit(0); \
    }

#   define args_show_short_help() \
    { \
        fprintf(stderr, \
                SHORT_USAGE_FORMAT \
                "\nOption -help will display usage.\n", \
                program); \
        exit(0); \
    }

#   define args_show_full_usage() \
    { \
        fprintf(stderr, SHORT_USAGE_FORMAT \
                "%s", \
                program, \
                LONG_USAGE); \
        exit(0); \
    }

#   define args_error_message(errmsg) \
    { \
        fprintf(stderr, "ERROR: %s\n", errmsg); \
        args_show_short_help(); \
        exit(1); \
    }

#   define args_error(argnum, argval, errmsg) \
    { \
        char buf[1024]; \
        sprintf(buf, "argument #%d (%s) : %s", argnum, argval, errmsg); \
        args_error_message(buf); \
    }

#   define args_verify_next(argnum, argval, errmsg) \
    { \
        if ((argnum+1 >= argc) || (argv[argnum+1][0] == '-')) \
            args_error(argnum,argval,errmsg); \
    }


    for (i=1; i<argc; i++)
    {
        argp = argv[i];

        if (strncmp(argp,"--",2) == 0)
        {
            if (argp[2] != '\0')
            {
                args_error(i,argp,"double-dashed options are not allowed");
            }
            else
            {
                i = argc+1;             /* no more parsing */
                continue;
            }
        }
        if ((strcmp(argp,"-help")== 0) ||
            (strcmp(argp,"-usage")== 0)  )
        {
            args_show_full_usage();
        }
        else if (strcmp(argp,"-version")== 0)
        {
            args_show_version();
        }
        else if (strcmp(argp,"-cert")==0)
        {
            args_verify_next(i,argp,"need a file name argument");
            certfile = argv[++i];
        }
        else if (strcmp(argp,"-certdir")==0)
        {
            args_verify_next(i,argp,"need a file name argument");
            certdir = argv[++i];
        }
        else if (strcmp(argp,"-out")==0)
        {
            args_verify_next(i,argp,"need a file name argument");
            outfile = argv[++i];
        }
        else if (strcmp(argp,"-key")==0)
        {
            args_verify_next(i,argp,"need a file name argument");
            keyfile = argv[++i];
        }
        else if (strcmp(argp,"-hours")==0)
        {
            args_verify_next(i,argp,"integer argument missing");
            hours = atoi(argv[++i]);
        }
        else if (strcmp(argp,"-bits")==0)
        {
            args_verify_next(i,argp,"integer argument missing");
            bits = atoi(argv[i+1]);
            if ((bits!=512) && (bits!=1024) && (bits!=2048) && (bits!=4096))
                args_error(i,argp,"value must be one of 512,1024,2048,4096");
            i++;
        }
        else if (strcmp(argp,"-debug")==0)
        {
            debug++;
        }
        else if (strcmp(argp,"-limited")==0)
        {
            proxy_type = GLOBUS_LIMITED_PROXY;
        }
        else if (strcmp(argp,"-verify")==0)
        {
            verify++;
        }
        else if (strcmp(argp,"-q")==0)
        {
            quiet++;
        }
        else if (strcmp(argp,"-new")==0)
        {
            fix_add_entry_asn1_set_param = 0;
        }
        else if (strcmp(argp,"-pwstdin")==0)
        {
            pw_cb = pwstdin_callback;
        }
        else if (strcmp(argp,"-pin")==0)
        {
            if (i+1 >= argc)
                args_error(i,argp,"smartcard PIN is missing");
        }
        else if (strcmp(argp,"-restriction")==0)
        {
            args_verify_next(i,argp,"restriction file name missing");
            restriction_filename = argv[++i];
	    proxy_type = GLOBUS_RESTRICTED_PROXY;
        }
        else if (strcmp(argp,"-trusted-subgroup")==0)
        {
            args_verify_next(i,argp,"subgroup name missing");
            if(untrusted_subgroup != NULL ||
               trusted_subgroup != NULL)
            {
                args_error(i,argp,"You may only specify one subgroup.");
            }
            trusted_subgroup = argv[++i];
            proxy_type = GLOBUS_RESTRICTED_PROXY;
        }
        else if (strcmp(argp,"-untrusted-subgroup")==0)
        {
            args_verify_next(i,argp,"subgroup name missing");
            if(untrusted_subgroup != NULL ||
               trusted_subgroup != NULL)
            {
                args_error(i,argp,"You may only specify one subgroup.");
            }
            untrusted_subgroup = argv[++i];
            proxy_type = GLOBUS_RESTRICTED_PROXY;
        }
        else
            args_error(i,argp,"unrecognized option");
    }


    if ((pcd = proxy_cred_desc_new()) == NULL)
        goto err;

    pcd->type = CRED_TYPE_PERMANENT;

    if ( proxy_get_filenames(pcd,
                             0,
                             &certcafile,
                             &certdir,
                             &outfile,
                             &certfile,
                             &keyfile) )
        goto err;

    if (debug)
    {
        printf("Files being used:\n");
        printf("    cert_file: %s\n", certcafile ? certcafile:"none");  
        printf("    cert_dir : %s\n", certdir ? certdir:"none");
        printf("    proxy    : %s\n", outfile ? outfile:"none");
        printf("    user_cert: %s\n", certfile ? certfile:"none");
        printf("    user_key : %s\n", keyfile ? keyfile:"none");
    }

    if (certdir)
        pcd->certdir = strdup(certdir);
        
    if (!strncmp(certfile,"SC:",3))
    {
        EVP_set_pw_prompt("Enter card pin:");
    }
    else
    {
        EVP_set_pw_prompt(quiet? "Enter GRID pass phrase:" :
                          "Enter GRID pass phrase for this identity:");
    }

    if(strrchr(certfile,'/'))
    {
        filename = strrchr(certfile,'/') + 1;
    }
    else
    {
        filename = certfile;
    }

    if(strstr(filename,".pem"))
    {
        if (proxy_load_user_cert(pcd, certfile, pw_cb, NULL))
            goto err;

        if (!quiet)
        {
            char *s = NULL;
            s = X509_NAME_oneline(X509_get_subject_name(pcd->ucert),NULL,0);
            printf("Your identity: %s\n", s);
            free(s);
        }
        
        if (!strncmp(keyfile,"SC:",3))
            EVP_set_pw_prompt("Enter card pin:");
        
        if (proxy_load_user_key(pcd, keyfile, pw_cb, NULL))
            goto err;
    }
    else
    {
        char                            password[50];

        EVP_read_pw_string(password, 50, NULL, 0);

        if(pkcs12_load_credential(pcd,certfile,password))
        {
            goto err;
        }

        if (!quiet)
        {
            char *s = NULL;
            s = X509_NAME_oneline(X509_get_subject_name(pcd->ucert),NULL,0);
            printf("Your identity: %s\n", s);
            free(s);
        }
    }

    if (strncmp("SC:",certfile,3)
        && !strstr(filename, ".p12")
        && !strcmp(certfile, keyfile)) 
    {
        if (pcd->cert_chain == NULL)
            pcd->cert_chain = sk_X509_new_null();
        if (proxy_load_user_proxy(pcd->cert_chain, certfile, NULL) < 0)
            goto err;
    } 
    
    if (debug)
        printf("Output to %s\n",outfile);

    /*
     * verify if the cert is good, i.e. is signed by one of the
     * trusted CAs.
     */
    if (verify)
    {
        proxy_verify_ctx_init(&pvxd);
        proxy_verify_init(&pvd, &pvxd);
        pvxd.certdir = certdir;
        if (proxy_verify_cert_chain(pcd->ucert,pcd->cert_chain,&pvd)) {
            fprintf(stderr,"verify OK\n");
        } else {
            fprintf(stderr,"verify failed\n");
            goto err;
        }
    }


    asn1_time = ASN1_UTCTIME_new();
    X509_gmtime_adj(asn1_time,0);
    time_now = ASN1_UTCTIME_mktime(asn1_time);

    /* deal with the extensions */

    extensions = sk_X509_EXTENSION_new_null();
    
    if(restriction_filename)
    {
        int restriction_buf_size = 0;
        
        if(!(fp = fopen(restriction_filename,"r")))
        {
            fprintf(stderr,"\nUnable to open restrictions file\n");
            goto err;
        }

        do 
        {
            restriction_buf_size += 512;
            
            /* First time through this is a essentially a malloc() */
            restriction_buf = realloc(restriction_buf,
                                      restriction_buf_size);

            if (restriction_buf == NULL)
            {
                fprintf(stderr, "\nmalloc() failed\n");
                goto err;
            }

            restriction_buf_len += 
                fread(&restriction_buf[restriction_buf_len], 1, 512, fp);

            /*
             * If we read 512 bytes then restriction_buf_len and
             * restriction_buf_size will be equal and there is
             * probably more to read. Even if there isn't more
             * to read, no harm is done, we just allocate 512
             * bytes we don't end up using.
             */
        }
        while (restriction_buf_len == restriction_buf_size);

        if (restriction_buf_len > 0)
        {
            asn1_obj = OBJ_txt2obj("RESTRICTEDRIGHTS",0);   
        
            if(!(asn1_oct_string = ASN1_OCTET_STRING_new()))
            {
                fprintf(stderr, "\nmalloc() failed\n");
                goto err;
            }

            asn1_oct_string->data = restriction_buf;
            asn1_oct_string->length = restriction_buf_len;

            if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, asn1_obj, 
                                                    1, asn1_oct_string)))
            {
                fprintf(stderr, "Failed to create restrictions extension\n");
                goto err;
            }
        
            asn1_oct_string = NULL;

            if (!sk_X509_EXTENSION_push(extensions, ex))
            {
                fprintf(stderr, "Failed to create restrictions extension\n");
                goto err;
            }
        }   
    }

    if(trusted_subgroup)
    {
        asn1_obj = OBJ_txt2obj("TRUSTEDGROUP",0);   
        
        if(!(asn1_oct_string = ASN1_OCTET_STRING_new()))
        {
            fprintf(stderr, "\nmalloc() failed\n");
            goto err;
        }
        
        asn1_oct_string->data = trusted_subgroup;
        asn1_oct_string->length = strlen(trusted_subgroup);
        
        if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, asn1_obj, 
                                                1, asn1_oct_string)))
        {
            fprintf(stderr, "Failed to create trusted group extension\n");
            goto err;
        }
        
        asn1_oct_string = NULL;
        
        if (!sk_X509_EXTENSION_push(extensions, ex))
        {
            fprintf(stderr, "Failed to create trusted group extension\n");
            goto err;
        }        
    }

    if(untrusted_subgroup)
    {
        asn1_obj = OBJ_txt2obj("UNTRUSTEDGROUP",0);   
        
        if(!(asn1_oct_string = ASN1_OCTET_STRING_new()))
        {
            fprintf(stderr, "\nmalloc() failed\n");
            goto err;
        }
        
        asn1_oct_string->data = untrusted_subgroup;
        asn1_oct_string->length = strlen(untrusted_subgroup);
        
        if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, asn1_obj, 
                                                1, asn1_oct_string)))
        {
            fprintf(stderr, "Failed to create untrusted group extension\n");
            goto err;
        }
        
        asn1_oct_string = NULL;
        
        if (!sk_X509_EXTENSION_push(extensions, ex))
        {
            fprintf(stderr, "Failed to create untrusted group extension\n");
            goto err;
        }        
    }
    
    if (!quiet)
    {
        printf("Creating proxy ");
        fflush(stdout);
    }

    if (proxy_create_local(pcd,
                           outfile,
                           hours,
                           bits,
                           proxy_type,
                           (int (*)(void)) kpcallback,
                           extensions))
    {
        goto err;
    }
        
    if (!quiet)
    {
        printf(" Done\n");
    }

    /*
     * test if expired, or the proxy will not be good for expected
     * length of time
     * But an expired certificate and proxy can be used to 
     * renew a certificate, so we still create the proxy! 
     */

    time_after = ASN1_UTCTIME_mktime(X509_get_notAfter(pcd->ucert));
    time_diff = time_after - time_now ;
    if (time_diff < 0) {
        printf("Error: your certificate expired %s\n",
               asctime(localtime(&time_after)));
        ret_status = 2;
    } else
        if (hours && time_diff < hours*60*60) {
            printf("Warning: your certificate and proxy will expire %swhich is within the requested lifetime of the proxy\n",
                   asctime(localtime(&time_after)));
            ret_status = 1;
        }

    if (!quiet && ret_status == 0)
    {
        if (hours)
            time_after_proxy = time_now + hours*60*60;
        else
            time_after_proxy = time_after;

        printf("Your proxy is valid until %s",
               asctime(localtime(&time_after_proxy)));
    }
 
    return ret_status;


err:
    {
        unsigned long l;
        char buf[256];
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
        const char *file;
#else
        char *file;
#endif
	const char *data;
	int line;
        int flags;
	
	while ( ERR_peek_error() != 0 )
	{
	    l=ERR_get_error_line_data(&file,&line,&data,&flags);
	    if (debug)
            {
                fprintf(stderr,
                        "%s:%s:%d%s\n",
                        ERR_error_string(l,buf),
                        file,
                        line,
                        data);
            }
            else
            {
                fprintf(stderr,
                        "%s%s\nFunction: %s\n",
                        ERR_reason_error_string(l),
                        data,
                        ERR_func_error_string(l));
            }
        }
    }
    exit(3);
}

