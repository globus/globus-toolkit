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

sslutils.c

Description:
        Routines used internally to implement delegation and proxy 
        certificates for use with Globus The same file is also used
        for the non-exportable sslk5 which allows Kerberos V5 to
        accept SSLv3 with certificates as proof of identiy and
        issue a TGT. 

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

#include "sslutils.h"
#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef DEFAULT_SECURE_TMP_DIR
#ifndef WIN32
#define DEFAULT_SECURE_TMP_DIR "/tmp"
#else
#define DEFAULT_SECURE_TMP_DIR "c:\\tmp"
#endif
#endif

#ifndef WIN32
#define FILE_SEPERATOR "/"
#else
#define FILE_SEPERATOR "\\"
#endif

#ifdef WIN32
#include "winglue.h"
#include <io.h>
#else
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <dirent.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

#include "openssl/buffer.h"
#include "openssl/crypto.h"

#include "openssl/objects.h"
#include "openssl/asn1.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/rand.h"
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
#include "openssl/x509v3.h"
#endif

#ifndef X509_V_ERR_INVALID_PURPOSE
#define X509_V_ERR_INVALID_PURPOSE X509_V_ERR_CERT_CHAIN_TOO_LONG
#endif 

#ifdef USE_PKCS11
#include "scutils.h"
#endif

#ifndef BUILD_FOR_K5CERT_ONLY
#ifndef NO_OLDGAA_API
#include "globus_oldgaa.h"
#include "globus_oldgaa_utils.h"
#else
#include "ca_policy_file_parse.h"
#endif
#endif

#ifdef WIN32
#ifndef ERR_file_name
#define ERR_file_name   __FILE__
#endif
#endif

int fix_add_entry_asn1_set_param = 0;

extern globus_mutex_t                   globus_l_gsi_ssl_utils_mutex;

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/
static ERR_STRING_DATA prxyerr_str_functs[]=
{
    {ERR_PACK(0,PRXYERR_F_PROXY_GENREQ ,0),"proxy_genreq"},
    {ERR_PACK(0,PRXYERR_F_PROXY_SIGN ,0),"proxy_sign"},
    {ERR_PACK(0,PRXYERR_F_VERIFY_CB ,0),"verify_callback"},
    {ERR_PACK(0,PRXYERR_F_PROXY_TMP ,0),"proxy_marshal_tmp"},
    {ERR_PACK(0,PRXYERR_F_INIT_CRED ,0),"proxy_init_cred"},
    {ERR_PACK(0,PRXYERR_F_LOCAL_CREATE, 0),"proxy_local_create"},
    {ERR_PACK(0,PRXYERR_F_CB_NO_PW, 0),"proxy_pw_cb"},
    {ERR_PACK(0,PRXYERR_F_GET_CA_SIGN_PATH, 0),"get_ca_signing_policy_path"},
    {ERR_PACK(0,PRXYERR_F_PROXY_SIGN_EXT ,0),"proxy_sign_ext"},
    {ERR_PACK(0,PRXYERR_F_PROXY_CHECK_SUBJECT_NAME,0),
     "proxy_check_subject_name"},
    {ERR_PACK(0,PRXYERR_F_PROXY_CONSTRUCT_NAME ,0),"proxy_construct_name"},
    {ERR_PACK(0,PRXYERR_F_SETUP_SSL_CTX ,0),"ssl_utils_setup_ssl_ctx"},
    {0,NULL},
};

static ERR_STRING_DATA prxyerr_str_reasons[]=
{
    {PRXYERR_R_PROCESS_PROXY_KEY, "processing proxy key"},
    {PRXYERR_R_PROCESS_REQ, "creating proxy req"},
    {PRXYERR_R_PROCESS_SIGN, "while signing proxy req"},
    {PRXYERR_R_MALFORM_REQ, "malformed proxy req"},
    {PRXYERR_R_SIG_VERIFY, "proxy req signature verification error"},
    {PRXYERR_R_SIG_BAD, "proxy req signature does not match"},
    {PRXYERR_R_PROCESS_PROXY, "processing user proxy cert"},
    {PRXYERR_R_PROXY_NAME_BAD, "proxy name does not match"},
    {PRXYERR_R_PROCESS_SIGNC, "while signing proxy cert"},
    {PRXYERR_R_BAD_PROXY_ISSUER, "proxy can only be signed by user"},
    {PRXYERR_R_SIGN_NOT_CA ,"user cert not signed by CA"},
    {PRXYERR_R_PROBLEM_PROXY_FILE ,"problems creating proxy file"},
    {PRXYERR_R_PROCESS_KEY, "processing key"},
    {PRXYERR_R_PROCESS_CERT, "processing cert"},
    {PRXYERR_R_PROCESS_CERTS, "unable to access trusted certificates in:"},
    {PRXYERR_R_PROCESS_CA_CERT, "unable to read trusted certificate in:"},
    {PRXYERR_R_PROCESS_PROXY, "processing user proxy cert"},
    {PRXYERR_R_NO_TRUSTED_CERTS, "check X509_CERT_DIR and X509_CERT_FILE"},
    {PRXYERR_R_PROBLEM_KEY_FILE, "bad file system permissions on private key\n"
                                 "    key must only be readable by the user"},
    {PRXYERR_R_SERVER_ZERO_LENGTH_KEY_FILE, "system key file is empty"},
    {PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE, "user private key file is empty"},
    {PRXYERR_R_PROBLEM_SERVER_NOKEY_FILE, "system key cannot be accessed"},
    {PRXYERR_R_PROBLEM_USER_NOKEY_FILE, "user private key cannot be accessed"},
    {PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE, "system certificate not found"},
    {PRXYERR_R_PROBLEM_USER_NOCERT_FILE, "user certificate not found"},
    {PRXYERR_R_INVALID_CERT, "no certificate in file"},
    {PRXYERR_R_REMOTE_CRED_EXPIRED, "remote certificate has expired"},
    {PRXYERR_R_USER_CERT_EXPIRED, "user certificate has expired"},
    {PRXYERR_R_SERVER_CERT_EXPIRED, "system certificate has expired"},
    {PRXYERR_R_PROXY_EXPIRED, "proxy expired: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_NO_PROXY, "no proxy credentials: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_CRL_SIGNATURE_FAILURE, "invalid signature on a CRL"},
    {PRXYERR_R_CRL_NEXT_UPDATE_FIELD, "invalid nextupdate field in CRL"},
    {PRXYERR_R_CRL_HAS_EXPIRED, "outdated CRL found, revoking all certs till you get new CRL"},
    {PRXYERR_R_CERT_REVOKED, "certificate revoked per CRL"},
    {PRXYERR_R_NO_HOME, "can't determine HOME directory"},
    {PRXYERR_R_KEY_CERT_MISMATCH, "user key and certificate don't match"},
    {PRXYERR_R_WRONG_PASSPHRASE, "wrong pass phrase"},
    {PRXYERR_R_CA_POLICY_VIOLATION, "remote certificate CA signature not allowed by policy"},
    {PRXYERR_R_CA_POLICY_ERR,"no matching CA found in file for remote certificate"}, 
    {PRXYERR_R_CA_NOFILE,"could not find CA policy file"}, 
    {PRXYERR_R_CA_NOPATH,"could not determine path to CA policy file"}, 
    {PRXYERR_R_CA_POLICY_RETRIEVE, "CA policy retrieve problems"},
    {PRXYERR_R_CA_POLICY_PARSE, "CA policy parse problems"},
    {PRXYERR_R_CA_UNKNOWN,"remote certificate signed by unknown CA"},
    {PRXYERR_R_PROBLEM_CLIENT_CA, "problems getting client_CA list"},
    {PRXYERR_R_CB_NO_PW, "no proxy credentials: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_CB_CALLED_WITH_ERROR,"certificate failed verify:"},
    {PRXYERR_R_CB_ERROR_MSG, "certificate:"},
    {PRXYERR_R_DELEGATE_VERIFY,"problem verifiying the delegate extension"},
    {PRXYERR_R_EXT_ADD,"problem adding extension"},
    {PRXYERR_R_DELEGATE_CREATE,"problem creating delegate extension"},
    {PRXYERR_R_DELEGATE_COPY,"problem copying delegate extension to proxy"},
    {PRXYERR_R_BUFFER_TOO_SMALL,"buffer too small"},
    {PRXYERR_R_CERT_NOT_YET_VALID,"remote certificate not yet valid"},
    {PRXYERR_R_LOCAL_CA_UNKNOWN,"cannot find CA certificate for local credential"},
    {PRXYERR_R_OUT_OF_MEMORY,"out of memory"},
    {PRXYERR_R_BAD_ARGUMENT,"bad argument"},
    {PRXYERR_R_BAD_MAGIC,"bad magic number"},
    {PRXYERR_R_UNKNOWN_CRIT_EXT,"unable to handle critical extension"},
    {0,NULL},
};

/*********************************************************************
Function: X509_NAME_cmp_no_set

Description:
        To circumvent a bug with adding X509_NAME_ENTRIES 
        with the wrong "set", we will compare names without
        the set. 
        This is a temporary fix which will be removed when we
        fix the creation of the names using the correct sets. 
        This is only being done this way for some compatability
        while installing the these fixes. 
        This fix is needed in all previous versions of Globus. 

Parameters:
        same as X509_NAME_cmp
Returns :
        same as X509_NAME_cmp 
********************************************************************/
static int
X509_NAME_cmp_no_set(
    X509_NAME *                         a,
    X509_NAME *                         b)
{
    int                                 i;
    int                                 j;
    X509_NAME_ENTRY *                   na;
    X509_NAME_ENTRY *                   nb;

    if (sk_X509_NAME_ENTRY_num(a->entries) !=
        sk_X509_NAME_ENTRY_num(b->entries))
    {
        return(sk_X509_NAME_ENTRY_num(a->entries) -
               sk_X509_NAME_ENTRY_num(b->entries));
    }
    
    for (i=sk_X509_NAME_ENTRY_num(a->entries)-1; i>=0; i--)
    {
        na = sk_X509_NAME_ENTRY_value(a->entries,i);
        nb = sk_X509_NAME_ENTRY_value(b->entries,i);
        j = na->value->length-nb->value->length;

        if (j)
        {
            return(j);
        }
        
        j = memcmp(na->value->data,
                   nb->value->data,
                   na->value->length);
        if (j)
        {
            return(j);
        }
        
        /*j=na->set-nb->set; */
        /* if (j) return(j); */
    }

    /* We will check the object types after checking the values
     * since the values will more often be different than the object
     * types. */
    for (i=sk_X509_NAME_ENTRY_num(a->entries)-1; i>=0; i--)
    {
        na = sk_X509_NAME_ENTRY_value(a->entries,i);
        nb = sk_X509_NAME_ENTRY_value(b->entries,i);
        j = OBJ_cmp(na->object,nb->object);

        if (j)
        {
            return(j);
        }
    }
    return(0);
}

#ifdef WIN32
/*********************************************************************
Function: getuid, getpid

Descriptions:
        For Windows95, WIN32, we don't have these, so we will default
    to using uid 0 and pid 0 Need to look at this better for NT. 
******************************************************************/
static unsigned long
getuid()
{
    return 0;
}

static int
getpid()
{
    return 0;
}

#endif /* WIN32 */



/**********************************************************************
Function: get_ca_signing_policy_path()

Description:

Given a CA certificate, return the filename for the signing policy
file for that certificate.

        
Parameters:

cert_dir, a string specifying the path to the trusted certificates
directory.

ca_name, the X509_NAME of the CA in question.


Returns:

Allocated buffer containing string with path to signing policy file
for this CA. NULL on error.

**********************************************************************/


static char *
get_ca_signing_policy_path(
    const char *                        cert_dir,
    X509_NAME *                         ca_name)
{
    char *                              buffer;
    unsigned int                        buffer_len;
    unsigned long                       hash;
    int                                 status;
    
    if ((cert_dir == NULL) ||
        (ca_name == NULL)) 
    {
        PRXYerr(PRXYERR_F_GET_CA_SIGN_PATH, PRXYERR_R_BAD_ARGUMENT);
        return NULL;
    }
    
    
    hash = X509_NAME_hash(ca_name);
    
    buffer_len = strlen(cert_dir) + strlen(FILE_SEPERATOR) + 8 /* hash */
        + strlen(SIGNING_POLICY_FILE_EXTENSION) + 1 /* NUL */;
    
    buffer = malloc(buffer_len);
    
    if (buffer == NULL) 
    {
        PRXYerr(PRXYERR_F_GET_CA_SIGN_PATH, PRXYERR_R_OUT_OF_MEMORY);
        return NULL;
    }

    sprintf(buffer,"%s%s%08lx%s", cert_dir, FILE_SEPERATOR, hash,
            SIGNING_POLICY_FILE_EXTENSION);
    
    return buffer;
}

#if SSLEAY_VERSION_NUMBER < 0x0900

/**********************************************************************
Function: ERR_add_error_data()

Description:
    Dummy routine only defined if running with SSLeay-0.8.x 
    this feature was introduced with SSLeay-0.9.0

Parameters:

Returns:
**********************************************************************/
void 
ERR_add_error_data( VAR_PLIST( int, num ))
    VAR_ALIST
{
    VAR_BDEFN(args, int, num);
}

/**********************************************************************
Function: ERR_get_error_line_data()

Description:
    Dummy routine only defined if running with SSLeay-0.8.x 
    this feature was introduced with SSLeay-0.9.0. We will
    simulate it for 0.8.1

Parameters:

Returns:
**********************************************************************/
unsigned long 
ERR_get_error_line_data(
    char **                             file,
    int *                               line,
    char **                             data,
    int *                               flags)
{
    if (data)
    {
        *data = "";
    }
    
    if (flags)
    {
        *flags = 0;
    }
    
    return (ERR_get_error_line(file, line));
}

#endif

/**********************************************************************
Function: ERR_set_continue_needed()

Description:
        Sets state information which error display routines can use to
        determine if the error just added is enough information to describe
        the error or if further error information need displayed. 
        (By default gss_display_status will only show one user level error)
        
        note: This function must be called after (or instead of) the ssl add error
        data functions.
        
Parameters:

Returns:
**********************************************************************/
    
void
ERR_set_continue_needed(void)
{
    ERR_STATE *es;
    es = ERR_get_state();
    es->err_data_flags[es->top] = 
        es->err_data_flags[es->top] | ERR_DISPLAY_CONTINUE_NEEDED;
}

/**********************************************************************
Function: ERR_load_prxyerr_strings()

Description:
    Sets up the error tables used by SSL and adds ours
    using the ERR_LIB_USER
    Only the first call does anything.
        Will also add any builtin objects for SSLeay. 

Parameters:
    i should be zero the first time one of the ERR_load functions
    is called and non-zero for each additional call.

Returns:
**********************************************************************/

int
ERR_load_prxyerr_strings(
    int                                 i)
{
    static int                          init = 1;
    struct stat                         stx;
    clock_t cputime;
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
    const char *                        randfile;
#else
    char *                              randfile;
#endif
    char *                              egd_path;
    char                                buffer[200];
        
#ifdef DEBUG
    fprintf(stderr,"ERR_load_prxyerr_strings, init=%d,i=%d\n",init,i);
#endif

    if (init)
    {
        init = 0;
        
#ifndef RAND_DO_NOT_USE_CLOCK
        clock(); 
#endif
        if (i == 0)
        {
            SSL_load_error_strings();
        }
        
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.2","DELEGATE","Delegate");
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.4","TRUSTEDGROUP",
                   "TrustedGroup");
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.5","UNTRUSTEDGROUP",
                   "UntrustedGroup");
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.3","RESTRICTEDRIGHTS",
                   "RestrictedRights");
        OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");

        ERR_load_strings(ERR_USER_LIB_PRXYERR_NUMBER,prxyerr_str_functs);
        ERR_load_strings(ERR_USER_LIB_PRXYERR_NUMBER,_SUSL(prxyerr_str_reasons));

        /*
         * We need to get a lot of randomness for good security
         * OpenSSL will use /dev/urandom (if available),
         * uid, time, and gid. 
         *
         * If user has RANDFILE set, or $HOME/.rnd
         * load it for extra random seed.
         * This may also not be enough, so we will also add in
         * the time it takes to run this routine, which includes 
         * reading the randfile.    
         * Later we will also add in some keys and some stats
         * if we have them.
         * look for RAND_add in this source file.
         *
         * Other methods we could use:
         *  * Librand from  Don Mitchell and Matt Blaze
         *  * Doing a netstat -in 
         *  * some form of pstat
         * But /dev/random and/or egd should be enough.
         */

        randfile = RAND_file_name(buffer,200);

        if (randfile)
        {
            RAND_load_file(randfile,1024L*1024L);
        }

#if SSLEAY_VERSION_NUMBER >=  0x0090581fL
        /*
         * Try to use the Entropy Garthering Deamon
         * See the OpenSSL crypto/rand/rand_egd.c 
         */
        egd_path = getenv("EGD_PATH");
        if (egd_path == NULL)
        {
            egd_path = "/etc/entropy";
        }
        RAND_egd(egd_path);
#endif
                
        /* if still not enough entropy*/
        if (RAND_status() == 0)
        {
            stat("/tmp",&stx); /* get times /tmp was modified */
            RAND_add((void*)&stx,sizeof(stx),16);
        }

#ifndef RAND_DO_NOT_USE_CLOCK
        cputime = clock();
        RAND_add((void*)&cputime, sizeof(cputime),8);
#endif
        
#if defined(DEBUG) || defined(DEBUGX)
        fprintf(stderr,"ERR_load_prxyerr_strings RAND_status=%d,i=%d\n",
                RAND_status(),i);
#endif
                        
        i++;
#ifdef USE_PKCS11
        i = ERR_load_scerr_strings(i);
#endif

    }
    return i;
}

/**********************************************************************
Function:       checkstat()
Description:    check the status of a file
Parameters:
Returns:
                0 pass all the following tests
                1 does not exist
                2 not owned by user
                3 readable by someone else
                4 zero length
**********************************************************************/
static int
checkstat(
    const char*                         filename)
{
    struct stat                         stx;

    if (stat(filename,&stx) != 0)
    {
        return 1;
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

#if !defined(WIN32) && !defined(TARGET_ARCH_CYGWIN)
    if (stx.st_uid != getuid())
    {
#ifdef DEBUG
        fprintf(stderr,"checkstat:%s:uid:%d:%d\n",filename,
                stx.st_uid, getuid());
#endif
        return 2;
    }

    if (stx.st_mode & 066)
    {
#ifdef DEBUG
        fprintf(stderr,"checkstat:%s:mode:%o\n",filename,stx.st_mode);
#endif
        return 3;
    }
    
#endif /* !WIN32 && !TARGET_ARCH_CYGWIN */

    if (stx.st_size == 0)
    {
        return 4;
    }
    return 0;

}


/**********************************************************************
Function:       checkcert()
Description:    check the status of a certificate file
Parameters:
Returns:
                0 pass all the following tests
                1 does not exist
                2 not owned by user
                3 writable by someone else
                4 zero length
**********************************************************************/
static int
checkcert(
    const char*                         filename)
{
    struct stat                         stx;

    if (stat(filename,&stx) != 0)
    {
        return 1;
    }

    /*
     * use any stat output as random data, as it will 
     * have file sizes, and last use times in it. 
     */
    RAND_add((void*)&stx,sizeof(stx),2);

#if !defined(WIN32) && !defined(TARGET_ARCH_CYGWIN)
    if (stx.st_uid != getuid())
    {
#ifdef DEBUG
        fprintf(stderr,"checkstat:%s:uid:%d:%d\n",filename,
                stx.st_uid, getuid());
#endif
        return 2;
    }

    if (stx.st_mode & 022)
    {
#ifdef DEBUG
        fprintf(stderr,"checkstat:%s:mode:%o\n",filename,stx.st_mode);
#endif
        return 3;
    }
    
#endif /* !WIN32 && !TARGET_ARCH_CYGWIN */

    if (stx.st_size == 0)
    {
        return 4;
    }
    return 0;

}


/***********************************************************************
Function: proxy_cred_desc_new()

Description:
        alloc a new proxy_cred_desc
*********************************************************************/

proxy_cred_desc *
proxy_cred_desc_new() 
{
    proxy_cred_desc *                   pcd;

    pcd = (proxy_cred_desc *)malloc(sizeof(proxy_cred_desc));
    
    if (pcd)
    {
        pcd->ucert = NULL;
        pcd->upkey = NULL;
        pcd->cert_chain = NULL;
        pcd->gs_ctx = NULL;
        pcd->hSession = 0;
        pcd->hPrivKey = 0;
        pcd->certdir = NULL;
        pcd->certfile = NULL;
        pcd->num_null_enc_ciphers = 0;
        pcd->type = CRED_TYPE_PERMANENT;
        pcd->owner = CRED_OWNER_USER;
    }
    
    return pcd;
}
/**********************************************************************
Function: proxy_load_user_proxy()

Description:
        Given the user_proxy file, skip the first cert, 
        and add any additional certs to the cert_chain. 
        These must be additional proxies, or the user's cert
        which signed the proxy. 
        This is based on the X509_load_cert_file routine.

Parameters:

Returns:
**********************************************************************/

int
proxy_load_user_proxy(
    STACK_OF(X509) *                    cert_chain,
    char *                              file,
    BIO *                               bp)
{

    int                                 ret = -1;
    BIO *                               in = NULL;
    int                                 i;
    int                                 count=0;
    X509 *                              x = NULL;

    if (bp)
    {
        in = bp;
    }
    else
    {
        if (file == NULL)
        {
            return(1);
        }
        in = BIO_new(BIO_s_file());
    }

    if ((in == NULL) || (!bp && BIO_read_filename(in,file) <= 0))
    {
        X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    for (;;)
    {
        x = PEM_read_bio_X509(in,NULL, OPENSSL_PEM_CB(NULL,NULL));
        if (x == NULL)
        {
            if ((ERR_GET_REASON(ERR_peek_error()) ==
                 PEM_R_NO_START_LINE) && (count > 0))
            {
                ERR_clear_error();
                break;
            }
            else
            {
                X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
                goto err;
            }
        }

#ifdef DEBUG
        {
            char *                      s;
            s = X509_NAME_oneline(X509_get_subject_name(x),NULL,0);
            fprintf(stderr,"Loading %d %p from user_proxy %s\n",
                    count,x,s);
            free(s);
        }
#endif

        if (bp || count)
        {
            i = sk_X509_insert(cert_chain,x,sk_X509_num(cert_chain));

            x = NULL;
        }
        
        count++;

        if (x)
        {
            X509_free(x);
            x = NULL;
        }
    }
    ret = count;
        
err:
    if (x != NULL)
    {
        X509_free(x);
    }
    
    if (!bp && in != NULL)
    {
        BIO_free(in);
    }
    return(ret);
}


/**********************************************************************
Function: proxy_genreq()

Description:
        generate certificate request for a proxy certificate. 
        This is based on using the current user certificate.
        If the current user cert is NULL, we are asking fke the server
    to fill this in, and give us a new cert. Used with k5cert.

Parameters:

Returns:
**********************************************************************/

int
proxy_genreq(
    X509 *                              ucert,
    X509_REQ **                         reqp,
    EVP_PKEY **                         pkeyp,
    int                                 bits,
    int                                 (*callback)(),
    proxy_cred_desc *                   pcd)

{
    RSA *                               rsa = NULL;
    EVP_PKEY *                          pkey = NULL;
    EVP_PKEY *                          upkey = NULL;
    X509_NAME *                         name = NULL; 
    X509_REQ *                          req = NULL;
    X509_NAME_ENTRY *                   ne = NULL;
    int                                 rbits;

    if (bits)
    {
        rbits = bits;
    }
    else if (ucert)
    { 
        if ((upkey = X509_get_pubkey(ucert)) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
            goto err;
        }
        
        if (upkey->type != EVP_PKEY_RSA)
        {
            EVP_PKEY_free(upkey);
            PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
            goto err;
        }
        
        rbits = 8 * EVP_PKEY_size(upkey);

        EVP_PKEY_free(upkey);

    }
    else
    {
        bits = 512;
    }
#ifdef DEBUG
    fprintf(stderr,"Using %d bits for proxy key\n",rbits);
#endif

    if ((pkey = EVP_PKEY_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }

    /*
     * Note: The cast of the callback function is consistent with
     * the declaration of RSA_generate_key() in OpenSSL.  It may
     * trigger a warning if you compile with SSLeay.
     */
    if ((rsa = RSA_generate_key(rbits,
                                RSA_F4,
                                (void (*)(int,int,void *))callback
                                ,NULL)) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }
    
    if (!EVP_PKEY_assign_RSA(pkey,rsa))
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }
    
    if ((req = X509_REQ_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
        goto err;
    }

    X509_REQ_set_version(req,0L);

    if (ucert)
    {

        if ((name = X509_NAME_dup(X509_get_subject_name(ucert))) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
            goto err;
        }
    }
    else
    {
        name = X509_NAME_new();
    }
                
        
    if ((ne = X509_NAME_ENTRY_create_by_NID(NULL,NID_commonName,
                                            V_ASN1_APP_CHOOSE,
                                            (unsigned char *)"proxy",
                                            -1)) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
        goto err;
    }
    
    X509_NAME_add_entry(name,
                        ne,
                        X509_NAME_entry_count(name),
                        fix_add_entry_asn1_set_param);

    X509_REQ_set_subject_name(req,name);
    X509_NAME_free(name);
    name = NULL;
    X509_REQ_set_pubkey(req,pkey);

    if (!X509_REQ_sign(req,pkey,EVP_md5()))
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_SIGN);
        goto err;
    }
        
    if (ne)
    {
        X509_NAME_ENTRY_free(ne);
        ne = NULL;
    }

    *pkeyp = pkey;
    *reqp = req;
    return 0;

err:
    if(rsa)
    {
        RSA_free(rsa);
    }
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
    if (name)
    {
        X509_NAME_free(name);
    }
    if (req)
    {
        X509_REQ_free(req);
    }
    if (ne)
    {
        X509_NAME_ENTRY_free(ne);
    }
    return 1;
}


/**
 * Sign a certificate request  
 *
 * This function is a wrapper function for proxy_sign_ext. The subject
 * name of the resulting certificate is generated by adding either
 * cn=proxy or cn=limited proxy to the subject name of user_cert. The
 * issuer name is set to the subject name of user_cert.
 *
 * @param user_cert
 *        A certificate to be used for subject and issuer name
 *        information if that information isn't provided.
 * @param user_private_key
 *        The private key to be used for signing the certificate
 *        request.
 * @param req
 *        The certificate request
 * @param new_cert
 *        This parameter will contain the signed certficate upon
 *        success. 
 * @param seconds
 *        The number of seconds the new cert is going to be
 *        valid. The validity should not exceed that of the issuing
 *        key pair. If this parameter is 0 the generated cert will
 *        have the same lifetime as the issuing key pair.
 * @param extensions
 *        Extensions to be placed in the new certificate.
 * @param limited_proxy
 *        If this value is non zero the resulting cert will be a
 *        limited proxy.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int
proxy_sign(
    X509 *                              user_cert,
    EVP_PKEY *                          user_private_key,
    X509_REQ *                          req,
    X509 **                             new_cert,
    int                                 seconds,
    STACK_OF(X509_EXTENSION) *          extensions,
    globus_proxy_type_t                 proxy_type)
{
    char *                              newcn;
    X509_NAME *                         subject_name = NULL;
    int                                 rc = 0;
        
    if(proxy_type == GLOBUS_LIMITED_PROXY)
    {
        newcn = "limited proxy";
    }
    else if(proxy_type == GLOBUS_RESTRICTED_PROXY)
    {
        newcn = "restricted proxy";
    }
    else
    {
        newcn = "proxy";
    }

    if(proxy_construct_name(
           user_cert,
           &subject_name,
           newcn))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_PROCESS_SIGN);
        return 1;
    }
    
    if(proxy_sign_ext(user_cert,
                      user_private_key,
                      EVP_md5(), 
                      req,
                      new_cert,
                      subject_name,
                      NULL,
                      seconds,
                      0,
                      extensions))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_PROCESS_SIGN);
        rc = 1;
    }

    X509_NAME_free(subject_name);
    return rc;
}

/**
 * Sign a certificate request  
 *
 * This function signs the given certificate request. Before signing
 * the certificate the certificate's subject and issuer names may be
 * replaced and extensions may be added to the certificate.
 *
 * @param user_cert
 *        A certificate to be used for lifetime and serial number
 *        information if that information isn't provided.
 * @param user_private_key
 *        The private key to be used for signing the certificate
 *        request.
 * @param method
 *        The method to employ for signing
 * @param req
 *        The certificate request
 * @param new_cert
 *        This parameter will contain the signed certficate upon
 *        success. 
 * @param subject_name
 *        The subject name to be used for the new certificate. If no
 *        subject name is provided the subject name in the certificate
 *        request will remain untouched.
 * @param issuer_name
 *        The issuer name to be used for the new certificate. If no
 *        issuer name is provided the issuer name will be set to the
 *        subject name of the user cert.
 * @param seconds
 *        The number of seconds the new cert is going to be
 *        valid. The validity should not exceed that of the issuing
 *        key pair. If this parameter is 0 the generated cert will
 *        have the same lifetime as the issuing key pair.
 * @param serial_num
 *        The serial number to be used for the new cert. If this
 *        parameter is 0 the serial number of the user_cert is used.
 * @param extensions
 *        Extensions to be placed in the new certificate.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int
proxy_sign_ext(
    X509 *                              user_cert,
    EVP_PKEY *                          user_private_key,
    EVP_MD *                            method,
    X509_REQ *                          req,
    X509 **                             new_cert,
    X509_NAME *                         subject_name,
    X509_NAME *                         issuer_name,    
    int                                 seconds,
    int                                 serial_num,
    STACK_OF(X509_EXTENSION) *          extensions)
{
    EVP_PKEY *                          new_public_key = NULL;
    EVP_PKEY *                          tmp_public_key = NULL;
    X509_CINF *                         new_cert_info;
    X509_CINF *                         user_cert_info;
    X509_EXTENSION *                    extension = NULL;
    int                                 i;

    user_cert_info = user_cert->cert_info;
    *new_cert = NULL;
    
    if ((req->req_info == NULL) ||
        (req->req_info->pubkey == NULL) ||
        (req->req_info->pubkey->public_key == NULL) ||
        (req->req_info->pubkey->public_key->data == NULL))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_MALFORM_REQ);
        goto err;
    }
    
    if ((new_public_key=X509_REQ_get_pubkey(req)) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_MALFORM_REQ);
        goto err;
    }

#ifdef DEBUG
    fprintf(stderr,"Verifying request\n");
#endif

    i = X509_REQ_verify(req,new_public_key);

    EVP_PKEY_free(new_public_key);

    if (i < 0)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_SIG_VERIFY);
        goto err;
    }

    if (i == 0)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_SIG_BAD);
        goto err;
    }

    /* signature ok. */

    if ((*new_cert = X509_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    new_cert_info = (*new_cert)->cert_info;

    /* set the subject name */

    if(subject_name && !X509_set_subject_name(*new_cert,subject_name))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    /* DEE? will use same serial number, this may help
     * with revocations, or may cause problems.
     */
    
    if (!ASN1_INTEGER_set(X509_get_serialNumber(*new_cert),
                          serial_num? serial_num:
                          ASN1_INTEGER_get(X509_get_serialNumber(user_cert))))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }


    /* set the issuer name */

    if (issuer_name)
    {
        if(!X509_set_issuer_name(*new_cert,issuer_name))
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
    }
    else
    {
        if(!X509_set_issuer_name(*new_cert,X509_get_subject_name(user_cert)))
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
            goto err;
        } 
    }

    /* Allow for a five minute clock skew here. */
 
    X509_gmtime_adj(X509_get_notBefore(*new_cert),-5*60);

    /* DEE? should accept an seconds parameter, and set to min of
     * hours or the ucert notAfter
     * for now use seconds if not zero. 
     */
    
    if (seconds)
    {
        X509_gmtime_adj(X509_get_notAfter(*new_cert),(long) seconds);
    }
    else
    {
        X509_set_notAfter(*new_cert, user_cert_info->validity->notAfter);
    }

    /* transfer the public key from req to new cert */
    /* DEE? should this be a dup? */

    X509_PUBKEY_free(new_cert_info->key);
    new_cert_info->key = req->req_info->pubkey;
    req->req_info->pubkey = NULL;

    /*
     * We can now add additional extentions here
     * such as to control the usage of the cert
     */

    if (new_cert_info->version == NULL)
    {
        if ((new_cert_info->version = ASN1_INTEGER_new()) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
    }

    /* Why is version set to 2 when we have a version 3 cert? - Sam */
    
    ASN1_INTEGER_set(new_cert_info->version,2); /* version 3 certificate */

    /* Free the current entries if any, there should not
     * be any I belive 
     */
    
    if (new_cert_info->extensions != NULL)
    {
        sk_X509_EXTENSION_pop_free(new_cert_info->extensions,
                                   X509_EXTENSION_free);
    }
        
    /* Add extensions provided by the client */

    if (extensions)
    {

#ifdef  DEBUG
        fprintf(stderr,"adding %d client extensions\n",
                sk_X509_EXTENSION_num(extensions));
#endif
        if ((new_cert_info->extensions =
             sk_X509_EXTENSION_new_null()) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
        }

        /* Lets 'copy' the client extensions to the new proxy */
        /* we should look at the type, and only copy some */

        for (i=0; i<sk_X509_EXTENSION_num(extensions); i++)
        {
            extension = X509_EXTENSION_dup(
                sk_X509_EXTENSION_value(extensions,i));

            if (extension == NULL)
            {
                PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
                goto err;
            }
            
            if (!sk_X509_EXTENSION_push(new_cert_info->extensions,
                                        extension))
            {
                PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
                goto err;
            }
        }
    }

    /* new cert is built, now sign it */

#ifndef NO_DSA
    /* DEE? not sure what this is doing, I think
     * it is adding from the key to be used to sign to the 
     * new certificate any info DSA may need
     */
    
    tmp_public_key = X509_get_pubkey(*new_cert);
    
    if (EVP_PKEY_missing_parameters(tmp_public_key) &&
        !EVP_PKEY_missing_parameters(user_private_key))
    {
        EVP_PKEY_copy_parameters(tmp_public_key,user_private_key);
    }

    EVP_PKEY_free(tmp_public_key);
    
#endif

    if (!X509_sign(*new_cert,user_private_key,method))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_SIGNC);
        goto err;
    }

#ifdef DEBUG
    fprintf(stderr,"Newly created proxy certificate:\n");
    X509_print_fp(stderr,*new_cert);
#endif
    return 0;

err:
    /* free new_cert upon error */
    
    if (*new_cert)
    {
        X509_free(*new_cert);
    }

    return 1;
}


/**
 * Check that the given subject name matches the one in the
 * certificate request.
 *
 * Check that the given subject name matches the one in the
 * certificate request.
 *
 * @param req
 *        The certificate request
 * @param subject_name
 *        The subject name to check against.
 *
 * @return
 *        0 on success
 *        1 on failure
 */


int
proxy_check_subject_name(
    X509_REQ *                          req,
    X509_NAME *                         subject_name)
{
    if (X509_NAME_cmp_no_set(subject_name,req->req_info->subject))
    {
        PRXYerr(PRXYERR_F_PROXY_CHECK_SUBJECT_NAME,
                PRXYERR_R_PROXY_NAME_BAD);
        return 1;
    }
    else
    {
        return 0;
    }
}


/**
 * Construct a X509 name
 *
 * This function constructs a X509 name by taking the subject name of
 * the certificate and adding a new CommonName field with value newcn
 * (if this parameter is non NULL). The resulting name should be freed
 * using X509_NAME_free.
 *
 * @param cert
 *        The certificate to extract the subject name from.
 * @param name
 *        The resulting name
 * @param newcn
 *        The value of the CommonName field to add. If this value is
 *        NULL this function just returns a copy of the subject name
 *        of the certificate.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int
proxy_construct_name(
    X509 *                              cert,
    X509_NAME **                        name,
    char *                              newcn)
{
    X509_NAME_ENTRY *                   name_entry = NULL;
    *name = NULL;
    
    if ((*name = X509_NAME_dup(X509_get_subject_name(cert))) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    if(newcn)
    {
        if ((name_entry = X509_NAME_ENTRY_create_by_NID(NULL,NID_commonName,
                                                        V_ASN1_APP_CHOOSE,
                                                        (unsigned char *)newcn,
                                                        -1)) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }

        if (!X509_NAME_add_entry(*name,
                                 name_entry,
                                 X509_NAME_entry_count(*name),
                                 fix_add_entry_asn1_set_param))
        {
            PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
        X509_NAME_ENTRY_free(name_entry);
    }
    
    return 0;

err:
    if (*name)
    {
        X509_NAME_free(*name);
    }

    if (name_entry)
    {
        X509_NAME_ENTRY_free(name_entry);
    }

    return 1;
    
}
    


/**********************************************************************
Function: proxy_marshal_tmp()

Description:
        Write out the proxy certificate, key, users certificate,
        and any other certificates need to use the proxy.

Parameters:

Returns:
**********************************************************************/
int
proxy_marshal_tmp(
    X509 *                              ncert,
    EVP_PKEY *                          npkey,
    X509 *                              ucert,
    STACK_OF(X509) *                    cert_chain,
    char **                             crednamep)
{
    struct stat                         stx;
    char                                filename[L_tmpnam+256];
    char                                tmpfname[L_tmpnam];
    char *                              tfp;
    char *                              envstr;
    int                                 i = 0;
    int                                 rc;
    FILE *                              fp;
    BIO *                               bp;

#ifdef DEBUG
    fprintf(stderr,"proxy_marshal_tmp\n");
#endif

    /*
     * use the unique part of the Posix, ANSI C tmpnam 
     * as part of our file name for thread safty. 
     * P_tmpdir is defined as the directory part.
     */
    tfp = tmpnam(tmpfname);
    tfp = strrchr(tfp,'/');
    tfp++;

    do
    {
        sprintf(filename,"%s%s%s%d.%s.%d",
                DEFAULT_SECURE_TMP_DIR,
                FILE_SEPERATOR,
                X509_USER_DELEG_FILE,
                getpid(),
                tfp,
                i++);
    }
    while(stat(filename,&stx) == 0);

    if ((fp = fopen(filename,"w")) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_TMP,PRXYERR_R_PROBLEM_PROXY_FILE);
        return 1;
    }

    if ((envstr = (char *)malloc(strlen(X509_USER_PROXY) +
                                 strlen(filename) + 2)) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_TMP, PRXYERR_R_OUT_OF_MEMORY);
        return 1;
    }
    strcpy(envstr,X509_USER_PROXY);
    strcat(envstr,"=");
    strcat(envstr,filename);

    if (crednamep)
    {
        *crednamep = envstr;
#ifdef DEBUG
        fprintf(stderr,"Using filename %s\n",filename);
#endif
    }
    else
    {
#ifdef DEBUG
        fprintf(stderr,"Setting ENV %s\n",envstr);
#endif
        putenv(envstr);
    }

#ifndef WIN32
    if (chmod(filename,0600) != 0)
    {
        PRXYerr(PRXYERR_F_PROXY_TMP,PRXYERR_R_PROBLEM_PROXY_FILE);
        return 2;
    }
#endif
        
    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp,fp,BIO_NOCLOSE);
    rc = proxy_marshal_bp(bp,ncert,npkey,ucert,cert_chain);

    if(rc)
    {
        *crednamep = NULL;
        free(envstr);
    }

    BIO_free(bp);
    if (fp != stdout)
    {
        fclose(fp);
    }

    return rc;
                
}
/**********************************************************************
Function: proxy_marshal_bp()

Description:
        Write to a bio the proxy certificate, key, users certificate,
        and any other certificates need to use the proxy.

Parameters:

Returns:
**********************************************************************/
int
proxy_marshal_bp(
    BIO *                               bp,
    X509 *                              ncert,
    EVP_PKEY *                          npkey,
    X509 *                              ucert,
    STACK_OF(X509) *                    cert_chain)
{
    int                                 i;
    X509 *                              cert;

#ifdef DEBUG2
    fprintf(stderr,"proxy_marsh_bp:\n");
#endif

#ifdef DEBUG
    {
        char * s;
        s = X509_NAME_oneline(X509_get_subject_name(ncert),NULL,0);
        fprintf(stderr,"  ncert:%s\n",s);
        free(s);
    }
#endif

    if (!PEM_write_bio_X509(bp,ncert))
    {
        return 1;
    }

    if (!PEM_write_bio_RSAPrivateKey(bp,
                                     npkey->pkey.rsa,
                                     NULL,
                                     NULL,
                                     0,
                                     OPENSSL_PEM_CB(NULL,NULL)))
    {
        return 2;
    }

    if (ucert)
    {
#ifdef DEBUG
        {
            char * s;
            s = X509_NAME_oneline(X509_get_subject_name(ucert),NULL,0);
            fprintf(stderr,"  ucert:%s\n",s);
            free(s);
        }
#endif
        if (!PEM_write_bio_X509(bp,ucert))
        {
            return 3;
        }
    }

    if (cert_chain)
    {
                        
#ifdef DEBUG
        fprintf(stderr,"proxy_marshal cert_chain:%d\n",
                sk_X509_num(cert_chain));
#endif
        /*
         * add additional certs, but not our cert, or the 
         * proxy cert, or any self signed certs
         */

        for(i=0;i<sk_X509_num(cert_chain);i++)
        {
            cert = sk_X509_value(cert_chain,i);
            if (!(!X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                        X509_get_subject_name(ncert)) 
                  || (ucert &&
                      !X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                            X509_get_subject_name(ucert)))  
                  || !X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                           X509_get_issuer_name(cert))))
            {
#ifdef DEBUG
                {
                    char * s;
                    s = X509_NAME_oneline(X509_get_subject_name(cert),
                                          NULL,
                                          0);
                    fprintf(stderr,"  cert:%s\n",s);
                    free(s);
                }
#endif
                if (!PEM_write_bio_X509(bp,cert))
                {
                    return 4;
                }
            }
        }
    }
        
    return 0;
}

/**********************************************************************
Function: proxy_verify_init()

Description:

Parameters:
   
Returns:
**********************************************************************/

void 
proxy_verify_init(
    proxy_verify_desc *                 pvd,
    proxy_verify_ctx_desc *             pvxd)
{
    pvd->magicnum = PVD_MAGIC_NUMBER; /* used for debuging */
    pvd->flags = 0;
    pvd->previous = NULL;
    pvd->pvxd = pvxd;
    pvd->proxy_depth = 0;
    pvd->cert_depth = 0;
    pvd->cert_chain = NULL;
    pvd->limited_proxy = 0;
    pvd->multiple_limited_proxy_ok = 0;
}

/**********************************************************************
Function: proxy_verify_ctx_init()

Description:

Parameters:
   
Returns:
**********************************************************************/

void 
proxy_verify_ctx_init(
    proxy_verify_ctx_desc *             pvxd)
{

    pvxd->magicnum = PVXD_MAGIC_NUMBER; /* used for debuging */
    pvxd->certdir = NULL;
    pvxd->goodtill = 0;

}

/**********************************************************************
Function: proxy_verify_release()

Description:

Parameters:
   
Returns:
**********************************************************************/

void 
proxy_verify_release(
    proxy_verify_desc *                 pvd)
{
    if (pvd->cert_chain)
    {
        sk_X509_pop_free(pvd->cert_chain,X509_free);
    }
    pvd->cert_chain = NULL;
    pvd->pvxd = NULL;
}

/**********************************************************************
Function: proxy_verify_ctx_release()

Description:

Parameters:
   
Returns:
**********************************************************************/

void 
proxy_verify_ctx_release(
    proxy_verify_ctx_desc *             pvxd)
{
    if (pvxd->certdir)
    {
        free(pvxd->certdir);
        pvxd->certdir = NULL;
    }
}

#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
/**********************************************************************
Function: proxy_app_verify_callback()

Description:
        SSL callback which lets us do the x509_verify_cert
        ourself. We use this to set the ctx->check_issued routine        
        so we can override some of the tests if needed. 

Parameters:
   
Returns:
        Same as X509_verify_cert 
**********************************************************************/

static int 
proxy_app_verify_callback(
    X509_STORE_CTX *                    ctx)
{
        
#ifdef DEBUG
    fprintf(stderr,"proxy_app_verify_callback\n");
#endif

    /*
     * OpenSSL-0.9.6 has a  check_issued routine which
     * we want to override so we  can replace some of the checks.
     */

    ctx->check_issued = proxy_check_issued;
    return X509_verify_cert(ctx);
}
#endif

/* Ifdef out all extra code not needed for k5cert
 * This includes the OLDGAA
 */

#ifndef BUILD_FOR_K5CERT_ONLY
/**********************************************************************
Function: proxy_check_proxy_name()

Description:
    Check if the subject name is a proxy, and the issuer name
        is the same as the subject name, but without the proxy
    entry. 
        i.e. inforce the proxy signing requirement of 
        only a user or a user's proxy can sign a proxy. 
        Also pass back Rif this is a limited proxy. 

Parameters:

Returns:
        -1  if there was an error
         0  if not a proxy
         1  if a proxy
         2  if a limited proxy

*********************************************************************/

proxy_check_proxy_name(
    X509 *                              cert)
{
    int                                 ret = 0;
    X509_NAME *                         subject;
    X509_NAME *                         issuer;
    X509_NAME *                         name = NULL;
    X509_NAME_ENTRY *                   ne = NULL;
    ASN1_STRING *                       data;


    subject = X509_get_subject_name(cert);
    ne = X509_NAME_get_entry(subject, X509_NAME_entry_count(subject)-1);
    if (!OBJ_cmp(ne->object,OBJ_nid2obj(NID_commonName)))
    {
        data = X509_NAME_ENTRY_get_data(ne);
        if ((data->length == 5 && 
             !memcmp(data->data,"proxy",5)) || 
            (data->length == 13 && 
             !memcmp(data->data,"limited proxy",13)) ||
	    (data->length == 16 && !memcmp(data->data,"restricted proxy",16)))
        {
        
            if (data->length == 13)
            {
                ret = GLOBUS_LIMITED_PROXY; /* its a limited proxy */
            }
            else if (data->length == 16)
	    {
                ret = GLOBUS_RESTRICTED_PROXY; /* its a restricted proxy */
            }
	    else
            {
                ret = GLOBUS_FULL_PROXY; /* its a proxy */
            }
#ifdef DEBUG
	    /* changed by slang: just using data->data since its been checked */
            fprintf(stderr,"Subject is a %s\n", data->data);
#endif
            /*
             * Lets dup the issuer, and add the CN=proxy. This should
             * match the subject. i.e. proxy can only be signed by
             * the owner.  We do it this way, to double check
             * all the ANS1 bits as well.
             */

            /* DEE? needs some more err processing here */

            name = X509_NAME_dup(X509_get_issuer_name(cert));
            ne = X509_NAME_ENTRY_create_by_NID(NULL,
                                               NID_commonName,
                                               V_ASN1_APP_CHOOSE,
                                               data->data,
                                               -1);

            X509_NAME_add_entry(name,ne,X509_NAME_entry_count(name),0);
            X509_NAME_ENTRY_free(ne);
            ne = NULL;

            if (X509_NAME_cmp_no_set(name,subject))
            {
                /*
                 * Reject this certificate, only the user
                 * may sign the proxy
                 */
                ret = -1;
            }
            X509_NAME_free(name);
        }
    }
    return ret;
}

#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
/**********************************************************************
 Function: proxy_check_issued()

Description:
        Replace the OpenSSL check_issued in x509_vfy.c with our own,
        so we can override the key usage checks if its a proxy. 
        We are only looking for X509_V_ERR_KEYUSAGE_NO_CERTSIGN

Parameters:r
        See OpenSSL check_issued

Returns:
        See OpenSSL check_issued

**********************************************************************/

int 
proxy_check_issued(
    X509_STORE_CTX *                    ctx,
    X509 *                              x,
    X509 *                              issuer)
{
    int                                 ret;
    int                                 ret_code = 1;
        
    ret = X509_check_issued(issuer, x);
    if (ret != X509_V_OK)
    {
        ret_code = 0;
        switch (ret)
        {
        case X509_V_ERR_AKID_SKID_MISMATCH:
            /* 
             * If the proxy was created with a previous version of Globus
             * where the extensions where copied from the user certificate
             * This error could arise, as the akid will be the wrong key
             * So if its a proxy, we will ignore this error.
             * We should remove this in 12/2001 
             * At which time we may want to add the akid extension to the proxy.
             */

        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
            /*
             * If this is a proxy certificate then the issuer
             * does not need to have the key_usage set.
             * So check if its a proxy, and ignore
             * the error if so. 
             */
            if (proxy_check_proxy_name(x) >= 1)
            {
                ret_code = 1;
            }
            break;
        default:
            break;
        }
    }
#ifdef DEBUG
    fprintf(stderr,"proxy_check_issued ret:%d ret_code:%d\n",
            ret, ret_code);
#endif
    return ret_code;
}
#endif

/**********************************************************************
Function: proxy_verify_callback()

Description:
        verify callback for SSL. Used to check that proxy
        certificates are only signed by the correct user, 
        and used for debuging.
        
        Also on the server side, the s3_srvr.c code does not appear
        to save the peer cert_chain, like the client side does. 
        We need these for additional proxies, so we need to 
        copy the X509 to our own stack. 

Parameters:
        ok  1 then we are given one last chance to check
                this certificate.
                0 then this certificate has failed, and ctx->error has the
                reason. We may want to override the failure. 
        ctx the X509_STORE_CTX which has as a user arg, our 
                proxy verify desc. 
   
Returns:
        1 - Passed the tests
        0 - failed.  The x509_vfy.c will return a failed to caller. 
**********************************************************************/

int 
proxy_verify_callback(
    int                                 ok,
    X509_STORE_CTX *                    ctx)
{
    X509_OBJECT                         obj;
    X509 *                              cert = NULL;
    X509_CRL *                          crl;
    X509_CRL_INFO *                     crl_info;
    X509_REVOKED *                      revoked;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex;
    ASN1_OBJECT *                       extension_obj;
    EVP_PKEY *                          tmp_public_key;
    int                                 nid;
    char *                              s = NULL;
    SSL *                               ssl = NULL;
    proxy_verify_desc *                 pvd;
    int                                 itsaproxy = 0;
    int                                 i;
    int                                 n;
    int                                 ret;
    time_t                              goodtill;
    char *                              ca_policy_file_path = NULL;
    char *                              cert_dir            = NULL;
    char *                              ca_policy_filename  = "ca-signing-policy.conf";
    
    
    /*
     * If we are being called recursivly to check delegated
     * cert chains, or being called by the grid-proxy-init,
     * a pointer to a proxy_verify_desc will be 
     * pased in the store.  If we are being called by SSL,
     * by a roundabout process, the app_data of the ctx points at
     * the SSL. We have saved a pointer to the  context handle
     * in the SSL, and its magic number should be PVD_MAGIC_NUMBER 
     */
#ifdef DEBUG
    fprintf(stderr,"\nproxy_verify_callback\n");
#endif
    if ((pvd = (proxy_verify_desc *)
         X509_STORE_CTX_get_ex_data(ctx,
                                    PVD_STORE_EX_DATA_IDX)))
    {
#ifdef DEBUG
        fprintf(stderr,"Called with alternate ex_data\n");
#endif
    }
    else
    {
        ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
        pvd = (proxy_verify_desc *)SSL_get_ex_data(ssl,
                                                   PVD_SSL_EX_DATA_IDX);
    }

    /*
     * For now we hardcode the ex_data. We could look at all 
     * ex_data to find ours. 
     * Double check that we are indeed pointing at the context
     * handle. If not, we have an internal error, SSL may have changed
     * how the callback and app_data are handled
     */
    
    if(pvd->magicnum != PVD_MAGIC_NUMBER)
    {
        PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_BAD_MAGIC);
        return(0);
    }

#ifdef DEBUG
    fprintf(stderr," magicnum=%d,OK=%d\n",
            pvd->magicnum, ok);
    s = X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),NULL,0);
    
    if (ok)
    {
        fprintf(stderr,"ctx->error_depth=%d %s\n",ctx->error_depth,
                s?s:"no-subject");
    }
    else
    {
        fprintf(stderr,"ctx->error_depth=%d error=%d %s\n",
                ctx->error_depth,ctx->error,s?s:"no-subject");
    }
    
    if (s)
    {
        free(s);
    }
    s = NULL;
    fprintf(stderr,"pvd->proxy_depth=%d, pvd->cert_depth=%d\n",
            pvd->proxy_depth, pvd->cert_depth);
#endif

    /*
     * We now check for some error conditions which
     * can be disregarded. 
     */
        
    if (!ok)
    {
        switch (ctx->error)
        {
#if SSLEAY_VERSION_NUMBER >=  0x0090581fL
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
#ifdef DEBUG
            fprintf(stderr,"X509_V_ERR_PATH_LENGTH_EXCEEDED\n");
#endif
            /*
             * Since OpenSSL does not know about proxies,
             * it will count them against the path length
             * So we will ignore the errors and do our
             * own checks later on, when we check the last
             * certificate in the chain we will check the chain.
             */
            ok = 1;
            break;
#endif
        default:
            break;
        }                       
        /* if already failed, skip the rest, but add error messages */
        if (!ok)
        {
            if (ctx->error==X509_V_ERR_CERT_NOT_YET_VALID)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CERT_NOT_YET_VALID);
                ERR_set_continue_needed();
            }
            else if (ctx->error==X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_LOCAL_CA_UNKNOWN); 
                ERR_set_continue_needed();
            }
            else if (ctx->error==X509_V_ERR_CERT_HAS_EXPIRED)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_REMOTE_CRED_EXPIRED); 
                ERR_set_continue_needed();
            }

            goto fail_verify;
        }
#ifdef DEBUG
        fprintf(stderr,"proxy_verify_callback:overriding:%d\n\n",
                ctx->error);
#endif
        /* don't really understand why we clear the error - Sam */
        ctx->error = 0;
        return(ok);
    }

    /* 
     * All of the OpenSSL tests have passed and we now get to 
     * look at the certificate to verify the proxy rules, 
     * and ca-signing-policy rules. We will also do a CRL check
     */

    /*
     * Test if the name ends in CN=proxy and if the issuer
     * name matches the subject without the final proxy. 
     */
        
    ret = proxy_check_proxy_name(ctx->current_cert);
    if (ret < 0)
    {
        PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_BAD_PROXY_ISSUER);
        ERR_set_continue_needed();
        ctx->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
        goto fail_verify;
    }
    if (ret > 0)
    {  /* Its a proxy */
        if (ret == GLOBUS_LIMITED_PROXY)
        {
            /*
             * If its a limited proxy, it means it use has been limited 
             * during delegation. It can not sign other certs i.e.  
             * it must be the top cert in the chain. 
             * Depending on who we are, 
             * We may want to accept this for authentication. 
             * 
             *   Globus gatekeeper -- don't accept
             *   sslk5d accept, but should check if from local site.
             *   globus user-to-user Yes, thats the purpose 
             *    of this cert. 
             *
             * We will set the limited_proxy flag, to show we found
             * one. A Caller can then reject. 
             */

            pvd->limited_proxy = 1; /* its a limited proxy */

            if (ctx->error_depth && !pvd->multiple_limited_proxy_ok)
            {
                /* tried to sign a cert with a limited proxy */
                /* i.e. there is still another cert on the chain */
                /* indicating we are trying to sign it! */
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_LPROXY_MISSED_USED);
                ERR_set_continue_needed();
                ctx->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
                goto fail_verify;
            }
        }

#ifdef DEBUG
        fprintf(stderr,"Passed proxy test\n");
#endif
        pvd->proxy_depth++;
        itsaproxy = 1;
    }

    if (!itsaproxy)
    {
                        
#ifdef X509_V_ERR_CERT_REVOKED
        /* 
         * SSLeay 0.9.0 handles CRLs but does not check them. 
         * We will check the crl for this cert, if there
         * is a CRL in the store. 
         * If we find the crl is not valid, we will fail, 
         * as once the sysadmin indicates that CRLs are to 
         * be checked, he best keep it upto date. 
         * 
         * When future versions of SSLeay support this better,
         * we can remove these tests. 
         * we come through this code for each certificate,
         * starting with the CA's We will check for a CRL
         * each time, but only check the signature if the
         * subject name matches, and check for revoked
         * if the issuer name matches.
         * this allows the CA to revoke its own cert as well. 
         */
        
        if (X509_STORE_get_by_subject(ctx,
                                      X509_LU_CRL, 
                                      X509_get_subject_name(ctx->current_cert),
                                      &obj))
        {
            crl =  obj.data.crl;
            crl_info = crl->crl;
#ifdef DEBUG
            {
                BIO * bp;
                bp = BIO_new_fp(stderr,BIO_NOCLOSE);
                                
                fprintf(stderr,"CRL last Update: ");
                ASN1_UTCTIME_print(bp, crl_info->lastUpdate);
                fprintf(stderr,"\nCRL next Update: ");
                ASN1_UTCTIME_print(bp, crl_info->nextUpdate);
                fprintf(stderr,"\n");
                BIO_free(bp);
            }
#endif
            /* verify the signature on this CRL */

            if((tmp_public_key = X509_get_pubkey(ctx->current_cert))
               == NULL)
            {
                X509_OBJECT_free_contents(&obj);
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_SIGNATURE_FAILURE);
                ERR_set_continue_needed();
                ctx->error = X509_V_ERR_CRL_SIGNATURE_FAILURE;
                goto fail_verify;
            }

            i = X509_CRL_verify(crl,tmp_public_key);

            EVP_PKEY_free(tmp_public_key);

            if (i <= 0)
            {
                X509_OBJECT_free_contents(&obj);                
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_SIGNATURE_FAILURE);
                ERR_set_continue_needed();
                ctx->error = X509_V_ERR_CRL_SIGNATURE_FAILURE;
                goto fail_verify;
            }

            /* Check date see if expired */

            i = X509_cmp_current_time(crl_info->nextUpdate);
            if (i == 0)
            {
                X509_OBJECT_free_contents(&obj);
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_NEXT_UPDATE_FIELD);
                ERR_set_continue_needed();                
                ctx->error = X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD;
                goto fail_verify;
            }
           

            if (i < 0)
            {
                X509_OBJECT_free_contents(&obj);
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_HAS_EXPIRED);
                ERR_set_continue_needed();
                ctx->error = X509_V_ERR_CRL_HAS_EXPIRED;
                goto fail_verify;
            }

            X509_OBJECT_free_contents(&obj);
        }

        /* now check if the issuer has a CRL, and we are revoked */

        if (X509_STORE_get_by_subject(ctx, X509_LU_CRL, 
                                      X509_get_issuer_name(ctx->current_cert),
                                      &obj))
        {
            crl = obj.data.crl;
            crl_info = crl->crl;
#ifdef DEBUG
            fprintf(stderr,"Checking  CRL\n");
#endif
            /* check if this cert is revoked */


            n = sk_X509_REVOKED_num(crl_info->revoked);
            for (i=0; i<n; i++)
            {
                revoked = (X509_REVOKED *)sk_X509_REVOKED_value(
                    crl_info->revoked,i);

                if(!ASN1_INTEGER_cmp(revoked->serialNumber,
                                     X509_get_serialNumber(ctx->current_cert)))
                {
                    long serial;
                    char buf[256];
                    PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CERT_REVOKED);
                    serial = ASN1_INTEGER_get(revoked->serialNumber);
                    sprintf(buf,"%ld (0x%lX)",serial,serial);
                    s = X509_NAME_oneline(X509_get_subject_name(
                                              ctx->current_cert),NULL,0);
                    
                    ERR_add_error_data(4,"Serial number = ",buf,
                                       " Subject=",s);

                    ctx->error = X509_V_ERR_CERT_REVOKED;
                    ERR_set_continue_needed();
#ifdef DEBUG
                    fprintf(stderr,"revolked %lX\n",
                            ASN1_INTEGER_get(revoked->serialNumber));
                                                
#endif
                    X509_OBJECT_free_contents(&obj);
                    free(s);
                    s = NULL;
                    goto fail_verify;
                }
            }
            X509_OBJECT_free_contents(&obj);
        }
#endif /* X509_V_ERR_CERT_REVOKED */

        /* Do not need to check self signed certs against ca_policy_file */

        if (X509_NAME_cmp(X509_get_subject_name(ctx->current_cert),
                          X509_get_issuer_name(ctx->current_cert)))
        {
            cert_dir = pvd->pvxd->certdir ? pvd->pvxd->certdir :
                getenv(X509_CERT_DIR);

            ca_policy_file_path =
                get_ca_signing_policy_path(
                    cert_dir,
                    X509_get_issuer_name(ctx->current_cert));
                
            if (ca_policy_file_path == NULL)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_NOPATH);
                ctx->error =  X509_V_ERR_APPLICATION_VERIFICATION; 
                goto fail_verify;
            }

            /*
             * XXX - make sure policy file exists. We get a segfault later
             * if it doesn't.
             */
            if (checkstat(ca_policy_file_path) == 1)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_NOFILE);
                ctx->error = X509_V_ERR_APPLICATION_VERIFICATION;
                ERR_set_continue_needed();
                goto fail_verify;
            }

#ifdef DEBUG
            fprintf(stderr, "ca_policy_file_path is %s\n", ca_policy_file_path);
#endif /* DEBUG */

            {
                char * error_string = NULL;
                char * issuer_name;
                char * subject_name;
#ifndef NO_OLDGAA_API
                oldgaa_rights_ptr            rights          = NULL;
                oldgaa_policy_ptr            policy_handle   = NULL;
                oldgaa_answer_ptr            detailed_answer = NULL;
                oldgaa_sec_context_ptr       oldgaa_sc          = NULL;
                oldgaa_options_ptr           options         = NULL;
                oldgaa_error_code            result;
                oldgaa_data_ptr              policy_db       = OLDGAA_NO_DATA;
                uint32                       minor_status;
#else /* Von's code */
                int result;

#endif /* #ifndef NO_OLDGAA_API */


                subject_name = X509_NAME_oneline(
                    X509_get_subject_name(ctx->current_cert),
                    NULL,
                    0);
                issuer_name = X509_NAME_oneline(
                    X509_get_issuer_name(ctx->current_cert),
                    NULL,
                    0);

#ifndef NO_OLDGAA_API

                globus_mutex_lock(&globus_l_gsi_ssl_utils_mutex);
                
                if(oldgaa_globus_initialize(&oldgaa_sc,
                                            &rights,
                                            &options,
                                            &policy_db,
                                            issuer_name,
                                            subject_name,
                                            ca_policy_file_path  
                       )!= OLDGAA_SUCCESS) 

                {
                    char buf[256];
                    sprintf(buf,"Minor status=%d", policy_db->error_code);
                    PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_POLICY_RETRIEVE);
                    ERR_add_error_data(3,buf,"\n        ",
                                       policy_db->error_str);
                    ctx->error=X509_V_ERR_APPLICATION_VERIFICATION;
                    ERR_set_continue_needed();
                    globus_mutex_unlock(&globus_l_gsi_ssl_utils_mutex);
                    goto fail_verify;
                }


                if(oldgaa_get_object_policy_info(
                       &minor_status,  
                       OLDGAA_NO_DATA,
                       policy_db,
                       oldgaa_globus_policy_retrieve,
                       &policy_handle) != OLDGAA_SUCCESS)
                {
                    char buf[256];
                    sprintf(buf,"Minor status=%d", minor_status);
                    PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_POLICY_PARSE);
                    ERR_add_error_data(3,buf,"\n        ",
                                       policy_db->error_str);
                    ctx->error =  X509_V_ERR_APPLICATION_VERIFICATION;
                    ERR_set_continue_needed(); 
                    globus_mutex_unlock(&globus_l_gsi_ssl_utils_mutex);
                    goto fail_verify;
                }

                result = oldgaa_check_authorization (&minor_status,   
                                                     oldgaa_sc,   
                                                     policy_handle,     
                                                     rights, 
                                                     options,
                                                     &detailed_answer);
                
                if (!detailed_answer)
                {
                    PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_POLICY_ERR);
                    ctx->error = X509_V_ERR_INVALID_PURPOSE; 
                    ERR_set_continue_needed(); 
                    if (subject_name) free(subject_name);
                    if (issuer_name) free(issuer_name);     
                    
                    oldgaa_globus_cleanup(&oldgaa_sc,
                                          &rights,
                                          options,
                                          &detailed_answer,  
                                          policy_db,
                                          NULL);
                    globus_mutex_unlock(&globus_l_gsi_ssl_utils_mutex);
                    goto fail_verify;
                }
#ifdef DEBUG
                fprintf(stderr,
                        "oldgaa result: %d(0 yes, 1 no, -1 maybe)\n",
                        result);
                if(detailed_answer) 
                { 
                    fprintf(stderr, "\nprint detailed answer:\n\n");
#ifndef WIN32
                    if(detailed_answer->rights)
                    {
                        oldgaa_globus_print_rights(detailed_answer->rights);
                    }
#endif
                }
#endif

                if (policy_handle)
                {
                    oldgaa_release_principals(&minor_status, &policy_handle);
                }
                

                oldgaa_globus_cleanup(&oldgaa_sc,
                                      &rights,
                                      options,
                                      &detailed_answer,  
                                      policy_db,
                                      NULL);

                globus_mutex_unlock(&globus_l_gsi_ssl_utils_mutex);
                    
#else /* Von's code */

                result = ca_policy_file_check_signature(issuer_name,
                                                        subject_name,
                                                        &error_string,
                                                        pvd->certdir);

#endif /* #ifndef NO_OLDGAA_API */

                free(subject_name);
                free(issuer_name);

                if (result != 0)
                {
                    PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_POLICY_VIOLATION);

                    ctx->error = X509_V_ERR_INVALID_PURPOSE; 
                                
                    if (error_string != NULL)
                    {
                        /*
                         * Seperate error message returned from policy check
                         * from above error message with colon
                         */
                        
                        ERR_add_error_data(2, ": ", error_string);
                        free(error_string);
                    }
                    ERR_set_continue_needed();
                    goto fail_verify;
                }
                else
                {
                    if (error_string != NULL)
                    {
                        free(error_string);
                    }
                }
            }
        } /* end of do not check self signed certs */
    }

    /*
     * We want to determine the minimum amount of time
     * any certificate in the chain is good till
     * Will be used for lifetime calculations
     */

    goodtill = ASN1_UTCTIME_mktime(X509_get_notAfter(ctx->current_cert));
    if (pvd->pvxd->goodtill == 0 || goodtill < pvd->pvxd->goodtill)
    {
        pvd->pvxd->goodtill = goodtill;
    }
        
    /* We need to make up a cert_chain if we are the server. 
     * The ssl code does not save this as I would expect. 
     * This is used to create a new proxy by delegation. 
     */

    if (pvd->cert_chain == NULL)
    {
        pvd->cert_chain = sk_X509_new_null();
    }
    
    sk_X509_insert(pvd->cert_chain, X509_dup(ctx->current_cert),0);

    pvd->cert_depth++;

    if (ca_policy_file_path != NULL)
    {
        free(ca_policy_file_path);
    }
    
    extensions = ctx->current_cert->cert_info->extensions;

    for (i=0;i<sk_X509_EXTENSION_num(extensions);i++)
    {
        ex = (X509_EXTENSION *) sk_X509_EXTENSION_value(extensions,i);

        if(X509_EXTENSION_get_critical(ex))
        {
            extension_obj = X509_EXTENSION_get_object(ex);

            nid = OBJ_obj2nid(extension_obj);
            
            if(nid != NID_basic_constraints &&
               nid != NID_key_usage &&
               nid != NID_ext_key_usage &&
               nid != NID_netscape_cert_type &&
               nid != NID_subject_key_identifier &&
               nid != NID_authority_key_identifier &&
               nid != OBJ_txt2nid("TRUSTEDGROUP") &&
               nid != OBJ_txt2nid("UNTRUSTEDGROUP"))
            {
                if(pvd->extension_cb)
                {
                    if(!pvd->extension_cb(pvd,ex))
                    {
                        PRXYerr(PRXYERR_F_VERIFY_CB,
                                PRXYERR_R_UNKNOWN_CRIT_EXT);
                        ctx->error = X509_V_ERR_CERT_REJECTED;
                        goto fail_verify;
                    }
                }
                else
                {
                    PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_UNKNOWN_CRIT_EXT);
                    ctx->error = X509_V_ERR_CERT_REJECTED;
                    goto fail_verify;
                }
            }
        }
    }

    /*
     * We ignored any path length restrictions above because
     * OpenSSL was counting proxies against the limit. 
     * If we are on the last cert in the chain, we 
     * know how many are proxies, so we can do the 
     * path length check now. 
     * See x509_vfy.c check_chain_purpose
     * all we do is substract off the proxy_dpeth 
     */

    if(ctx->current_cert == ctx->cert)
    {
        for (i=0; i < sk_X509_num(ctx->chain); i++)
        {
            cert = sk_X509_value(ctx->chain,i);
#ifdef DEBUG
            fprintf(stderr,"pathlen=:i=%d x=%p pl=%d\n",
                    i, cert, cert->ex_pathlen);
#endif
            if (((i - pvd->proxy_depth) > 1) && (cert->ex_pathlen != -1)
                && ((i - pvd->proxy_depth) > (cert->ex_pathlen + 1))
                && (cert->ex_flags & EXFLAG_BCONS)) 
            {
                ctx->current_cert = cert; /* point at failing cert */
                ctx->error = X509_V_ERR_PATH_LENGTH_EXCEEDED;
                goto fail_verify;
            }
        }
    }


#ifdef DEBUG 
    fprintf(stderr,"proxy_verify_callback:returning:%d\n\n", ok);
#endif
        
    return(ok);

fail_verify:

    if (ctx->current_cert)
    {
        char *subject_s = NULL;
        char *issuer_s = NULL;
                
        subject_s = X509_NAME_oneline(
            X509_get_subject_name(ctx->current_cert),NULL,0);
        issuer_s = X509_NAME_oneline(
            X509_get_issuer_name(ctx->current_cert),NULL,0);
        
        switch (ctx->error)
        {
            case X509_V_OK:
            case X509_V_ERR_INVALID_PURPOSE:
            case X509_V_ERR_APPLICATION_VERIFICATION:
                 PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CB_ERROR_MSG);
                 ERR_add_error_data(6, 
                    "\n        File=", 
                    ca_policy_file_path ? ca_policy_file_path : "UNKNOWN",
                    "\n        subject=",
                    subject_s ? subject_s : "UNKNOWN",
                    "\n        issuer =",
                    issuer_s ? issuer_s : "UNKNOWN");
            break;
            case X509_V_ERR_CERT_NOT_YET_VALID:
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            case X509_V_ERR_CERT_HAS_EXPIRED:
                 PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CB_ERROR_MSG);
                 ERR_add_error_data(4, 
                    "\n        subject=",
                    subject_s ? subject_s : "UNKNOWN",
                    "\n        issuer =",
                    issuer_s ? issuer_s : "UNKNOWN");
            break;
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                 PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CA_UNKNOWN);
                    ERR_add_error_data(2, "\n        issuer =",
                    issuer_s ? issuer_s : "UNKNOWN");
            break;

            default:
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CB_CALLED_WITH_ERROR);
                ERR_add_error_data(6,"\n        error =",
                    X509_verify_cert_error_string(ctx->error),
                    "\n        subject=",
                    subject_s ? subject_s : "UNKNOWN",
                    "\n        issuer =",
                    issuer_s ? issuer_s : "UNKNOWN");
        }

        free(subject_s);
        free(issuer_s);
    }
    if (ca_policy_file_path != NULL)
    {
        free(ca_policy_file_path);
    }

    return(0);

}

/**********************************************************************
Function: proxy_verify_cert_chain()

Description:

Parameters:

Returns:
**********************************************************************/

int
proxy_verify_cert_chain(
    X509 *                              ucert,
    STACK_OF(X509) *                    cert_chain,
    proxy_verify_desc *                 pvd)
{
    int                                 i;
    int                                 j;
    int                                 retval = 0;
    X509_STORE *                        cert_store = NULL;
    X509_LOOKUP *                       lookup = NULL;
    X509_STORE_CTX                      csc;
    X509 *                              xcert = NULL;
    X509 *                              scert = NULL;
#ifdef DEBUG
    fprintf(stderr,"proxy_verify_cert_chain\n");
#endif
    scert = ucert;
    cert_store = X509_STORE_new();
    X509_STORE_set_verify_cb_func(cert_store, proxy_verify_callback);
    if (cert_chain != NULL)
    {
        for (i=0;i<sk_X509_num(cert_chain);i++)
        {
            xcert = sk_X509_value(cert_chain,i);
            if (!scert)
            {
                scert = xcert;
            }
            else
            {
#ifdef DEBUG
                {
                    char * s;
                    s = X509_NAME_oneline(X509_get_subject_name(xcert),
                                          NULL,0);
                    fprintf(stderr,"Adding %d %p %s\n",i,xcert,s);
                    free(s);
                }
#endif
                j = X509_STORE_add_cert(cert_store, xcert);
                if (!j)
                {
                    if ((ERR_GET_REASON(ERR_peek_error()) ==
                         X509_R_CERT_ALREADY_IN_HASH_TABLE))
                    {
                        ERR_clear_error();
                        break;
                    }
                    else
                    {
                        /*DEE need errprhere */
                        goto err;
                    }
                }
            }
        }
    }
    if ((lookup = X509_STORE_add_lookup(cert_store,
                                        X509_LOOKUP_hash_dir())))
    {
        X509_LOOKUP_add_dir(lookup,pvd->pvxd->certdir,X509_FILETYPE_PEM);
        X509_STORE_CTX_init(&csc,cert_store,scert,NULL);

#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
        /* override the check_issued with our version */
        csc.check_issued = proxy_check_issued;
#endif
        X509_STORE_CTX_set_ex_data(&csc,
                                   PVD_STORE_EX_DATA_IDX, (void *)pvd);
                 
        if(!X509_verify_cert(&csc))
        {
            goto err;
        }
    } 
    retval = 1;

err:
    return retval;
}
#endif /* NO_PROXY_VERIFY_CALLBACK */

/**********************************************************************
Function: proxy_get_base_name()

Description:
        Given an X509 name, strip off all the /CN=proxy 
        and /CN=limited proxy to get the base nameb

Parameters:

Returns:
**********************************************************************/

int
proxy_get_base_name(
    X509_NAME *                        subject)
{
    X509_NAME_ENTRY *                  ne;
    ASN1_STRING *                      data;

    /* 
     * drop all the /CN=proxy entries 
     */
    for(;;)
    {
        ne = X509_NAME_get_entry(subject,
                                 X509_NAME_entry_count(subject)-1);
        if (!OBJ_cmp(ne->object,OBJ_nid2obj(NID_commonName)))
        {
            data = X509_NAME_ENTRY_get_data(ne);
            if ((data->length == 5 && 
                 !memcmp(data->data,"proxy",5)) ||
                (data->length == 13 && 
                 !memcmp(data->data,"limited proxy",13)) ||
		(data->length == 16 &&
		 !memcmp(data->data,"restricted proxy",16)))
            {
                ne = X509_NAME_delete_entry(subject,
                                            X509_NAME_entry_count(subject)-1);
                X509_NAME_ENTRY_free(ne);
                ne = NULL;
            }
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }

    return 0;
}

/**********************************************************************
Function: proxy_get_filenames()

Description:
    Gets the filenames for the various files used 
    to store the cert, key, cert_dir and proxy.
    
    
    Environment variables to use:
        X509_CERT_DIR   Directory of trusted certificates
                        File names are hash values, see the SSLeay
                        c_hash script. 
        X509_CERT_FILE  File of trusted certifiates
        X509_USER_PROXY File with a proxy certificate, key, and
                        additional certificates to makeup a chain
                        of certificates used to sign the proxy. 
        X509_USER_CERT  User long term certificate.
        X509_USER_KEY   private key for the long term certificate. 

    All of these are assumed to be in PEM form. If there is a 
    X509_USER_PROXY, it will be searched first for the cert and key. 
    If not defined, but a file /tmp/x509up_u<uid> is
    present, it will be used, otherwise the X509_USER_CERT
    and X509_USER_KEY will be used to find the certificate
    and key. If X509_USER_KEY is not defined, it will be assumed
    that the key is is the same file as the certificate.
 
    If windows, look in the registry HKEY_CURRENT_USER for the 
    GSI_REGISTRY_DIR, then look for the x509_user_cert, etc.

    Then try $HOME/.globus/usercert.pem
    and $HOME/.globus/userkey.pem 
        Unless it is being run as root, then look for 
        /etc/grid-security/hostcert.pem and /etc/grid-security/hostkey.pem

    X509_CERT_DIR and X509_CERT_FILE can point to world readable
    shared director and file. One of these must be present.
    if not use $HOME/.globus/certificates
        or /etc/grid-security/certificates
        or $GLOBUS_LOCATION/share/certificates

    The file with the key must be owned by the user,
    and readable only by the user. This could be the X509_USER_PROXY,
    X509_USER_CERT or the X509_USER_KEY

    X509_USER_PROXY_FILE is used to generate the default
    proxy file name.

    In other words:

    proxy_get_filenames() is used by grid-proxy-init, wgpi, grid-proxy-info and
    Indirectly by gss_acquire_creds. For grid-proxy-init and wgpi, the proxy_in
    is 0, for acquire_creds its 1. This is used to signal how the proxy file is
    to be used, 1 for input 0 for output.
        
    The logic for output is to use the provided input parameter, registry,
    environment, or default name for the proxy. Wgpi calls this multiple times
    as the options window is updated. The file will be created if needed.
        
    The logic for input is to use the provided input parameter, registry,
    environment variable. But only use the default file if it exists, is owned
    by the user, and has something in it. But not when run as root.
        
    Then on input if there is a proxy, the user_cert and user_key are set to
    use the proxy.

    Smart card support using PKCS#11 is controled by the USE_PKCS11 flag.

    If the filename for the user key starts with SC: then it is assumed to be
    of the form SC:card:label where card is the name of a smart card, and label
    is the label of the key on the card. The card must be using Cryptoki
    (PKCS#11) This code has been developed using the DataKey implementation
    under Windows 95.

    This will allow the cert to have the same form, with the same label as well
    in the future.  



Parameters:

Returns:
**********************************************************************/

int
proxy_get_filenames(
    proxy_cred_desc *                   pcd,
    int                                 proxy_in,
    char **                             p_cert_file,
    char **                             p_cert_dir,
    char **                             p_user_proxy,
    char **                             p_user_cert,
    char **                             p_user_key)
{

    int                                 status = -1;
    int                                 len;
    char *                              cert_file = NULL;
    char *                              cert_dir = NULL;
    char *                              user_proxy = NULL;
    char *                              user_cert = NULL;
    char *                              user_key = NULL;
    char *                              home = NULL;
    char *                              default_user_proxy = NULL;
    char *                              default_user_cert = NULL;
    char *                              default_user_key = NULL;
    char *                              default_cert_dir = NULL;
    char *                              installed_cert_dir = NULL;
#ifdef WIN32
    HKEY                                hkDir = NULL;
    char                                val_user_cert[512];
    char                                val_user_key[512];
    char                                val_user_proxy[512];
    char                                val_cert_dir[512];
    char                                val_cert_file[512];
    LONG                                lval;
    DWORD                               type;
#endif

#ifdef WIN32
    RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
#endif
    
    /* setup some default values */
    if (pcd) 
    {
        pcd->owner = CRED_OWNER_USER;
        pcd->type = CRED_TYPE_PERMANENT;
    }

    if (p_cert_dir)
    {
        cert_dir = *p_cert_dir;
    }


    if (!cert_dir)
    {
        cert_dir = (char *)getenv(X509_CERT_DIR);
    }
#ifdef WIN32
    if (!cert_dir)
    {
        lval = sizeof(val_cert_dir)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_cert_dir",0,&type,
                                      val_cert_dir,&lval) == ERROR_SUCCESS))
        {
            cert_dir = val_cert_dir;
        }
    }
#endif
    if (p_cert_file)
    {
        cert_file = *p_cert_file;
    }
    
    if (!cert_file)
    {
        cert_file = (char *)getenv(X509_CERT_FILE);
    }
#ifdef WIN32
    if (!cert_file)
    {
        lval = sizeof(val_cert_file)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_cert_file",0,&type,
                                      val_cert_file,&lval) == ERROR_SUCCESS))
        {
            cert_file = val_cert_file;
        }
    }
#endif
        
    if (cert_dir == NULL)
    {

        /*
         * If ~/.globus/certificates exists, then use that
         */
        home = getenv("HOME");
#ifdef WIN32
        /* Under windows use c:\windows as default home */
        if (!home)
        {
            home = "c:\\windows";
        }
#endif /* WIN32 */

        if (home) 
        {
            len = strlen(home) + strlen(X509_DEFAULT_CERT_DIR) + 2;
            default_cert_dir = (char *)malloc(len);
            if (!default_cert_dir)
            {
                PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                goto err;
            }
            sprintf(default_cert_dir, "%s%s%s",
                    home, FILE_SEPERATOR, X509_DEFAULT_CERT_DIR);

            if (checkstat(default_cert_dir) != 1)
            {
                /* default_cert_dir exists */
                cert_dir = default_cert_dir;
#ifdef DEBUG
                fprintf(stderr,
                        "Using user's personal certdir %s\n",
                        cert_dir);
#endif /* DEBUG */
            }
        }
                

        /* 
         * Now check for host based default directory
         */
        if (!cert_dir)
        {

            if (checkstat(X509_INSTALLED_HOST_CERT_DIR) != 1)
            {
                /* default_cert_dir exists */
                cert_dir = X509_INSTALLED_HOST_CERT_DIR;
#ifdef DEBUG
                fprintf(stderr,
                        "Using host's default certdir %s\n",
                        cert_dir);
#endif /* DEBUG */
            }
        }

        if (!cert_dir)
        {
            /*
             * ...else look for (in order)
             * $GLOBUS_LOCATION/share/certficates
             */
            char *globus_location;

            globus_location = getenv("GLOBUS_LOCATION");

            if (globus_location)
            {
#ifdef DEBUG
                fprintf(stderr,
                        "Checking for certdir in Globus path (%s)\n",
                        globus_location);
#endif /* DEBUG */

                len = strlen(globus_location) +
                    strlen(X509_INSTALLED_CERT_DIR)
                    + 2 /* NUL and FILE_SEPERATOR */;

                installed_cert_dir = (char *) malloc(len);
                if  (!installed_cert_dir)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }
                sprintf(installed_cert_dir,
                        "%s%s%s",
                        globus_location,
                        FILE_SEPERATOR,
                        X509_INSTALLED_CERT_DIR);

                /*
                 * Previous code always set cert_dir to
                 * default_cert_dir without checking for its
                 * existance, so we'll also skip the existance
                 * check here.
                 */
                cert_dir = installed_cert_dir;
            }
        }

        if (!cert_dir)
        {
            cert_dir = X509_INSTALLED_HOST_CERT_DIR;
        }
    }

#ifdef DEBUG
    fprintf(stderr, "Using cert_dir = %s\n",
            (cert_dir ? cert_dir : "null"));
#endif /* DEBUG */

    if (cert_dir)
    {
        if (checkstat(cert_dir)  == 1)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERTS); 
            ERR_add_error_data(2,"x509_cert_dir=",cert_dir);
            goto err;
        }
    }

    if (cert_file)
    {
        if (checkstat(cert_file)  == 1)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERTS); 
            ERR_add_error_data(2,"x509_cert_file=",cert_file);
            goto err;
        }
    }
    /* if X509_USER_PROXY is defined, use it for cert and key,
     * and for additional certs. 
     * if not, and the default user_proxy file is present, 
     * use it. 
     * If not, get the X509_USER_CERT and X509_USER_KEY
     * if not, use ~/.globus/usercert.pem ~/.globus/userkey.pem
     */
    if (p_user_proxy)
    {
        user_proxy = *p_user_proxy;
    }
    
    if (!user_proxy)
    {
        user_proxy = (char *)getenv(X509_USER_PROXY);
    }
#ifdef WIN32
    if (!user_proxy)
    {
        lval = sizeof(val_user_proxy)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_user_proxy",0,&type,
                                      val_user_proxy,&lval) == ERROR_SUCCESS))
        {
            user_proxy = val_user_proxy;
        }
    }
#endif
    if (!user_proxy && !getenv("X509_RUN_AS_SERVER"))
    {
        unsigned long uid;
        uid = getuid();
        len = strlen(DEFAULT_SECURE_TMP_DIR) 
            + strlen(X509_USER_PROXY_FILE) 
            + 64; 
       
        default_user_proxy = (char *) malloc(len);
        if (!default_user_proxy)
        {
            PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
            goto err;
        }
        sprintf(default_user_proxy,"%s%s%s%lu",
                DEFAULT_SECURE_TMP_DIR,
                FILE_SEPERATOR,
                X509_USER_PROXY_FILE,
                uid);

#ifndef WIN32
        if ((!proxy_in || getuid() != 0)
            && checkstat(default_user_proxy) == 0) 
#endif
        {
            user_proxy = default_user_proxy;
        }
    }
    if (proxy_in && user_proxy)
    {
        user_cert = user_proxy;
        user_key = user_proxy;
        if (pcd) pcd->type = CRED_TYPE_PROXY;
    }
    else
    {
        if (!user_proxy && !proxy_in)
        {
            user_proxy = default_user_proxy;
        }

        if (p_user_cert)
        {
            user_cert = *p_user_cert;
        }

        if(!user_cert)
        {
            user_cert = (char *)getenv(X509_USER_CERT);
        }

#ifdef WIN32
        if (!user_cert)
        {
            lval = sizeof(val_user_cert)-1;
            if (hkDir && (RegQueryValueEx(
                              hkDir,
                              "x509_user_cert",
                              0,
                              &type,
                              val_user_cert,&lval) == ERROR_SUCCESS))
            {
                user_cert = val_user_cert;
            }
        }
#endif
        if (user_cert)
        {
            if (p_user_key)
            {
                user_key = *p_user_key;
            }
            if (!user_key)
            {
                user_key = (char *)getenv(X509_USER_KEY);
            }
#ifdef WIN32
            if (!user_key)
            {
                lval = sizeof(val_user_key)-1;
                if (hkDir && (RegQueryValueEx(
                                  hkDir,
                                  "x509_user_key",
                                  0,
                                  &type,
                                  val_user_key,&lval) == ERROR_SUCCESS))
                {
                    user_key = val_user_key;
                }
            }
#endif
            if (!user_key)
            {
                user_key = user_cert;
            }
        }
        else
        {
#ifndef WIN32
            if (getuid() == 0)
            {
                if (checkstat(X509_DEFAULT_HOST_CERT) != 1)
                {
                    if (pcd) pcd->owner=CRED_OWNER_SERVER;
                    user_cert = X509_DEFAULT_HOST_CERT;
                }
                if (checkstat(X509_DEFAULT_HOST_KEY) != 1)
                {
                    if (pcd) pcd->owner=CRED_OWNER_SERVER;
                    user_key = X509_DEFAULT_HOST_KEY;
                }
            }
            else 
#endif
            {
                if (!home)
                {
                    home = getenv("HOME");
                }
                if (!home)
                {
#ifndef WIN32
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_NO_HOME);
                    goto err;
#else
                    home = "c:\\";
#endif
                }
                
                len = strlen(home) + strlen(X509_DEFAULT_USER_CERT) + 2;
                default_user_cert = (char *)malloc(len);

                if (!default_user_cert)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                } 

                sprintf(default_user_cert,"%s%s%s",
                        home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT);
                len = strlen(home) + strlen(X509_DEFAULT_USER_KEY) + 2;
                default_user_key = (char *)malloc(len);
                if (!default_user_key)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }
                sprintf(default_user_key, "%s%s%s",
                        home,FILE_SEPERATOR, X509_DEFAULT_USER_KEY);
                                                
                user_cert = default_user_cert;
                user_key = default_user_key;

                if(checkcert(user_cert) ||
                   checkstat(user_key))
                {
                    len = strlen(home) + strlen(X509_DEFAULT_PKCS12_FILE) + 2;
                    default_user_cert = (char *)realloc(default_user_cert,len);

                    if (!default_user_cert)
                    {
                        PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                        goto err;
                    } 

                    sprintf(default_user_cert,"%s%s%s",
                            home, FILE_SEPERATOR, X509_DEFAULT_PKCS12_FILE);
                    len = strlen(home) + strlen(X509_DEFAULT_PKCS12_FILE) + 2;
                    default_user_key = (char *) realloc(default_user_key,len);
                    if (!default_user_key)
                    {
                        PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                        goto err;
                    }
                    sprintf(default_user_key, "%s%s%s",
                            home,FILE_SEPERATOR, X509_DEFAULT_PKCS12_FILE);
                                                
                    user_cert = default_user_cert;
                    user_key = default_user_key;

                }
            }
        }
    }

 
#ifdef DEBUG
    fprintf(stderr,"Using x509_user_cert=%s\n      x509_user_key =%s\n",
            user_cert, user_key);
#endif
    status = 0;
err:
    if (p_cert_file && cert_file)
    {
        *p_cert_file = strdup(cert_file);
    }
    if (p_cert_dir && cert_dir)
    {
        *p_cert_dir = strdup(cert_dir);
    }
    if (p_user_proxy && user_proxy)
    {
        *p_user_proxy = strdup(user_proxy);
    }
    if (p_user_cert && user_cert)
    {
        *p_user_cert = strdup(user_cert);
    }
    if (p_user_key && user_key)
    {
        *p_user_key = strdup(user_key);
    }
        
#ifdef WIN32
    if (hkDir)
    {
        RegCloseKey(hkDir);
    }
#endif

    if (default_user_proxy)
    {
        free(default_user_proxy);
    }

    if (installed_cert_dir)
    {
        free(installed_cert_dir);
    }

    if (default_cert_dir)
    {
        free(default_cert_dir);
    }

    if (default_user_cert)
    {
        free(default_user_cert);
    }

    if (default_user_key)
    {
        free(default_user_key);
    }

    return status;
}
/**********************************************************************
Function: proxy_load_user_cert()

Description:
    loads the users cert. May need a pw callback for Smartcard PIN. 
    May use a smartcard too.   

Parameters:

Returns:
**********************************************************************/

int
proxy_load_user_cert(
    proxy_cred_desc *                   pcd, 
    const char *                        user_cert,
    int                                 (*pw_cb)(),
    BIO *                               bp)
{
    int                                 status = -1;
    FILE *                              fp;
    int                                 (*xpw_cb)();

    xpw_cb = pw_cb;
#ifdef WIN32
    if (!xpw_cb)
    {
        xpw_cb = read_passphrase_win32;
    }
#endif

#ifdef DEBUG
    fprintf(stderr,"proxy_load_user_cert\n");
#endif
    /* Check arguments */
    if (!bp && !user_cert)
    {
        if (pcd->owner==CRED_OWNER_SERVER)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE);
            status = PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE;
        }
        else
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
            status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
        }
        
        ERR_add_error_data(1, "\n        No certificate file found");
        goto err;   
    }

    if (!bp && !strncmp(user_cert,"SC:",3))
    {
#ifdef USE_PKCS11
        char * cp;
        char * kp;
        int rc;

        cp = user_cert + 3;
        kp = strchr(cp,':');
        if (kp == NULL)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
            ERR_add_error_data(2, "\n        SmartCard reference=",
                               user_cert);
            status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
            goto err;
        }
        kp++; /* skip the : */
        if (pcd->hSession == 0)
        {
            rc = sc_init(&(pcd->hSession), cp, NULL, NULL, CKU_USER, 0);
            if (rc)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
                ERR_add_error_data(
                    1,
                    "\n        Failed to open session to smartcard");
                status = PRXYERR_R_PROCESS_CERT;
                goto err;
            }
        }
        rc = sc_get_cert_obj_by_label(pcd->hSession,kp,
                                      &(pcd->ucert));
        if (rc)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
            ERR_add_error_data(
                2,
                "\n        Could not find certificate on smartcard, label=",
                kp);
            status = PRXYERR_R_PROCESS_CERT;
            goto err;
        }
#else
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
        ERR_add_error_data(
            1,
            "\n       Smartcard support not compiled with this program");
        status = PRXYERR_R_PROCESS_CERT;
        goto err;

        /*
         * DEE? need to add a random number routine here, to use
         * the random number generator on the card
         */ 

#endif /* USE_PKCS11 */
    }
    else
    {
        if (bp)
        {
            if (PEM_read_bio_X509(bp,&(pcd->ucert),
                                  OPENSSL_PEM_CB(NULL,NULL)) == NULL)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
                status = PRXYERR_R_PROCESS_CERT;
                goto err;

            }
        }
        else
        {

            if((fp = fopen(user_cert,"r")) == NULL)
            {
                if (pcd->type == CRED_TYPE_PROXY && pcd->owner == CRED_OWNER_USER)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_NO_PROXY);
                    ERR_add_error_data(2, "\n        Proxy File=", user_cert);
                    status = PRXYERR_R_NO_PROXY;
                }
                else
                {
                    if (pcd->owner==CRED_OWNER_SERVER)
                    {
                        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE);
                        status = PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE;
                    }
                    else
                    {
                        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
                        status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
                    }
                    
                    ERR_add_error_data(2, "\n        Cert File=", user_cert);
                }
                goto err;
            }

            if (PEM_read_X509(fp,
                              &(pcd->ucert),
                              OPENSSL_PEM_CB(NULL,NULL)) == NULL)
            {
               if (ERR_peek_error() == ERR_PACK(ERR_LIB_PEM,PEM_F_PEM_READ_BIO,PEM_R_NO_START_LINE))
                {
                    ERR_clear_error();
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_INVALID_CERT);
                    status = PRXYERR_R_INVALID_CERT;
                } 
                else
                { 
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
                    status = PRXYERR_R_PROCESS_CERT;
                }
                    ERR_add_error_data(2, "\n        File=", user_cert);
                    fclose(fp);
                    goto err;
                
            }
            fclose(fp);
        }
    }
    status = 0;
err:

    return status;
}


/**********************************************************************
Function: proxy_load_user_key()

Description:
    loads the users key. Assumes the cert has been loaded,
    and checks they match. 
    May use a smartcard too.   

Parameters:

Returns:
    an int specifying the error
**********************************************************************/

int
proxy_load_user_key(
    proxy_cred_desc *                   pcd, 
    const char *                        user_key,
    int                                 (*pw_cb)(),
    BIO *                               bp)
{
    unsigned long                       error;
    int                                 mismatch = 0;
    int                                 status = -1;
    FILE *                              fp;
    EVP_PKEY *                          ucertpkey = NULL;
    int                                 (*xpw_cb)();

    xpw_cb = pw_cb;
#ifdef WIN32
    if (!xpw_cb)
    {
        xpw_cb = read_passphrase_win32;
    }
#endif

#ifdef DEBUG
    fprintf(stderr,"proxy_load_user_key\n");
#endif

    /* Check arguments */
    if (!bp && !user_key)
    {
        if (pcd->owner==CRED_OWNER_SERVER)
        {
            PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_PROBLEM_SERVER_NOKEY_FILE);
            status = PRXYERR_R_PROBLEM_SERVER_NOKEY_FILE;
        }
        else
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOKEY_FILE);
            status = PRXYERR_R_PROBLEM_USER_NOKEY_FILE;
        }

        ERR_add_error_data(1,"\n        No key file found");
        goto err;   
    }

            
    if (!bp && !strncmp(user_key,"SC:",3))
    {
#ifdef USE_PKCS11
        char *cp;
        char *kp;
        int rc;

        cp = user_key + 3;
        kp = strchr(cp,':');
        if (kp == NULL)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_KEY_FILE);
            ERR_add_error_data(2,"\n        SmartCard reference=",user_key);
            status = PRXYERR_R_PROBLEM_KEY_FILE;
            goto err;
        }
        kp++; /* skip the : */
        if (pcd->hSession == 0)
        {
            rc = sc_init(&(pcd->hSession), cp, NULL, NULL, CKU_USER, 0);
            if (rc)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
                ERR_add_error_data(
                    1,
                    "\n        Failed to open session to smartcard");
                status = PRXYERR_R_PROCESS_KEY;
                goto err;
            }
        }
        rc = sc_get_priv_key_obj_by_label(pcd->hSession,kp,
                                          &(pcd->upkey));
        if (rc)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
            ERR_add_error_data(
                2,
                "\n        Could not find key on smartcard, label=",
                kp);
            status = PRXYERR_R_PROCESS_KEY;
            goto err;
        }
#else
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
        ERR_add_error_data(
            1,
            "\n       Smartcard support not compiled with this program");
        status = PRXYERR_R_PROCESS_KEY;
        goto err;
        
        /*
         * DEE? could add a random number routine here, to use
         * the random number generator on the card
         */ 

#endif /* USE_PKCS11 */
    }
    else
    {
        if (bp)
        {
            if (PEM_read_bio_PrivateKey(bp,&(pcd->upkey),
                                        OPENSSL_PEM_CB(xpw_cb,NULL)) == NULL)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
                status = PRXYERR_R_PROCESS_KEY;
                goto err;
            }
        }
        else
        {
            int keystatus;
            if ((fp = fopen(user_key,"r")) == NULL)
            {
                if (pcd->owner==CRED_OWNER_SERVER)
                {    
                     PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_SERVER_NOKEY_FILE);
                     status = PRXYERR_R_PROBLEM_SERVER_NOKEY_FILE;
                }
                else
                {
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOKEY_FILE);
                    status = PRXYERR_R_PROBLEM_USER_NOKEY_FILE;
                }

                ERR_add_error_data(2, "\n        File=",user_key);
                goto err;
            }

            /* user key must be owned by the user, and readable
             * only be the user
             */

            if (keystatus = checkstat(user_key))
            {
                if (keystatus == 4)
                {
                    if (pcd && pcd->owner==CRED_OWNER_SERVER)
                    {                    
                        status = PRXYERR_R_SERVER_ZERO_LENGTH_KEY_FILE;
                        PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_SERVER_ZERO_LENGTH_KEY_FILE);
                    }
                    else
                    {
                         status = PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE;
                         PRXYerr(PRXYERR_F_INIT_CRED,
                                 PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE);
                    }
                }
                else
                {
                    status = PRXYERR_R_PROBLEM_KEY_FILE;
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_KEY_FILE);
                }

                ERR_add_error_data(2, "\n        File=", user_key);
                fclose(fp);
                goto err;
            }

            if (PEM_read_PrivateKey(fp,
                                    &(pcd->upkey),
                                    OPENSSL_PEM_CB(xpw_cb,NULL)) == NULL)
            {
                fclose(fp);
                error = ERR_peek_error();
                if (error == ERR_PACK(ERR_LIB_PEM,
                                      PEM_F_DEF_CALLBACK,
                                      PEM_R_PROBLEMS_GETTING_PASSWORD))
                {
                    ERR_clear_error(); 
                }
                else if (error == ERR_PACK(ERR_LIB_EVP,
                                           EVP_F_EVP_DECRYPTFINAL,
                                           EVP_R_BAD_DECRYPT))
                {
                    ERR_clear_error();
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_WRONG_PASSPHRASE);
                    status = PRXYERR_R_WRONG_PASSPHRASE;
                }
                else
                {
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
                    ERR_add_error_data(2, "\n        File=", user_key);
                    status = PRXYERR_R_PROCESS_KEY;
                }
                goto err;
            }
            fclose(fp);
        }
    }

    /* 
     * check that the private key matches the certificate
     * Dont want a mixup of keys and certs
     * Will only check rsa type for now. 
     */
    if (pcd->ucert)
    {
        ucertpkey =  X509_PUBKEY_get(X509_get_X509_PUBKEY(pcd->ucert));
        if (ucertpkey!= NULL  && ucertpkey->type == pcd->upkey->type)
        {
            if (ucertpkey->type == EVP_PKEY_RSA)
            {
                /* add in key as random data too */
                if (ucertpkey->pkey.rsa != NULL)
                {
                    if(ucertpkey->pkey.rsa->p != NULL)
                    {
                        RAND_add((void*)ucertpkey->pkey.rsa->p->d,
                                 BN_num_bytes(ucertpkey->pkey.rsa->p),
                                 BN_num_bytes(ucertpkey->pkey.rsa->p));
                    }
                    if(ucertpkey->pkey.rsa->q != NULL)
                    {
                        RAND_add((void*)ucertpkey->pkey.rsa->q->d,
                                 BN_num_bytes(ucertpkey->pkey.rsa->q),
                                 BN_num_bytes(ucertpkey->pkey.rsa->q));
                    }
                }
                if ((ucertpkey->pkey.rsa != NULL) && 
                    (ucertpkey->pkey.rsa->n != NULL) &&
                    (pcd->upkey->pkey.rsa != NULL) )
                {
                    if (pcd->upkey->pkey.rsa->n != NULL
                        && BN_num_bytes(pcd->upkey->pkey.rsa->n))
                    {
                        if (BN_cmp(ucertpkey->pkey.rsa->n,
                                   pcd->upkey->pkey.rsa->n))
                        {
                            mismatch=1;
                        }
                    }
                    else
                    {
                        pcd->upkey->pkey.rsa->n =
                            BN_dup(ucertpkey->pkey.rsa->n);
                        pcd->upkey->pkey.rsa->e =
                            BN_dup(ucertpkey->pkey.rsa->e);
#ifdef DEBUG2
                        fprintf(stderr,"LITRONIC HACK- copying modulus and exponent\n");
#endif
                    }
                }
            }
        }
        else
        {
            mismatch=1;
        }

        if(ucertpkey != NULL)
        {
            EVP_PKEY_free(ucertpkey);
        }
        
        if (mismatch)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_KEY_CERT_MISMATCH);
            status = PRXYERR_R_KEY_CERT_MISMATCH;
            goto err;
        }
    }

    status = 0;

err:
    /* DEE need more cleanup */
    return status;

}

/**********************************************************************
Function: proxy_init_cred()

Description:
    Gets the local credentials. Here is establishes the SSL context
    and set the cert, and key files and directories from the
    environment.
    
Parameters:

Returns:
**********************************************************************/

int
proxy_init_cred(
    proxy_cred_desc *                   pcd,
    int                                 (*pw_cb)(),
    BIO *                               bp)
{
        
    int                                 status = -1;
    int                                 len;
    int                                 i;
    int                                 j;
    char *                              cert_file = NULL;
    char *                              cert_dir = NULL;
    char *                              user_proxy = NULL;
    char *                              user_cert = NULL;
    char *                              user_key = NULL;
    char *                              fname = NULL;
    X509_STORE_CTX                      csc;
#ifndef WIN32
    DIR *                               dirp = NULL;
    struct dirent *                     direntp;
#endif
    FILE *                              fp = NULL;
    X509 *                              ccert = NULL;
    X509 *                              xcert = NULL;

#if 0
    pcd->gs_ctx = NULL;
    pcd->ucert = NULL;
    pcd->upkey = NULL;
    pcd->cert_chain = NULL;
    pcd->hSession = 0;
    pcd->hPrivKey = 0;
#endif

    if (proxy_get_filenames(pcd,
                            1,
                            &cert_file,
                            &cert_dir,
                            (pcd->ucert||pcd->upkey)? NULL : &user_proxy,
                            pcd->ucert? NULL : &user_cert,
                            pcd->upkey? NULL : &user_key))
    {
        goto err;
    }

    if (cert_dir)
    {
        pcd->certdir = strdup(cert_dir);
    }

    if (cert_file)
    {
        pcd->certfile = strdup(cert_file);
    }

    SSLeay_add_ssl_algorithms();
    pcd->gs_ctx = SSL_CTX_new(SSLv3_method());
    if(pcd->gs_ctx == NULL)
    {
        goto err;
    }

    SSL_CTX_set_cert_verify_callback(pcd->gs_ctx, 
                                     proxy_app_verify_callback,
                                     NULL);

    /* set a small limit on ssl session-id reuse */

    SSL_CTX_sess_set_cache_size(pcd->gs_ctx,5);

    if (!SSL_CTX_load_verify_locations(pcd->gs_ctx,
                                       cert_file,
                                       cert_dir))
    {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERTS);
        ERR_add_error_data(4, "\n        x509_cert_file=", 
                           (cert_file) ? cert_file: "NONE" ,
                           "\n        x509_cert_dir=",
                           (cert_dir) ? cert_dir : "NONE");
        status = PRXYERR_R_PROCESS_CERTS;       
        goto err;
    }

    /* Set the verify callback to test our proxy 
     * policies. 
     * The SSL_set_verify does not appear to work as 
     * expected. The SSL_CTX_set_verify does more,
     * it also sets the X509_STORE_set_verify_cb_func
     * which is what we want. This occurs in both 
     * SSLeay 0.8.1 and 0.9.0 
     */

    SSL_CTX_set_verify(pcd->gs_ctx,SSL_VERIFY_PEER,
                       proxy_verify_callback);

    /*
     * for now we will accept any purpose, as Globus does
     * nor have any restrictions such as this is an SSL client
     * or SSL server. Globus certificates are not required
     * to have these fields set today.
     * DEE - Need  to look at this in future if we use 
     * certificate extensions...  
     */
    SSL_CTX_set_purpose(pcd->gs_ctx,X509_PURPOSE_ANY);

    /*
     * Need to load the cert_file and/or the CA certificates
     * to get the client_CA_list. This is really only needed
     * on the server side, but will do it on both for now. 
     * Some Java implementations insist on having this. 
     */

    if (cert_file)
    {
        SSL_CTX_set_client_CA_list(pcd->gs_ctx,
                                   SSL_load_client_CA_file(cert_file));
        if (!SSL_CTX_get_client_CA_list(pcd->gs_ctx))
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_CLIENT_CA);
            ERR_add_error_data(2,"\n        File=", cert_file);
            status = PRXYERR_R_PROBLEM_CLIENT_CA;
            goto err;
        }
    }
        
#ifdef NO_OLDGAA_API
    /* 
     * DEE-Get a list of all the CAs from the ca-signing-policy.conf
     * Problem with this method is that the names are in the 
     * "X509_NAME_oneline" format, and not X509_NAME, as we realy 
     * need the DER encoding of the name. 
     * DEE-Will add later if needed.
     */
                                                                          
#endif
    /*
     * So go through the cert_dir looking for certificates
     * then verify that they are in the ca-signing-policy 
     * as well. 
     */ 

#ifndef WIN32
    if ((dirp = opendir(cert_dir)) != NULL)
    {
#ifdef DEBUG
        fprintf(stderr,"looking for CA certs\n");
#endif
        while ( (direntp = readdir( dirp )) != NULL )
        {
            /* look for hashed file names hhhhhhhh.n */
            len = strlen(direntp->d_name);
            if ((len >= 10)
                && (*(direntp->d_name + 8) == '.')
                && (strspn(direntp->d_name, 
                           "0123456789abcdefABCDEF") == 8)
                && (strspn((direntp->d_name + 9),
                           "0123456789") == (len - 9)))
            {
                fname = (char *)malloc(strlen(cert_dir) + 
                                       strlen(direntp->d_name) + 2);
                if (!fname)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    status = PRXYERR_R_OUT_OF_MEMORY;
                    goto err;
                }
                sprintf(fname,"%s%s%s", cert_dir,
                        FILE_SEPERATOR,
                        direntp->d_name);

#ifdef DEBUG
                fprintf(stderr,"CA cert=%s\n",fname);
#endif
                if ((fp = fopen(fname,"r")) == NULL)
                {
                    if (pcd->owner==CRED_OWNER_SERVER)
                    {
                       PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE);
                       status = PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE;
                    }
                    else
                    {
                       PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
                       status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
                    }
                    
                    ERR_add_error_data(2, "\n        File=", fname);
                    goto err;
                }

                if (PEM_read_X509(fp,&ccert,OPENSSL_PEM_CB(NULL,NULL)) == NULL)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
                    ERR_add_error_data(2, "\n        File=", fname);
                    status = PRXYERR_R_PROCESS_CERT;
                    goto err;
                }

                free(fname);
                fname = NULL;
                fclose(fp);
                fp = NULL;
                SSL_CTX_add_client_CA(pcd->gs_ctx, ccert);
                X509_free(ccert);
                ccert = NULL;
            }
        }
    }
#endif /* WIN32 */

    if (!pcd->ucert)
    {
        if (status = proxy_load_user_cert(pcd, user_cert,
                                 pw_cb, bp))
        {
            goto err;
        }
        
        if (proxy_check_proxy_name(pcd->ucert)>0)
        {
            pcd->type = CRED_TYPE_PROXY;
        }
        else
        {
            pcd->type = CRED_TYPE_PERMANENT;
        }
    }
    else
    {
        pcd->type = CRED_TYPE_PERMANENT;
    }

    if (!pcd->upkey)
    {
        if (status = proxy_load_user_key(pcd, user_key,
                                pw_cb, bp))
        {
            goto err;
        }
    }
                        
    if (!SSL_CTX_use_certificate(pcd->gs_ctx,pcd->ucert))
    {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
        ERR_add_error_data(2,"\n        File=", user_cert);
        status = PRXYERR_R_PROCESS_CERT;
        goto err;
    }
    /* test if the cert is still valid */
    if (X509_cmp_current_time(X509_get_notAfter(pcd->ucert)) <= 0)
    {
        if (pcd->type==CRED_TYPE_PROXY)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROXY_EXPIRED);
            status = PRXYERR_R_PROXY_EXPIRED; 
        }
        else if (pcd->type==CRED_OWNER_SERVER)
        {
                        
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_SERVER_CERT_EXPIRED);
            status = PRXYERR_R_SERVER_CERT_EXPIRED; 
        }
        else 
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_USER_CERT_EXPIRED);
            status = PRXYERR_R_USER_CERT_EXPIRED; 
        }

        ERR_add_error_data(2,"\n        File=", user_cert);
        goto err;
    }

    if (!SSL_CTX_use_PrivateKey(pcd->gs_ctx, pcd->upkey))
    {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
        ERR_add_error_data(2, "\n        File=", user_key);
        status = PRXYERR_R_PROCESS_KEY;
        goto err;
    }

    /* if using the user_proxy file, then there may be more certs
     * we should read in. These are trusted only by the user,
     * and are part of the certificarte chain.
     *DEE? need to look at this closer.
     */


    if (bp || user_proxy)
    {
        if (pcd->cert_chain == NULL)
        {
            pcd->cert_chain = sk_X509_new_null();
        }
        
        if (proxy_load_user_proxy(pcd->cert_chain,
                                  user_proxy, bp) < 0)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_PROXY);
            if (user_proxy)
            { 
                ERR_add_error_data(2,"\n        x509_user_proxy=", user_proxy);
            }
            status = PRXYERR_R_PROCESS_PROXY;
            goto err;
        }
    }
    if (pcd->cert_chain)
    {
        for (i=0;i<sk_X509_num(pcd->cert_chain);i++)
        {
            xcert = sk_X509_value(pcd->cert_chain,i);

#ifdef DEBUG
            {
                char * s;
                s=X509_NAME_oneline(X509_get_subject_name(xcert),NULL,0);
                fprintf(stderr,"Adding to X509_STORE %d %p %s\n",i,xcert,s);
                free(s);
            }
#endif
            j = X509_STORE_add_cert(pcd->gs_ctx->cert_store,xcert);
            if (!j)
            {
                if ((ERR_GET_REASON(ERR_peek_error()) ==
                     X509_R_CERT_ALREADY_IN_HASH_TABLE))
                {
                    ERR_clear_error();
                    break;
                }
                else
                {
                    goto err;
                }
            }
        }
    }

    status = 0;
err:
    if (fname)
    {
        free(fname);
    }
    if (fp)
    {
        fclose(fp);
    }
#ifndef WIN32
    if (dirp)
    {
        closedir(dirp);
    }
#endif
    if(cert_file)
    {
        free(cert_file);
    }
    if(cert_dir)
    {
        free(cert_dir);
    }
    if(user_proxy)
    {
        free(user_proxy);
    }
    if(user_cert)
    {
        free(user_cert);
    }
    if(user_key)
    {
        free(user_key);
    }
    return status;

}

/**********************************************************************
Function: proxy_cred_desc_free()

Description:
        free the proxy_cred_desc and its contents 
        X509_certs etc. 

Parameters:

Returns:
**********************************************************************/

int
proxy_cred_desc_free(
    proxy_cred_desc *                   pcd)
{
    if (pcd)
    {
        if (pcd->ucert != NULL)
        {
            X509_free(pcd->ucert);
            pcd->ucert = NULL;
        }

        if (pcd->upkey != NULL)
        {
            EVP_PKEY_free(pcd->upkey);
            pcd->upkey = NULL;
        }

        if (pcd->cert_chain != NULL)
        {
            sk_X509_pop_free(pcd->cert_chain,X509_free);
            pcd->cert_chain = NULL;
        }

        if (pcd->gs_ctx)
        {
            /*
             * SSLeay or OpenSSL map not free the  
             * session cache as expected when calling SSL_CTX_free
             */
            SSL_CTX_free(pcd->gs_ctx);
            pcd->gs_ctx = NULL;     
        }
        if (pcd->certdir)
        {
            free(pcd->certdir);
            pcd->certdir = NULL;
        }
        if (pcd->certfile)
        {
            free(pcd->certfile);
            pcd->certfile = NULL;
        }
#ifdef USE_PKCS11
        if (pcd->hSession)
        {
            sc_final(pcd->hSession);
            pcd->hSession = 0;
        }
#endif

        free(pcd);
    }
    return 0;
}

/**********************************************************************
Function: proxy_create_local()

Description:
    Creates a proxy on the local machine. Used by globus_proxy_init
        
Parameters:

Returns:
**********************************************************************/

int
proxy_create_local(
    proxy_cred_desc *                   pcd,
    const char *                        outfile,
    int                                 hours,
    int                                 bits,
    globus_proxy_type_t                 proxy_type,
    int                                 (*kpcallback)(),
    STACK_OF(X509_EXTENSION) *          extensions)
{
    int                                 status = -1;
    FILE *                              fpout = NULL;
    X509 *                              ncert = NULL; 
    EVP_PKEY *                          npkey;
    X509_REQ *                          req;
    BIO *                               bp = NULL;

    fpout=fopen(outfile,"w");
    if (fpout == NULL)
    {
        PRXYerr(PRXYERR_F_LOCAL_CREATE,PRXYERR_R_PROBLEM_PROXY_FILE);
        ERR_add_error_data(2,"\n        Open failed for File=",outfile);
        goto err;
    }

#ifndef WIN32
    if (fchmod(fileno(fpout),0600) == -1)
    {
        PRXYerr(PRXYERR_F_LOCAL_CREATE,PRXYERR_R_PROBLEM_PROXY_FILE);
        ERR_add_error_data(2, "\n        chmod failed for File=",outfile);
        goto err;
    }
#endif
    /* 
     * DEE? may need to create a x509_store with the rest of 
     * the certificates. If so it needs to be passed to
     * proxy_marshal_bp
     */ 

    if (proxy_genreq(pcd->ucert,&req,&npkey,bits,
                     (int (*)())kpcallback, pcd))
    {
        goto err;
    }

    /* 
     * Add proxy extensions
     */
#ifdef DEBUG
    fprintf(stderr,"Adding Extensions to request\n");
#endif
        

    if (proxy_sign(pcd->ucert,
                   pcd->upkey,
                   req,
                   &ncert,
                   hours*60*60,
                   extensions,
                   proxy_type))
    {
        goto err;
    }
        
    if ((bp=BIO_new(BIO_s_file())) != NULL)
    {
        BIO_set_fp(bp,fpout,BIO_NOCLOSE);
    }

    if (proxy_marshal_bp(bp,ncert,npkey,pcd->ucert,pcd->cert_chain))
    {
        goto err;
    }

    status = 0;
err:
    if (ncert)
    {
        X509_free(ncert);
    }
    if (bp)
    {
        BIO_free(bp);
    }
    if (fpout)
    {
        fclose(fpout);
    }

    return status;

}

/**********************************************************************
Function: ASN1_UTCTIME_mktime()

Description:
 SSLeay only has compare functions to the current 
 So we define a convert to time_t from which we can do differences
 Much of this it taken from the X509_cmp_current_time()
 routine. 

Parameters:

Returns:
        time_t 
**********************************************************************/

time_t
ASN1_UTCTIME_mktime(
    ASN1_UTCTIME *                      ctm)
{
    char *                              str;
    time_t                              offset;
    char                                buff1[24];
    char *                              p;
    int                                 i;
    struct tm                           tm;

    p = buff1;
    i = ctm->length;
    str = (char *)ctm->data;
    if ((i < 11) || (i > 17))
    {
        return(0);
    }
    memcpy(p,str,10);
    p += 10;
    str += 10;

    if ((*str == 'Z') || (*str == '-') || (*str == '+'))
    {
        *(p++)='0'; *(p++)='0';
    }
    else
    {
        *(p++)= *(str++); *(p++)= *(str++);
    }
    *(p++)='Z';
    *(p++)='\0';

    if (*str == 'Z')
    {
        offset=0;
    }
    else
    {
        if ((*str != '+') && (str[5] != '-'))
        {
            return(0);
        }
        offset=((str[1]-'0')*10+(str[2]-'0'))*60;
        offset+=(str[3]-'0')*10+(str[4]-'0');
        if (*str == '-')
        {
            offset=-offset;
        }
    }

    tm.tm_isdst = 0;
    tm.tm_year = (buff1[0]-'0')*10+(buff1[1]-'0');

    if (tm.tm_year < 70)
    {
        tm.tm_year+=100;
    }
        
    tm.tm_mon   = (buff1[2]-'0')*10+(buff1[3]-'0')-1;
    tm.tm_mday  = (buff1[4]-'0')*10+(buff1[5]-'0');
    tm.tm_hour  = (buff1[6]-'0')*10+(buff1[7]-'0');
    tm.tm_min   = (buff1[8]-'0')*10+(buff1[9]-'0');
    tm.tm_sec   = (buff1[10]-'0')*10+(buff1[11]-'0');

    /*
     * mktime assumes local time, so subtract off
     * timezone, which is seconds off of GMT. first
     * we need to initialize it with tzset() however.
     */

    tzset();

#if defined(HAVE_TIME_T_TIMEZONE)
    return (mktime(&tm) + offset*60*60 - timezone);
#elif defined(HAVE_TIME_T__TIMEZONE)
    return (mktime(&tm) + offset*60*60 - _timezone);
#else
    return (mktime(&tm) + offset*60*60);
#endif
}


/**********************************************************************
Function: proxy_password_callback_no_prompt()

Description:
            Function to be passed into SSLeay as a password callback. Simply
      returns an error if called so that user will not be prompted.
        
Parameters:
      buffer - pointer to buffer to be filled in with password
                        size - size of buffer
                        w - XXX I have no idea

Returns:
      -1 always

**********************************************************************/

int
proxy_password_callback_no_prompt(
    char *                              buffer,
    int                                 size,
    int                                 w)
{
    PRXYerr(PRXYERR_F_CB_NO_PW, PRXYERR_R_NO_PROXY);

    return(-1);
}


int
i2d_integer_bio(
    BIO *                               bp,
    long                                v)
{
    ASN1_INTEGER *                      asn1_int;
    unsigned char *                     buffer;
    
    asn1_int = ASN1_INTEGER_new();

    ASN1_INTEGER_set(asn1_int, v);

    ASN1_i2d_bio(i2d_ASN1_INTEGER, bp, (unsigned char *) asn1_int);
    
    ASN1_INTEGER_free(asn1_int);
    
}

long
d2i_integer_bio(
    BIO *                               bp,
    long *                              v)
{
    ASN1_INTEGER *                      asn1_int = NULL;
    
    ASN1_d2i_bio((char *(*)())ASN1_INTEGER_new,
                 (char *(*)())d2i_ASN1_INTEGER,
                 (bp),
                 (unsigned char **)(&asn1_int));
    
    *v = ASN1_INTEGER_get(asn1_int);
    ASN1_INTEGER_free(asn1_int);

    return *v;
}

int
pkcs12_load_credential(
    proxy_cred_desc *                   pcd, 
    const char *                        user_cred,
    char *                              password)
{
    PKCS12 *                            p12 = NULL;
    STACK_OF(PKCS7) *                   auth_safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *          bags = NULL;
    STACK_OF(X509) *                    certs;
    PKCS12_SAFEBAG *                    bag;
    int                                 bag_nid;
    int                                 i;
    int                                 j;
    PKCS7 *                             p7;
    PKCS8_PRIV_KEY_INFO *               p8;
    int                                 status = -1;
    FILE *                              fp;

#ifdef DEBUG
    fprintf(stderr,"pkcs12_load_credential\n");
#endif
    /* Check arguments */
    if (!user_cred)
    {
        if (pcd->owner==CRED_OWNER_SERVER)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE);
            status = PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE;
        }
        else
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
            status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
        }
        
        ERR_add_error_data(1, "\n        No credential file found");
        goto err;   
    }

    if((fp = fopen(user_cred,"r")) == NULL)
    {
        if (pcd->type == CRED_TYPE_PROXY && pcd->owner == CRED_OWNER_USER)
        {
            PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_NO_PROXY);
            ERR_add_error_data(2, "\n        Proxy File=", user_cred);
            status = PRXYERR_R_NO_PROXY;
        }
        else
        {
            if (pcd->owner==CRED_OWNER_SERVER)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE);
                status = PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE;
            }
            else
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
                status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
            }
                    
            ERR_add_error_data(2, "\n        Cert File=", user_cred);
        }
        goto err;
    }
    
    p12 = d2i_PKCS12_fp(fp, NULL);

    fclose(fp);
    
    if(p12 == NULL)
    {
        /* some error or other */
        goto err;   
    }
    
    /* don't know if we need to check the MAC */
    
    if(!PKCS12_verify_mac(p12,password,-1))
    {
        /* some error or other */
        goto err;   
    }
    
    auth_safes = M_PKCS12_unpack_authsafes(p12);
    
    if(!auth_safes)
    {
        /* some error or other */
        goto err;   
    }

    certs = sk_X509_new_null();
    
    for (i = 0; i < sk_PKCS7_num(auth_safes); i++)
    {
        p7 = sk_PKCS7_value (auth_safes, i);
        
        bag_nid = OBJ_obj2nid (p7->type);
        
        if(bag_nid == NID_pkcs7_data)
        {
            bags = M_PKCS12_unpack_p7data(p7);
        }
        else if(bag_nid == NID_pkcs7_encrypted)
        {
            bags = M_PKCS12_unpack_p7encdata (p7, password, -1);
        }
        else
        {
            /* some error or other */
            goto err;   
        }

    
        for (j=0;j<sk_PKCS12_SAFEBAG_num(bags);j++)
        {
            bag = sk_PKCS12_SAFEBAG_value(bags, j);
            
            if(M_PKCS12_bag_type(bag) == NID_certBag &&
               M_PKCS12_cert_bag_type(bag) == NID_x509Certificate)
            {
                sk_X509_push(certs,M_PKCS12_certbag2x509(bag));
            }
            else if(M_PKCS12_bag_type(bag) == NID_keyBag &&
                    pcd->upkey == NULL)
            {
                p8 = bag->value.keybag;
                if (!(pcd->upkey = EVP_PKCS82PKEY (p8)))
                {
                    /* some error or other */
                    goto err;   
                }
            }
            else if(M_PKCS12_bag_type(bag) == NID_pkcs8ShroudedKeyBag &&
                    pcd->upkey == NULL)
            {
                if (!(p8 = M_PKCS12_decrypt_skey(bag,
                                                 password,
                                                 strlen(password))))
                {
                    /* some error or other */
                    goto err;   
                }
            
                if (!(pcd->upkey = EVP_PKCS82PKEY(p8)))
                {
                    /* some error or other */
                    goto err;   
                }
                
                PKCS8_PRIV_KEY_INFO_free(p8);
            }
        }
    }
    
    if(pcd->upkey == NULL)
    {
        /* some error or other */
        goto err;   
    }

    for(i=0;i<sk_X509_num(certs);i++)
    {
        pcd->ucert = sk_X509_pop(certs);

        if(X509_check_private_key(pcd->ucert, pcd->upkey)) 
        {
            sk_X509_pop_free(certs, X509_free);
            return 0;
        }
        else
        {
            X509_free(pcd->ucert);
        }
    }

err:
    return status;
}

int
globus_ssl_utils_setup_ssl_ctx(
    SSL_CTX **                          context,
    char *                              ca_cert_file,
    char *                              ca_cert_dir,
    X509 *                              client_cert,
    EVP_PKEY *                          client_private_key,
    STACK_OF(X509) *                    cert_chain,
    int *                               num_null_enc_ciphers)
{
    int                                 status = -1;
    int                                 len;
    int                                 i;
    int                                 j;
    char *                              fname = NULL;
#ifndef WIN32
    DIR *                               dirp = NULL;
    struct dirent *                     direntp;
#endif
    FILE *                              fp = NULL;
    X509 *                              ca_cert = NULL;
    X509 *                              xcert = NULL;
    SSL_CIPHER *                        cipher;
    
    SSLeay_add_ssl_algorithms();
    *context = SSL_CTX_new(SSLv3_method());

    if(*context == NULL)
    {
        goto err;
    }

    SSL_CTX_set_options(*context, 0); /* no options */
    
    SSL_CTX_set_cert_verify_callback(*context, 
                                     proxy_app_verify_callback,
                                     NULL);

    /* Set the verify callback to test our proxy 
     * policies. 
     * The SSL_set_verify does not appear to work as 
     * expected. The SSL_CTX_set_verify does more,
     * it also sets the X509_STORE_set_verify_cb_func
     * which is what we want. This occurs in both 
     * SSLeay 0.8.1 and 0.9.0 
     */

    SSL_CTX_set_verify(*context,SSL_VERIFY_PEER,
                       proxy_verify_callback);

    /*
     * for now we will accept any purpose, as Globus does
     * nor have any restrictions such as this is an SSL client
     * or SSL server. Globus certificates are not required
     * to have these fields set today.
     * DEE - Need  to look at this in future if we use 
     * certificate extensions...  
     */
    SSL_CTX_set_purpose(*context,X509_PURPOSE_ANY);

    /* set a small limit on ssl session-id reuse */

    SSL_CTX_sess_set_cache_size(*context,5);

    if (!SSL_CTX_load_verify_locations(*context,
                                       ca_cert_file,
                                       ca_cert_dir))
    {
        PRXYerr(PRXYERR_F_SETUP_SSL_CTX,PRXYERR_R_PROCESS_CERTS);
        ERR_add_error_data(4, "\n        x509_cert_file=", 
                           (ca_cert_file) ? ca_cert_file: "NONE" ,
                           "\n        x509_cert_dir=",
                           (ca_cert_dir) ? ca_cert_dir : "NONE");
        status = PRXYERR_R_PROCESS_CERTS;       
        goto err;
    }
        
    /*
     * Need to load the cert_file and/or the CA certificates
     * to get the client_CA_list. This is really only needed
     * on the server side, but will do it on both for now. 
     * Some Java implementations insist on having this. 
     */

    if (ca_cert_file)
    {
        SSL_CTX_set_client_CA_list(*context,
                                   SSL_load_client_CA_file(ca_cert_file));
        if (!SSL_CTX_get_client_CA_list(*context))
        {
            PRXYerr(PRXYERR_F_SETUP_SSL_CTX,PRXYERR_R_PROBLEM_CLIENT_CA);
            ERR_add_error_data(2,"\n        File=", ca_cert_file);
            status = PRXYERR_R_PROBLEM_CLIENT_CA;
            goto err;
        }
    }
        
    /*
     * So go through the ca_cert_dir looking for certificates
     * then verify that they are in the ca-signing-policy 
     * as well. 
     */ 

#ifndef WIN32
    if ((dirp = opendir(ca_cert_dir)) != NULL)
    {
#ifdef DEBUG
        fprintf(stderr,"looking for CA certs\n");
#endif
        while ( (direntp = readdir( dirp )) != NULL )
        {
            /* look for hashed file names hhhhhhhh.n */
            len = strlen(direntp->d_name);
            if ((len >= 10)
                && (*(direntp->d_name + 8) == '.')
                && (strspn(direntp->d_name, 
                           "0123456789abcdefABCDEF") == 8)
                && (strspn((direntp->d_name + 9),
                           "0123456789") == (len - 9)))
            {
                fname = (char *)malloc(strlen(ca_cert_dir) + 
                                       strlen(direntp->d_name) + 2);
                if (!fname)
                {
                    PRXYerr(PRXYERR_F_SETUP_SSL_CTX, PRXYERR_R_OUT_OF_MEMORY);
                    status = PRXYERR_R_OUT_OF_MEMORY;
                    goto err;
                }
                sprintf(fname,"%s%s%s", ca_cert_dir,
                        FILE_SEPERATOR,
                        direntp->d_name);

#ifdef DEBUG
                fprintf(stderr,"CA cert=%s\n",fname);
#endif
                if ((fp = fopen(fname,"r")) == NULL)
                {
                    PRXYerr(PRXYERR_F_SETUP_SSL_CTX,PRXYERR_R_PROCESS_CA_CERT);
                    ERR_add_error_data(2, "\n        File=", fname);
                    goto err;
                }

                if (PEM_read_X509(fp,
                                  &ca_cert,
                                  OPENSSL_PEM_CB(NULL,NULL)) == NULL)
                {
                    PRXYerr(PRXYERR_F_SETUP_SSL_CTX,PRXYERR_R_PROCESS_CERT);
                    ERR_add_error_data(2, "\n        File=", fname);
                    status = PRXYERR_R_PROCESS_CERT;
                    goto err;
                }

                free(fname);
                fname = NULL;
                fclose(fp);
                fp = NULL;
                SSL_CTX_add_client_CA(*context, ca_cert);
                X509_free(ca_cert);
                ca_cert = NULL;
            }
        }
    }
#endif /* WIN32 */
    
    if (client_cert && !SSL_CTX_use_certificate(*context,client_cert))
    {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
        status = PRXYERR_R_PROCESS_CERT;
        goto err;
    }
    
    if (client_private_key && !SSL_CTX_use_PrivateKey(*context,
                                                      client_private_key))
    {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
        status = PRXYERR_R_PROCESS_KEY;
        goto err;
    }

    if (cert_chain)
    {
        for (i=0;i<sk_X509_num(cert_chain);i++)
        {
            xcert = sk_X509_value(cert_chain,i);

#ifdef DEBUG
            {
                char * s;
                s=X509_NAME_oneline(X509_get_subject_name(xcert),NULL,0);
                fprintf(stderr,"Adding to X509_STORE %d %p %s\n",i,xcert,s);
                free(s);
            }
#endif
            j = X509_STORE_add_cert((*context)->cert_store,xcert);
            
            if (!j)
            {
                if ((ERR_GET_REASON(ERR_peek_error()) ==
                     X509_R_CERT_ALREADY_IN_HASH_TABLE))
                {
                    ERR_clear_error();
                    break;
                }
                else
                {
                    goto err;
                }
            }
        }
    }

    
    /*
     * The SSLeay when built by default excludes the NULL 
     * encryption options: #ifdef SSL_ALLOW_ENULL in ssl_ciph.c
     * Since the user obtains and builds the SSLeay, we have 
     * no control over how it is built. 
     *
     * We have an export licence for this code, and don't
     * need/want encryption. We will therefore turn off
     * any encryption by placing the RSA_NULL_MD5 cipher
     * first. See s3_lib.c ssl3_ciphers[]=  The RSA_NUL_MD5
     * is the first, but the way to get at it is as  n-1 
     *
     * Now that we support encryption, we may still add
     * RSA_NUL_MD5 but it may be at the begining or end
     * of the list. This will allow for some compatability. 
     * (But in this code we will put it last for now.)
     *
     * Where, if at all, RSA_NUL_MD5 is added:
     *
     *                 |  Initiate     Accept
     * ----------------------------------------
     * GSS_C_CONF_FLAG |
     *     set         |  end        don't add
     *   notset        |  begining   end
     *                 ------------------------
     *
     * This gives the initiator control over the encryption
     * but lets the server force encryption.
     *
     *                         Acceptor
     *                   |    yes     no    either
     * ----------------------------------------------
     *             yes   |    yes    reject  yes
     * Initiator   no    |    reject  no     no
     *             either|    yes     no     no
     * 
     * When encryption is selected, the ret_flags will have
     * ret_flags set with GSS_C_CONF_FLAG. The initiator and
     * acceptor can then decied if this was acceptable, i.e.
     * reject the connection. 
     *                 
     * 
     * This method may need to be checked with new versions
     * of the SSLeay packages. 
     */ 

#define MY_NULL_MASK 0x130021L
        
    j = 0;

    for (i=0; i<(*((*context)->method->num_ciphers))(); i++)
    {
        cipher = (*((*context)->method->get_cipher))(i);

        if (cipher && 
            ((cipher->algorithms & MY_NULL_MASK) == MY_NULL_MASK))
        {
            j++;
#ifdef DEBUG
            fprintf(stderr,"adding cipher %d %d\n", i, j);
#endif
            sk_SSL_CIPHER_push(
                (*context)->cipher_list, cipher);
            sk_SSL_CIPHER_push(
                (*context)->cipher_list_by_id, cipher);
        }
    }

    if(num_null_enc_ciphers)
    {
        *num_null_enc_ciphers = j;
    }
    
    status = 0;
err:
    if (fname)
    {
        free(fname);
    }
    if (fp)
    {
        fclose(fp);
    }
#ifndef WIN32
    if (dirp)
    {
        closedir(dirp);
    }
#endif

    return status;
}

/* Thought I'd need the below, but didn't. Might come in handy some
 * day -Sam
 */

#if 0

int
globus_ssl_utils_get_verified_cert_chain(
    X509 *                              ucert,
    STACK_OF(X509) *                    cert_chain,
    char *                              ca_cert_dir,
    STACK_OF(X509) **                   verified_cert_chain)
{
    int                                 i;
    int                                 j;
    int                                 retval = 0;
    X509_STORE *                        cert_store = NULL;
    X509_LOOKUP *                       lookup = NULL;
    X509_STORE_CTX *                    store_context = NULL;
    X509 *                              chain_cert = NULL;
    X509 *                              user_cert = NULL;
    STACK_OF(X509) *                    store_chain;
    
#ifdef DEBUG
    fprintf(stderr,"globus_ssl_utils_get_verified_cert_chain\n");
#endif
    user_cert = ucert;
    cert_store = X509_STORE_new();
    store_context = X509_STORE_CTX_new();

    if (cert_chain != NULL)
    {
        for (i=0;i<sk_X509_num(cert_chain);i++)
        {
            chain_cert = sk_X509_value(cert_chain,i);

            if (user_cert == NULL)
            {
                user_cert = chain_cert;
            }
            else
            {
#ifdef DEBUG
                {
                    char * s;
                    s = X509_NAME_oneline(X509_get_subject_name(chain_cert),
                                          NULL,0);
                    fprintf(stderr,"Adding %d %p %s\n",i,chain_cert,s);
                    free(s);
                }
#endif
                j = X509_STORE_add_cert(cert_store, X509_dup(chain_cert));
                if (!j)
                {
                    if ((ERR_GET_REASON(ERR_peek_error()) ==
                         X509_R_CERT_ALREADY_IN_HASH_TABLE))
                    {
                        ERR_clear_error();
                        break;
                    }
                    else
                    {
                        /*DEE need errprhere */
                        goto err;
                    }
                }
            }
        }
    }
    
    if (ca_cert_dir != NULL &&
        (lookup = X509_STORE_add_lookup(cert_store,
                                        X509_LOOKUP_hash_dir())))
    {
        X509_LOOKUP_add_dir(lookup,ca_cert_dir,X509_FILETYPE_PEM);
    }

    X509_STORE_CTX_init(store_context,cert_store,user_cert,NULL);

#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
    /* override the check_issued with our version */
    store_context->check_issued = proxy_check_issued;
#endif

    if(!X509_verify_cert(store_context))
    {
        goto err;
    }

    *verified_cert_chain = sk_X509_new_null();

    store_chain = X509_STORE_CTX_get_chain(store_context);
    
    for(i=0;i<sk_X509_num(store_chain);i++)
    {
        sk_X509_insert(*verified_cert_chain,
                  X509_dup(sk_X509_value(store_chain,i)),i);
    }
    
    retval = 1;

err:
    if(store_context)
    {
        X509_STORE_CTX_free(store_context);
    }

    if(cert_store)
    {
        X509_STORE_free(cert_store);
    }
    
    return retval;
}

#endif





