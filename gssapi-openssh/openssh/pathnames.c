#include "includes.h"
#include "xmalloc.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define USRDIR "/usr"
#define BINDIR "/bin"
#define LIBEXEC "/libexec"
#define GSISSHDIR "/etc/gsissh"
#define SSHDIR "/etc/ssh"
#define VARDIR "/var"
#define VARRUN "/var/run"

#define STRINIT "init_pathnames() not called!"

char *_PATH_SSH_SYSTEM_HOSTFILE		= STRINIT;
char *_PATH_SSH_SYSTEM_HOSTFILE2	= STRINIT;
char *_PATH_SERVER_CONFIG_FILE		= STRINIT;
char *_PATH_HOST_CONFIG_FILE		= STRINIT;
char *_PATH_HOST_KEY_FILE		= STRINIT;
char *_PATH_HOST_DSA_KEY_FILE		= STRINIT;
char *_PATH_HOST_ECDSA_KEY_FILE		= STRINIT;
char *_PATH_HOST_RSA_KEY_FILE		= STRINIT;
char *_PATH_DH_MODULI			= STRINIT;
char *_PATH_DH_PRIMES			= STRINIT;
char *_PATH_SSH_PROGRAM			= STRINIT;
char *_PATH_SSH_DAEMON_PID_FILE		= STRINIT;
char *_PATH_SSH_SYSTEM_RC		= STRINIT;
char *_PATH_SSH_HOSTS_EQUIV		= STRINIT;
char *_PATH_SSH_KEY_SIGN		= STRINIT;
char *_PATH_SSH_PKCS11_HELPER	= STRINIT;
char *_PATH_SFTP_SERVER			= STRINIT;
char *_PATH_STDPATH_WITH_SCP		= STRINIT;

static char *
compose2(const char str1[], const char str2[])
{
    int len;
    char *result;

    len = strlen(str1) + strlen(str2) + 1;
    result = xmalloc(len);
    snprintf(result, len, "%s%s", str1, str2);

    return result;
}

static char *
compose3(const char str1[], const char str2[], const char str3[])
{
    int len;
    char *result;

    len = strlen(str1) + strlen(str2) + strlen(str3) + 1;
    result = xmalloc(len);
    snprintf(result, len, "%s%s%s", str1, str2, str3);

    return result;
}

void
init_pathnames()
{
    char *gl=NULL, *bindir=NULL, *libexec=NULL, *sshdir=NULL, *piddir=NULL;

    gl = (char *)getenv("GLOBUS_LOCATION");

    if (gl) {
        bindir = compose2(gl, BINDIR);
        libexec = compose2(gl, LIBEXEC);
        piddir = compose2(gl, VARDIR);
    } else {
        bindir = compose2(USRDIR, BINDIR);
        libexec = compose2(USRDIR, LIBEXEC);
        piddir = strdup(VARRUN);
    }

    if (gl) {
        sshdir = compose2(gl, SSHDIR);
        if (access(sshdir, X_OK) < 0) {
            logit("%s not found.", sshdir);
            free(sshdir);
            sshdir = NULL;
        }
    }
    if (!sshdir) {
        sshdir = strdup(GSISSHDIR);
        if (access(sshdir, X_OK) < 0) {
            fatal("%s not found.", sshdir);
        }
    }

    /* lots of one time memory leaks here */
    _PATH_SSH_SYSTEM_HOSTFILE	= compose2(sshdir, "/ssh_known_hosts");
    _PATH_SSH_SYSTEM_HOSTFILE2	= compose2(sshdir, "/ssh_known_hosts2");
    _PATH_SERVER_CONFIG_FILE	= compose2(sshdir, "/sshd_config");
    _PATH_HOST_CONFIG_FILE	= compose2(sshdir, "/ssh_config");
    _PATH_HOST_KEY_FILE		= compose2(sshdir, "/ssh_host_key");
    _PATH_HOST_DSA_KEY_FILE	= compose2(sshdir, "/ssh_host_dsa_key");
    _PATH_HOST_ECDSA_KEY_FILE	= compose2(sshdir, "/ssh_host_ecdsa_key");
    _PATH_HOST_RSA_KEY_FILE	= compose2(sshdir, "/ssh_host_rsa_key");
    _PATH_DH_MODULI		= compose2(sshdir, "/moduli");
    _PATH_DH_PRIMES		= compose2(sshdir, "/primes");
    _PATH_SSH_PROGRAM		= compose2(bindir, "/gsissh");
    _PATH_SSH_DAEMON_PID_FILE	= compose2(piddir, "/gsisshd.pid");
    _PATH_SSH_SYSTEM_RC		= compose2(sshdir, "/sshrc");
    _PATH_SSH_HOSTS_EQUIV	= compose2(sshdir, "/shosts.equiv");
    _PATH_SSH_KEY_SIGN		= compose2(libexec, "/ssh-keysign");
    _PATH_SSH_PKCS11_HELPER = compose2(libexec, "/ssh-pkcs11-helper");
    _PATH_SFTP_SERVER		= compose2(libexec, "/sftp-server");
    _PATH_STDPATH_WITH_SCP	= compose3(_PATH_STDPATH, ":", bindir);

    if (bindir) free(bindir);
    if (libexec) free(libexec);
    if (sshdir) free(sshdir);
    if (piddir) free(piddir);
}
