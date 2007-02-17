#include "includes.h"
#include "xmalloc.h"
#include "log.h"

#define BINDIR "/bin"
#define LIBEXEC "/libexec"
#define SSHDIR "/etc/ssh"
#define VARDIR "/var"

#define STRINIT "init_pathnames() not called!"

char *SSH_PRNG_COMMAND_FILE		= STRINIT;
char *_PATH_SSH_SYSTEM_HOSTFILE		= STRINIT;
char *_PATH_SSH_SYSTEM_HOSTFILE2	= STRINIT;
char *_PATH_SERVER_CONFIG_FILE		= STRINIT;
char *_PATH_HOST_CONFIG_FILE		= STRINIT;
char *_PATH_HOST_KEY_FILE		= STRINIT;
char *_PATH_HOST_DSA_KEY_FILE		= STRINIT;
char *_PATH_HOST_RSA_KEY_FILE		= STRINIT;
char *_PATH_DH_MODULI			= STRINIT;
char *_PATH_DH_PRIMES			= STRINIT;
char *_PATH_SSH_PROGRAM			= STRINIT;
char *_PATH_SSH_DAEMON_PID_FILE		= STRINIT;
char *_PATH_SSH_SYSTEM_RC		= STRINIT;
char *_PATH_SSH_HOSTS_EQUIV		= STRINIT;
char *_PATH_SSH_KEY_SIGN		= STRINIT;
char *_PATH_SFTP_SERVER			= STRINIT;
char *SSH_RAND_HELPER			= STRINIT;
char *_PATH_STDPATH_WITH_SCP		= STRINIT;

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

static char *
compose4(const char str1[], const char str2[], const char str3[],
	 const char str4[])
{
    int len;
    char *result;

    len = strlen(str1) + strlen(str2) + strlen(str3) + strlen(str4) + 1;
    result = xmalloc(len);
    snprintf(result, len, "%s%s%s%s", str1, str2, str3, str4);

    return result;
}

void
init_pathnames()
{
    char *gl;

    gl = (char *)getenv("GLOBUS_LOCATION");
    if (gl == (char *)NULL) {
	fatal("GLOBUS_LOCATION environment variable undefined.");
    }

    /* lots of one time memory leaks here */
    SSH_PRNG_COMMAND_FILE	= compose3(gl, SSHDIR, "/ssh_prng_cmds");
    _PATH_SSH_SYSTEM_HOSTFILE	= compose3(gl, SSHDIR, "/ssh_known_hosts");
    _PATH_SSH_SYSTEM_HOSTFILE2	= compose3(gl, SSHDIR, "/ssh_known_hosts2");
    _PATH_SERVER_CONFIG_FILE	= compose3(gl, SSHDIR, "/sshd_config");
    _PATH_HOST_CONFIG_FILE	= compose3(gl, SSHDIR, "/ssh_config");
    _PATH_HOST_KEY_FILE		= compose3(gl, SSHDIR, "/ssh_host_key");
    _PATH_HOST_DSA_KEY_FILE	= compose3(gl, SSHDIR, "/ssh_host_dsa_key");
    _PATH_HOST_RSA_KEY_FILE	= compose3(gl, SSHDIR, "/ssh_host_rsa_key");
    _PATH_DH_MODULI		= compose3(gl, SSHDIR, "/moduli");
    _PATH_DH_PRIMES		= compose3(gl, SSHDIR, "/primes");
    _PATH_SSH_PROGRAM		= compose3(gl, BINDIR, "/gsissh");
    _PATH_SSH_DAEMON_PID_FILE	= compose3(gl, VARDIR, "/sshd.pid");
    _PATH_SSH_SYSTEM_RC		= compose3(gl, SSHDIR, "/sshrc");
    _PATH_SSH_HOSTS_EQUIV	= compose3(gl, SSHDIR, "/shosts.equiv");
    _PATH_SSH_KEY_SIGN		= compose3(gl, LIBEXEC, "/ssh-keysign");
    _PATH_SFTP_SERVER		= compose3(gl, LIBEXEC, "/sftp-server");
    SSH_RAND_HELPER		= compose3(gl, LIBEXEC, "/ssh-rand-helper");
    _PATH_STDPATH_WITH_SCP	= compose4(_PATH_STDPATH, ":", gl, BINDIR);
}
