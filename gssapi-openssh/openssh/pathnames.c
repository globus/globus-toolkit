#include "includes.h"
#include "xmalloc.h"
#include "log.h"

#define BINDIR "/bin"
#define LIBEXEC "/libexec"
#define SSHDIR "/etc/ssh"

char *SSH_PRNG_COMMAND_FILE;
char *_PATH_SSH_SYSTEM_HOSTFILE;
char *_PATH_SSH_SYSTEM_HOSTFILE2;
char *_PATH_SERVER_CONFIG_FILE;
char *_PATH_HOST_CONFIG_FILE;
char *_PATH_HOST_KEY_FILE;
char *_PATH_HOST_DSA_KEY_FILE;
char *_PATH_HOST_RSA_KEY_FILE;
char *_PATH_DH_MODULI;
char *_PATH_DH_PRIMES;
char *_PATH_SSH_PROGRAM;
char *_PATH_SSH_SYSTEM_RC;
char *_PATH_SSH_HOSTS_EQUIV;
char *_PATH_SFTP_SERVER;

static char *
compose(const char str1[], const char str2[], const char str3[])
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
    char *gl;

    gl = getenv("GLOBUS_LOCATION");
    if (gl == NULL) {
	fatal("GLOBUS_LOCATION environment variable undefined.");
    }

    SSH_PRNG_COMMAND_FILE	= compose(gl, SSHDIR, "/ssh_prng_cmds");
    _PATH_SSH_SYSTEM_HOSTFILE	= compose(gl, SSHDIR, "/ssh_known_hosts");
    _PATH_SSH_SYSTEM_HOSTFILE2	= compose(gl, SSHDIR, "/ssh_known_hosts2");
    _PATH_SERVER_CONFIG_FILE	= compose(gl, SSHDIR, "/sshd_config");
    _PATH_HOST_CONFIG_FILE	= compose(gl, SSHDIR, "/ssh_config");
    _PATH_HOST_KEY_FILE		= compose(gl, SSHDIR, "/ssh_host_key");
    _PATH_HOST_DSA_KEY_FILE	= compose(gl, SSHDIR, "/ssh_host_dsa_key");
    _PATH_HOST_RSA_KEY_FILE	= compose(gl, SSHDIR, "/ssh_host_rsa_key");
    _PATH_DH_MODULI		= compose(gl, SSHDIR, "/moduli");
    _PATH_DH_PRIMES		= compose(gl, SSHDIR, "/primes");
    _PATH_SSH_PROGRAM		= compose(gl, BINDIR, "/ssh");
    _PATH_SSH_SYSTEM_RC		= compose(gl, SSHDIR, "/sshrc");
    _PATH_SSH_HOSTS_EQUIV	= compose(gl, SSHDIR, "/shosts.equiv");
    _PATH_SFTP_SERVER		= compose(gl, LIBEXEC, "/sftp-server");
}
