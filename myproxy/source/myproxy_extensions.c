#include "myproxy_common.h"

static STACK_OF(X509_EXTENSION) *extensions = NULL;

int
myproxy_set_extensions_from_file(const char filename[])
{
    CONF *extconf = NULL;
    long errorline = -1;

    myproxy_free_extensions();

    extensions = sk_X509_EXTENSION_new_null();

    extconf = NCONF_new(NULL);
    if (NCONF_load(extconf, filename, &errorline) <= 0) {
        if (errorline <= 0) {
            verror_put_string("OpenSSL error loading the proxy_extfile '%s'",
                              filename);
        } else {
            verror_put_string("OpenSSL error on line %ld of proxy_extfile '%s'\n", errorline, filename);
        }
        return -1;
    }
    myproxy_debug("Successfully loaded extensions file %s.", filename);
    if (X509V3_EXT_add_nconf_sk(extconf, NULL, "default", &extensions) != 1) {
        verror_put_string("X509V3_EXT_add_nconf_sk() failed");
        return -1;
    }
    myproxy_debug("Successfully set extensions.");

    return 0;
}

int
myproxy_set_extensions_from_callout(const char path[],
                                    const char username[],
                                    const char location[])
{
    pid_t childpid;
    int fds[3];
    int exit_status;
    CONF *extconf = NULL;
    long errorline = -1;
    FILE *nconf_stream = NULL;

    myproxy_debug("calling %s", path);

    childpid = myproxy_popen(fds, path, username, location, NULL);
    if (childpid < 0) {
        return -1; /* myproxy_popen will set verror */
    }
    close(fds[0]);
    if (waitpid(childpid, &exit_status, 0) == -1) {
        verror_put_string("wait() failed for proxy_extapp child");
        verror_put_errno(errno);
        return -1;
    }
    if (exit_status != 0) {
        FILE *fp = NULL;
        char buf[100];
        verror_put_string("proxy_extapp call-out returned non-zero.");
        fp = fdopen(fds[1], "r");
        if (fp) {
            while (fgets(buf, 100, fp) != NULL) {
                verror_put_string("%s", buf);
            }
            fclose(fp);
        }
        fp = fdopen(fds[2], "r");
        if (fp) {
            while (fgets(buf, 100, fp) != NULL) {
                verror_put_string("%s", buf);
            }
            fclose(fp);
        }
        return -1;
    }
    close(fds[2]);
    myproxy_free_extensions();
    extensions = sk_X509_EXTENSION_new_null();
    extconf = NCONF_new(NULL);
    nconf_stream = fdopen(fds[1], "r");
    if (NCONF_load_fp(extconf, nconf_stream, &errorline) <= 0) {
        if (errorline <= 0) {
            verror_put_string("OpenSSL error parsing output of proxy_extapp call-out.");
        } else {
            verror_put_string("OpenSSL error parsing line %ld of of proxy_extapp call-out output.", errorline);
        }
        fclose(nconf_stream);
        return -1;
    }
    fclose(nconf_stream);

    myproxy_debug("Successfully loaded extensions.");
    if (X509V3_EXT_add_nconf_sk(extconf, NULL, "default", &extensions) != 1) {
        verror_put_string("X509V3_EXT_add_nconf_sk() failed");
        return -1;
    }
    myproxy_debug("Successfully set extensions.");

    return 0;
}

int
myproxy_get_extensions(STACK_OF(X509_EXTENSION) **e)
{
    if (extensions) {
        *e = sk_X509_EXTENSION_dup(extensions);
    }
    return 0;
}

int myproxy_free_extensions()
{
    if (extensions) {
        sk_X509_EXTENSION_free(extensions);
        extensions = NULL;
    }
    return 0;
}

int
myproxy_add_extension(X509_EXTENSION *extension)
{
    if (extension == NULL) {
        verror_put_string("NULL extension is passed");
        return -1;
    }
    if (X509v3_add_ext(&extensions, extension, -1) == NULL) {
        verror_put_string("Couldn't add extension.");
        return -1;
    }
    return 0;
}
