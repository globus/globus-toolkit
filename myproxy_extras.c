/*
 * myproxy_extras.c
 *
 * Contains useful; client functions for reading a password, 
 * generating and destroying delegated credentials
 */

#include <stdio.h>
#include <stdlib.h>

/* read_passphrase()
 * 
 * Reads a passphrase from stdin. The passphrase must be allocated and
 * be less than min and greater than max characters
 */
int
read_passphrase(char *passphrase, const int passlen, const int min, const int max) 
{
    int i;
    char pass[passlen];
    int done = 0;

    assert(passphrase != NULL);

    /* Get user's passphrase */    
    do {
        printf("Enter password to access myproxy-server:\n");
        
        if (!(fgets(pass, passlen, stdin))) {
            fprintf(stderr,"Failed to read password from stdin\n");   
            return -1;
        }	
        i = strlen(pass);
        if ((i < min) || (i > max)) {
            printf("Password must be between %d and %d characters\n, min, max");
        } else {
            done = 1;
        }
    } while (!done);
    
    if (pass[i-1] == '\n') {
        pass[i-1] = '\0';
    }
    strncpy(passphrase, pass, passlen);
    return 0;
}

/* grid_proxy_init()
 *
 * Uses the system() call to run grid-proxy-init to create a user proxy
 *
 * returns grid-proxy-init status 0 if OK, -1 on error
 */
int
grid_proxy_init(int hours, const char *proxyfile) {

    int rc;
    char command[128];
  
    assert(proxyfile != NULL);

    sprintf(command, "grid-proxy-init -hours %d -out %s", hours, proxyfile);
    rc = system(command);

    return rc;
}

/* grid_proxy_destroy()
 *
 * Uses the system() call to run grid-proxy-destroy to create a user proxy
 *
 * returns grid-proxy-destroy status 0 if OK, -1 on error
 */
int
grid_proxy_destroy(const char *proxyfile) {
  
    int rc;
    char command[128];

    assert(proxyfile != NULL);

    sprintf(command, "grid-proxy-destroy %s", proxyfile);
    rc = system(command);

    return rc;
}

