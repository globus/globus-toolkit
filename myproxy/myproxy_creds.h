/*
 * myproxy_creds.h
 *
 * Interface for storing and retrieving proxies.
 */
#ifndef __MYPROXY_CREDS_H
#define __MYPROXY_CREDS_H

#include <time.h>

#define REGULAR_EXP 1
#define MATCH_CN_ONLY 0

#include <time.h>

struct myproxy_creds {
    char *username;
    char *location;

    /* the following items are stored in the credential data file */
    char *passphrase; /* stored crypt()'ed */
    char *owner_name;
    int lifetime;
    char *credname;
    char *creddesc;
    char *retrievers;
    char *renewers;

    /* start_time and end_time are set from the certificates in the cred */
    time_t start_time;
    time_t end_time;

    struct myproxy_creds *next;
};

typedef struct myproxy_creds myproxy_creds_t;

/*
 * myproxy_creds_store()
 *
 * Store the given credentials. The caller should allocate and fill in
 * the myproxy_creds structure.  The passphrase in the myproxy_creds
 * structure will be crypt()'ed before it is written.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_store(const struct myproxy_creds *creds);

/*
 * myproxy_creds_retrieve()
 *
 * Retrieve the credentials associated with the username and
 * credential name in the given myproxy_creds structure.
 * Note: No checking on the passphrase or owner name is done.
 * Note: The passphrase returned in the myproxy_creds structure is crypt()'ed.
 *
 * Returns -1 on error, 0 on success.  */
int myproxy_creds_retrieve(struct myproxy_creds *creds);

/*
 * myproxy_creds_retrieve_all()
 *
 * Retrieve all credentials associated with the username and owner
 * name in the given myproxy_creds structure.  If multiple credentials
 * are stored under the given username, they'll be chained together in
 * a linked-list using the next field in the given myproxy_creds
 * structure.  The default credential (i.e., with no credname) will be
 * first in the list, if one exists.
 * Note: The passphrase returned in the myproxy_creds structure is crypt()'ed.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_retrieve_all(struct myproxy_creds *creds);

/*
 * myproxy_creds_delete()
 *
 * Delete any stored credentials held for the given user as indiciated
 * by the username and credname fields in the given myproxy_creds structure.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_delete(const struct myproxy_creds *creds);

/*
 * myproxy_creds_change_passphrase()
 *
 * Change the passphrase of the credential specified by the username
 * and credential name to new_passphrase.
 * The current passphrase must be present in the myproxy_creds struct.
 *
 * Returns -1 on error, 0 on success
 */

int myproxy_creds_change_passphrase(const struct myproxy_creds *creds,
				    const char *new_passphrase);
 
/*
 * myproxy_creds_exist()
 *
 * Check to see if the given user already has credentials stored.
 *
 * Returns 1 if the user does, 0 if they do not, -1 on error.
 */
int myproxy_creds_exist(const char *username, const char *credname);

/*
 * myproxy_creds_is_owner()
 *
 * Check to see if the given client is the owner of the credentials
 * referenced by username.
 *
 * Returns 1 if the client owns the credentials, 0 if they do not, -1 on error.
 */
int myproxy_creds_is_owner(const char *username, const char *credname,
			   const char *client_name);

/*
 * myproxy_creds_free_contents()
 *
 * Free all the contents of the myproxy_creds structure, but not the
 * structure itself.
 */
void myproxy_creds_free_contents(struct myproxy_creds *creds);

/* 
 * myproxy_set_storage_dir()
 * 
 * Change default storage directory.
 * Returns -1 on error, 0 on success.
 */
int myproxy_set_storage_dir(const char *dir);

/* 
 * myproxy_check_storage_dir()
 * 
 * Make sure the storage directory is OK.
 * Returns 0 if OK, -1 if not.
 */
int myproxy_check_storage_dir();

#endif

