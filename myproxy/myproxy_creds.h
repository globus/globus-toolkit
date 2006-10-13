/*
 * myproxy_creds.h
 *
 * Interface for storing and retrieving proxies.
 */
#ifndef __MYPROXY_CREDS_H
#define __MYPROXY_CREDS_H

#include <stdio.h>
#include <time.h>

#define REGULAR_EXP   1
#define MATCH_CN_ONLY 0

struct myproxy_creds {
    char  *username;
    char  *location;

    /* the following items are stored in the credential data file */
    char                 *passphrase; /* stored crypt()'ed */
    char                 *owner_name;
    int                   lifetime;
    char                 *credname;
    char                 *creddesc;
    char                 *retrievers;
    char                 *renewers;
    char                 *keyretrieve;
    char                 *trusted_retrievers;

    /* start_time and end_time are set from the certificates in the cred */
    time_t                start_time;
    time_t                end_time;

    /* non-NULL lockmsg indicates credential is administratively
       locked and should not be accessible.  lockmsg should be
       returned on any attempted access. */
    char                 *lockmsg;

    struct myproxy_creds *next;
};

typedef struct myproxy_creds myproxy_creds_t;

/* trusted certificate files */
struct myproxy_certs {
    char                 *filename;
    char                 *contents;
    struct myproxy_certs *next;
};

typedef struct myproxy_certs myproxy_certs_t;

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
 * Returns -1 on error, 0 on success.
 */
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

/* myproxy_admin_retrieve_all()
 *
 * Used by the repository query tool on the server side for admin purposes.
 *
 * Retrieve all credentials stored in the credential storage directory
 * in the given myproxy_creds structure.  Credentials are chained together in 
 * a linked-list using the next field in the given myproxy_creds structure
 * If creds->username is non-NULL, only retrieve credentials for that
 * username.
 * If creds->credname is non-NULL, only retrieve credentials for that
 * credential name.  A credname of "" indicates the "default" credential.
 * If creds->start_time is non-zero, only retrieve credentials with
 * end_time >= specified time.
 * If creds->end_time is non-zero, only retrieve credentials with
 * end_time < specified time.
 * Note: The passphrase returned in the myproxy_creds structure is crypt()'ed.
 *
 * Returns -1 on error, number of credentials on success.
 */
int myproxy_admin_retrieve_all(struct myproxy_creds *creds);

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
 * myproxy_creds_lock()
 *
 * Lock credentials indicated by the username and credname fields in
 * the given myproxy_creds structure, for the specified reason.
 * Locked credentials can not be retrieved or renewed.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_lock(const struct myproxy_creds *creds, const char *reason);

/*
 * myproxy_creds_unlock()
 *
 * Unlock credentials indicated by the username and credname fields in
 * the given myproxy_creds structure.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_unlock(const struct myproxy_creds *creds);

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
 * myproxy_creds_encrypted()
 *
 * Returns 1 if credentials are encrypted, 0 if unencrypted, and -1 on
 * error.
 */
int myproxy_creds_encrypted(const struct myproxy_creds *creds);

/*
 * myproxy_creds_verify_passphrase()
 *
 * Verify the given passphrase against the myproxy_creds structure.
 *
 * Returns 1 on verify, 0 on failure, and -1 on error.
 */
int myproxy_creds_verify_passphrase(const struct myproxy_creds *creds,
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
 * myproxy_creds_free()
 *
 * Free a list of myproxy_creds structures.
 */
void myproxy_creds_free(struct myproxy_creds *certs);

/*
 * myproxy_creds_free_contents()
 *
 * Free all the contents of the myproxy_creds structure, but not the
 * structure itself.
 */
void myproxy_creds_free_contents(struct myproxy_creds *creds);

/*
 * myproxy_certs_free()
 *
 * Free a list of myproxy_certs structures.
 */
void myproxy_certs_free(struct myproxy_certs *certs);

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

/*
 * myproxy_get_storage_dir()
 *
 * Returns path to storage directory.
 * Returns NULL on error.
 */
const char *myproxy_get_storage_dir();


/*
 * myproxy_print_cred_info()
 *
 * Print info about creds to out.
 * Returns 0 if OK, -1 if not.
 */
int myproxy_print_cred_info(myproxy_creds_t *creds, FILE *out);

/*
 * myproxy_get_certs()
 *
 * Return linked list of trusted CA certificate and related files.
 * Returns NULL on error.
 */
myproxy_certs_t *myproxy_get_certs(const char cert_dir[]);

/*
 * myproxy_install_trusted_cert_files()
 *
 * Install a linked list of files in trusted cert dir.
 * Returns 0 on success, -1 otherwise.
 */
int myproxy_install_trusted_cert_files(myproxy_certs_t *);

/*
 * myproxy_creds_verify()
 *
 * Check the validity of the credentials in the myproxy_creds structure:
 *   - check Not Before and Not After fields against current time
 *   - check signature by trusted CA
 *   - check revocation status (CRL, OCSP)
 *
 * The myproxy_creds structure should be filled in by a previous call to
 * myproxy_creds_retrieve().
 *
 * Returns 0 on success, -1 on error (setting verror).
 */
int myproxy_creds_verify(const struct myproxy_creds *);

#endif

