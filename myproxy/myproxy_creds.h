/*
 * myproxy_creds.h
 *
 * Interface for storing and retrieving proxies.
 */
#ifndef __MYPROXY_CREDS_H
#define __MYPROXY_CREDS_H

#include <time.h>
#include "my_utility.h" 

#define REGULAR_EXP 1
#define MATCH_CN_ONLY 0

struct myproxy_creds {
    char *username;
    char *passphrase;
    char *owner_name;
    char *location;
    char *retrievers;
    int retriever_expr_type;
    char *renewers;
    int renewer_expr_type;
    int lifetime;
    char *credname;
    char *creddesc;
    int force_credential_overwrite;
    void *restrictions;
    time_t start_time;
    time_t end_time;
};

typedef struct myproxy_creds myproxy_creds_t;

// debugging levels
#define DBG_HI 2
#define DBG_IN 1
#define DBG_LO 0
#define MAX_VARCHAR_LEN 255
#define CRED_NAME_LEN 200
#define MAX_TEXT_LEN 65535

struct myproxy_database {
	char *owner;
	char *passphrase;
	char *username;
	unsigned long lifetime;
	char *retrievers;
	char *renewers;
	char *credname;
	char *creddesc;
	char credentials[MAX_TEXT_LEN];
	int force_credential_overwrite;
};

	
	
/*
 * myproxy_creds_store()
 *
 * Store the given credentials. The caller should allocate and fill in
 * the myproxy_creds structure.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_store(const struct myproxy_creds *creds);

/*
 * myproxy_creds_fetch_entry ()
 */
int myproxy_creds_fetch_entry (char *username, char *credname, struct myproxy_creds *creds);

/*
 * myproxy_creds_retrieve()
 *
 * Retrieve the credentials associated with the given username and credential name in the
 * given myproxy_creds structure. The passphrase field in the structure
 * should also be filled in and will be checked.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_retrieve(struct myproxy_creds *creds);

/*
 * myproxy_creds_delete()
 *
 * Delete any stored credentials held for the given user as indiciated
 * by the username field in the given myproxy_creds structure.
 * Either the passphrase or the owner_name field in the structure should
 * be filled in and match those in the credentials.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_delete(const struct myproxy_creds *creds);

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
 */
void myproxy_set_storage_dir(char *dir);

#if defined (MULTICRED_FEATURE)
/*
 * freedbase ()
 *
 * free allotted database
 *
 */
void freedbase (struct myproxy_database *dbase);

/*
 * my_retrieve()
 *
 * retrieve one row of data from result set
 *
*/
int myretrieve(SQLHDBC hdbc, SQLHSTMT hstmt);

/*
 * my_param_insert()
 */
int my_param_insert(SQLHDBC hdbc, SQLHSTMT hstmt);

/*
 * read_from_database_for_info ()
 * 
 * read owner, credential name and credential description fields from database for myproxy-info
 */

char *read_from_database_for_info ();

/*
 * retreive_cred_from_database()
 *
 * retrieves credential from database for specified username and credential name
 */

int retrieve_cred_from_database_given_username_credname(char *username, char *credname, struct myproxy_creds *retrieved_creds);

/*
 * copy_credential_to_file()
 *
 * copies credential in database to file. GSI requires credential in a file before delegation
 *
 */

int copy_credential_to_file(struct myproxy_creds *creds, char *filename);
#endif

#endif /* __MYPROXY_CREDS_H */
