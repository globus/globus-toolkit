/*
 * myproxy_creds.h
 *
 * Interface for storing and retrieving proxies.
 */
#ifndef __MYPROXY_CREDS_H
#define __MYPROXY_CREDS_H

struct myproxy_creds {
    char *user_name;
    char *pass_phrase;
    char *owner_name;
    char *location;
    int lifetime;
    void *restrictions;
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
 * myproxy_creds_retrieve()
 *
 * Retrieve the credentials associated with the give username and fill
 * in the passed myproxy_creds structure.
 *
 * Returns -1 on error, 0 on success.
 */
int myproxy_creds_retrieve(const char *user_name,
			   struct myproxy_creds *creds);

/*
 * myproxy_creds_delete()
 *
 * Delete any stored credentials held for the given user.
 */
void myproxy_creds_delete(const char *user_name);

/*
 * myproxy_creds_free_contents()
 *
 * Free all the contents of the myproxy_creds structure, but not the
 * structure itself.
 */
void myproxy_creds_free_contents(struct myproxy_creds *creds);

#endif /* __MYPROXY_CREDS_H */
