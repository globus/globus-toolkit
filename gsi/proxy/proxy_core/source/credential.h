
struct globus_l_cred_handle_s;

typedef struct globus_l_cred_handle_s * globus_cred_handle_t

typedef struct globus_l_cred_handle_s
{
    X509 *                              cert;
    EVP_KEY *                           key;
    STACK_OF(X509) *                    cert_chain
    globus_l_cred_handle_attrs_t *      attrs;
}
globus_l_cred_handle_t;

struct globus_l_cred_handle_attrs_s;

typedef struct globus_l_cred_handle_attrs_s * globus_cred_handle_attrs_t

typedef struct globus_l_cred_handle_attrs_s
{
    char *                              ca_cert_file;
    char *                              ca_cert_dir;
    char *                              proxy_file;
    char *                              cert_file;
    char *                              key_file;
    globus_cred_type_t                  search_order[];/*{PROXY,USER,HOST}*/
}
globus_l_cred_handle_attrs_t;

globus_result_t globus_cred_handle_init(
    globus_cred_handle_t *              handle,
    globus_cred_handle_attrs_t          handle_attrs);

globus_result_t globus_cred_handle_destroy(
    globus_cred_handle_t *              handle);

globus_result_t globus_cred_handle_attrs_init(
    globus_cred_handle_attrs_t *        handle_attrs);

globus_result_t globus_cred_handle_attrs_destroy(
    globus_cred_handle_attrs_t *        handle_attrs);

globus_result_t globus_cred_handle_attrs_copy(
    globus_cred_handle_attrs_t          a,
    globus_cred_handle_attrs_t          b);

/* acquire a credential from a filesystem location. The search order
 * is there to allow people to specify what kind of credential should
 * looked for first. I'm not quite sure whether I like this yet.
 */

globus_result_t globus_cred_read(
    globus_cred_handle_t                handle,
    char *                              desired_subject);

/* Read a credential from a BIO. IE: read cert, read key, read cert
 * chain.
 */

globus_result_t globus_cred_read_bio(
    globus_cred_handle_t                handle,
    BIO *                               bio);

/* Write a credential to a BIO. IE: write cert_chain, write key, write
 * cert. 
 */

globus_result_t globus_cred_write(
    globus_cred_handle_t                handle
    BIO *                               bio);

/* Utility function that will write the credential to the standard
 * proxy file.
 */

globus_result_t globus_cred_write_proxy(
    globus_cred_handle_t                handle);

/* Determine whether the credential structure contains a proxy */

globus_result_t globus_cred_is_proxy(
    globus_cred_handle_t                handle);

/* If we can, walk the cert chain and make sure that the credential is
 * ok. Might also check that all proxy certs are wellformed.
 */

globus_result_t globus_cred_verify(
    globus_cred_handle_t                handle);


/* allows setting the subject name prior to acquiring the cred. If the
 * subject name is set in this manner cred_read should try to acquire
 * the credential corresponding to this subject name.
 */

globus_result_t globus_cred_set_subject_name(
    globus_cred_handle_t                handle,
    char *                              subject_name);

/*
 * Returns the subject name of the cert. Other accessor functions for
 * fields in the cert should probably be added. These function would
 * be almost pure duplication of stuff that is in openssl. Do we want
 * to do this or just let the user of this API extract the X509
 * structure and deal with it directly?
 *
 */

globus_result_t globus_cred_get_subject_name(
    globus_cred_handle_t                handle,
    char **                             subject_name);


/* not sure whether I like the {set,get}_{cert,key,cert_chain} functions and
 * I'm not sure that we actually need them.
 */


globus_result_t globus_cred_set_cert(
    globus_cred_handle_t                handle,
    X509 *                              cert);

globus_result_t globus_cred_set_key(
    globus_cred_handle_t                handle,
    EVP_KEY *                           key);

globus_result_t globus_cred_set_cert_chain(
    globus_cred_handle_t                handle,
    STACK_OF(X509) *                    cert_chain);

globus_result_t globus_cred_get_cert(
    globus_cred_handle_t                handle,
    X509 **                             cert);

globus_result_t globus_cred_get_key(
    globus_cred_handle_t                handle,
    EVP_KEY **                          key);

globus_result_t globus_cred_get_cert_chain(
    globus_cred_handle_t                handle,
    STACK_OF(X509) **                   cert_chain);

globus_result_t globus_cred_handle_attrs_set_ca_cert_file(
    globus_cred_handle_attrs_t          handle_attrs,
    char *                              ca_cert_file);


globus_result_t globus_cred_handle_attrs_get_ca_cert_file(
    globus_cred_handle_attrs_t          handle_attrs,
    char **                             ca_cert_file);

globus_result_t globus_cred_handle_attrs_set_ca_cert_dir(
    globus_cred_handle_attrs_t          handle_attrs,
    char *                              ca_cert_dir);


globus_result_t globus_cred_handle_attrs_get_ca_cert_dir(
    globus_cred_handle_attrs_t          handle_attrs,
    char **                             ca_cert_dir);


globus_result_t globus_cred_handle_attrs_set_proxy_file(
    globus_cred_handle_attrs_t          handle_attrs,
    char *                              proxy_file);


globus_result_t globus_cred_handle_attrs_get_proxy_file(
    globus_cred_handle_attrs_t          handle_attrs,
    char **                             proxy_file);

globus_result_t globus_cred_handle_attrs_set_cert_file(
    globus_cred_handle_attrs_t          handle_attrs,
    char *                              cert_file);


globus_result_t globus_cred_handle_attrs_get_cert_file(
    globus_cred_handle_attrs_t          handle_attrs,
    char **                             cert_file);

globus_result_t globus_cred_handle_attrs_set_key_file(
    globus_cred_handle_attrs_t          handle_attrs,
    char *                              key_file);


globus_result_t globus_cred_handle_attrs_get_key_file(
    globus_cred_handle_attrs_t          handle_attrs,
    char **                             key_file);

globus_result_t globus_cred_handle_attrs_set_search_order(
    globus_cred_handle_attrs_t          handle_attrs,
    globus_cred_type_t                  search_order[]);/*{PROXY,USER,HOST}*/


globus_result_t globus_cred_handle_attrs_get_search_order(
    globus_cred_handle_attrs_t          handle_attrs,
    globus_cred_type_t *                search_order[]);/*{PROXY,USER,HOST}*/









