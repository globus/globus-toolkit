struct globus_l_proxy_req_handle_s;

typedef struct globus_l_proxy_req_handle_s * globus_proxy_req_handle_t

typedef struct globus_l_proxy_req_handle_s
{
    EVP_KEY *                           proxy_key;
    globus_l_proxy_req_handle_attrs_t * attrs;
}
globus_l_proxy_req_handle_t;

struct globus_l_proxy_req_handle_attrs_s;

typedef struct globus_l_proxy_req_handle_attrs_s * globus_proxy_req_handle_attrs_t

typedef struct globus_l_proxy_req_handle_attrs_s
{
    PROXYCERTINFO *                     proxy_cert_info;    
}
globus_l_proxy_req_handle_attrs_t;




globus_result_t globus_proxy_req_handle_init(
    globus_proxy_req_handle_t *             handle,
    globus_proxy_req_handle_attrs_t         handle_attrs);

globus_result_t globus_proxy_req_handle_destroy(
    globus_proxy_req_handle_t *             handle);

globus_result_t globus_proxy_req_handle_attrs_init(
    globus_proxy_req_handle_attrs_t *       handle_attrs);

globus_result_t globus_proxy_req_handle_attrs_destroy(
    globus_proxy_req_handle_attrs_t *       handle_attrs);

globus_result_t globus_proxy_req_handle_attrs_copy(
    globus_proxy_req_handle_attrs_t         a,
    globus_proxy_req_handle_attrs_t         b);


/* create X509_REQ and write it to the supplied bio */

globus_result_t globus_proxy_create_req(
    globus_proxy_req_handle_t           handle,
    BIO *                               output_bio);

/* read X509_REQ from  input_bio, sign it using the supplied
 * issuer_credential and write the resulting cert + cert_chain to
 * output_bio
 */

globus_result_t globus_proxy_sign_req(
    globus_proxy_req_handle_t           handle,
    globus_cred_handle_t                issuer_credential,
    BIO *                               input_bio,
    BIO *                               output_bio);

/* read cert and cert chain from bio and combine them with the private
 * key into a credential structure.
 */

globus_result_t globus_proxy_create_req(
    globus_proxy_req_handle_t           handle,
    globus_cred_handle_t *              proxy_credential,
    BIO *                               input_bio);

globus_result_t globus_proxy_req_handle_attrs_set_policy(
    globus_proxy_req_handle_attrs_t     handle_attrs,
    unsigned char *                     policy,
    int                                 policy_NID);

globus_result_t globus_proxy_req_handle_attrs_get_policy(
    globus_proxy_req_handle_attrs_t     handle_attrs,
    unsigned char **                    policy,
    int *                               policy_NID);

globus_result_t globus_proxy_req_handle_attrs_set_group(
    globus_proxy_req_handle_attrs_t     handle_attrs,
    unsigned char *                     group,
    int                                 attached);

globus_result_t globus_proxy_req_handle_attrs_get_group(
    globus_proxy_req_handle_attrs_t     handle_attrs,
    unsigned char **                    group,
    int *                               attached);

globus_result_t globus_proxy_req_handle_attrs_set_pathlen(
    globus_proxy_req_handle_attrs_t     handle_attrs,
    int                                 pathlen);

globus_result_t globus_proxy_req_handle_attrs_get_pathlen(
    globus_proxy_req_handle_attrs_t     handle_attrs,
    int *                               pathlen);


