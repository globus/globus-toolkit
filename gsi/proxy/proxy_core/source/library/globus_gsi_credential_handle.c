#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_credential_handle.c
 * @author Sam Meder, Sam Lang

 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gsi_credential.h"

/**
 * @name Initialize
 */
/* @{ */
/**
 * Initialize a GSI Credential handle.
 * @ingroup globus_gsi_credential_handle
 *
 * Initialize a credential handle which can be used in subsequent
 * operations.  The handle may only be used in once sequence of 
 * operations at a time.
 *
 * @param handle
 *        to be initialized by the init function. This parameter
 *        can be NULL when passed in
 * @param handle_attrs
 *        immutable attributes for the handle, which get set
 *        initially and exist throughout the life of the handle.
 * @return
 *        an error if the handle could not be initialized, GLOBUS_SUCCESS
 *        otherwise
 */
globus_result_t globus_gsi_cred_handle_init(
    globus_gsi_cred_handle_t *          handle,
    globus_gsi_cred_handle_attrs_t      handle_attrs)
{
    if(handle != NULL)
    {
        return GLOBUS

globus_result_t globus_gsi_cred_handle_destroy(
    globus_gsi_cred_handle_t *          handle);

globus_result_t globus_gsi_cred_handle_attrs_init(
    globus_gsi_cred_handle_attrs_t *    handle_attrs);

globus_result_t globus_gsi_cred_handle_attrs_destroy(
    globus_gsi_cred_handle_attrs_t *    handle_attrs);

globus_result_t globus_gsi_cred_handle_attrs_copy(
    globus_gsi_cred_handle_attrs_t      a,
    globus_gsi_cred_handle_attrs_t      b);

/* acquire a credential from a filesystem location. The search order
 * is there to allow people to specify what kind of credential should
 * looked for first. I'm not quite sure whether I like this yet.
 */

globus_result_t globus_gsi_cred_read(
    globus_gsi_cred_handle_t            handle,
    char *                              desired_subject);

/* Read a credential from a BIO. IE: read cert, read key, read cert
 * chain.
 */

globus_result_t globus_gsi_cred_read_bio(
    globus_gsi_cred_handle_t            handle,
    BIO *                               bio);

/* Write a credential to a BIO. IE: write cert_chain, write key, write
 * cert. 
 */

globus_result_t globus_gsi_cred_write(
    globus_gsi_cred_handle_t            handle,
    BIO *                               bio);

/* Utility function that will write the credential to the standard
 * proxy file.
 */

globus_result_t globus_gsi_cred_write_proxy(
    globus_gsi_cred_handle_t            handle);

/* Determine whether the credential structure contains a proxy */

globus_result_t globus_gsi_cred_is_proxy(
    globus_gsi_cred_handle_t            handle);

/* If we can, walk the cert chain and make sure that the credential is
 * ok. Might also check that all proxy certs are wellformed.
 */

globus_result_t globus_gsi_cred_verify(
    globus_gsi_cred_handle_t            handle);


/* allows setting the subject name prior to acquiring the cred. If the
 * subject name is set in this manner cred_read should try to acquire
 * the credential corresponding to this subject name.
 */

globus_result_t globus_gsi_cred_set_subject_name(
    globus_gsi_cred_handle_t            handle,
    char *                              subject_name);

/*
 * Returns the subject name of the cert. Other accessor functions for
 * fields in the cert should probably be added. These function would
 * be almost pure duplication of stuff that is in openssl. Do we want
 * to do this or just let the user of this API extract the X509
 * structure and deal with it directly?
 *
 */

globus_result_t globus_gsi_cred_get_subject_name(
    globus_gsi_cred_handle_t            handle,
    char **                             subject_name);


/* not sure whether I like the {set,get}_{cert,key,cert_chain} functions and
 * I'm not sure that we actually need them.
 */


globus_result_t globus_gsi_cred_set_cert(
    globus_gsi_cred_handle_t            handle,
    X509 *                              cert);

globus_result_t globus_gsi_cred_set_key(
    globus_gsi_cred_handle_t            handle,
    EVP_PKEY *                          key);

globus_result_t globus_gsi_cred_set_cert_chain(
    globus_gsi_cred_handle_t            handle,
    STACK_OF(X509) *                    cert_chain);

globus_result_t globus_gsi_cred_get_cert(
    globus_gsi_cred_handle_t            handle,
    X509 **                             cert);

globus_result_t globus_gsi_cred_get_key(
    globus_gsi_cred_handle_t            handle,
    EVP_PKEY **                         key);

globus_result_t globus_gsi_cred_get_cert_chain(
    globus_gsi_cred_handle_t            handle,
    STACK_OF(X509) **                   cert_chain);

globus_result_t globus_gsi_cred_handle_attrs_set_ca_cert_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              ca_cert_file);


globus_result_t globus_gsi_cred_handle_attrs_get_ca_cert_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             ca_cert_file);

globus_result_t globus_gsi_cred_handle_attrs_set_ca_cert_dir(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              ca_cert_dir);


globus_result_t globus_gsi_cred_handle_attrs_get_ca_cert_dir(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             ca_cert_dir);


globus_result_t globus_gsi_cred_handle_attrs_set_proxy_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              proxy_file);


globus_result_t globus_gsi_cred_handle_attrs_get_proxy_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             proxy_file);

globus_result_t globus_gsi_cred_handle_attrs_set_cert_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              cert_file);


globus_result_t globus_gsi_cred_handle_attrs_get_cert_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             cert_file);

globus_result_t globus_gsi_cred_handle_attrs_set_key_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char *                              key_file);


globus_result_t globus_gsi_cred_handle_attrs_get_key_file(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    char **                             key_file);

globus_result_t globus_gsi_cred_handle_attrs_set_search_order(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    globus_gsi_cred_type_t              search_order[]); /*{PROXY,USER,HOST}*/


globus_result_t globus_gsi_cred_handle_attrs_get_search_order(
    globus_gsi_cred_handle_attrs_t      handle_attrs,
    globus_gsi_cred_type_t *            search_order[]);/*{PROXY,USER,HOST}*/

