#include "gaa.h"
#include "gssapi.h"
#define MY_MECHNAME "gss"

/** @defgroup gaa_gss_generic "gaa generic gss callbacks"
 */

/** gaa_gss_generic_cred_pull()
 *
 * @ingroup gaa_gss_generic
 *
 * Pulls gss credentials (sets only the principal name).  This function
 * is meant to be used as a cred_pull callback in GAA.
 *
 * @param gaa 
 *        input gaa pointer
 * @param sc
 *        input/output security context -- credentials in the sc are looked
 *        up in the credential map; if mapped entries are found, they're added
 *        to the sc.
 * @param which
 *        this argument is ignored
 * @param params
 *        input -- should be a (gss_ctx_id_t *) pointer to a gss security
 *        context
 *
 * @retval GAA_S_SUCCESS
 *        success
 */
gaa_status
gaa_gss_generic_cred_pull(gaa_ptr		gaa,
			gaa_sc_ptr	sc,
			gaa_cred_type	which,
			void *		params)
{
    gaa_status status = GAA_S_SUCCESS;
    gss_ctx_id_t context;
    gaa_cred *cred = 0;

    if (params == 0)
	return(GAA_S_SUCCESS);

    context = *(gss_ctx_id_t *)params;
    if ((status = gaa_new_cred(gaa, sc, &cred, MY_MECHNAME, context,
			       GAA_IDENTITY, 1, 0)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_add_cred(gaa, sc, cred));
}

/** gaa_gss_generic_cred_eval()
 *
 * @ingroup gaa_gss_generic
 *
 * Evaluate a gss credential (take gss context and translates it
 * into a gaa credential).  This function is meant to be used as a cred_eval
 * callback in gaa.
 *
 * @param gaa 
 *        input gaa pointer
 * @param sc
 *        this argument is ignored.
 * @param cred
 *        input/output credential (an unevaluated credential is input
 *        and will be filled in if appropriate).
 * @param raw
 *        input "raw" credential -- a (gss_ctx_id_t) gss security context.
 * @param cred_type
 *        this argument is ignored
 * @param params
 *        (char **) pointer to name of defining authority to use
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_CRED_EVAL_FAILURE
 *         problem evaluating raw gss cred.
 */
gaa_status
gaa_gss_generic_cred_eval(gaa_ptr		gaa,
			gaa_sc_ptr	sc,
			gaa_cred *	cred,
			void *		raw,
			gaa_cred_type	cred_type,
			void *		params)
{
    gaa_status				status;
    OM_uint32				majstat;
    OM_uint32				minstat;
    gss_name_t				src_name;
    gss_ctx_id_t			context;
    gss_OID				mech_type;
    gss_buffer_desc			nbuf;
    gss_buffer_t			namebuf = &nbuf;
    gaa_sec_attrb *			principal;
    char **				authp = (char **)params;

    if (cred == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if (authp == 0)
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));

    context = (gss_ctx_id_t)raw;
    if ((majstat = gss_inquire_context(&minstat, context, &src_name,
				       0, 0, &mech_type, 0, 0,
				       0)) != GSS_S_COMPLETE)
	return(GAA_STATUS(GAA_S_CRED_EVAL_FAILURE, 0));
    if ((majstat = gss_display_name(&minstat, src_name, namebuf,
				    0)) != GSS_S_COMPLETE)
	return(GAA_STATUS(GAA_S_CRED_EVAL_FAILURE, 0));

    if ((status = gaa_new_sec_attrb(&(cred->principal), GAA_IDENTITY,
				   *authp, namebuf->value)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_new_identity_info(gaa, &(cred->info.id_info))) != GAA_S_SUCCESS)
	return(status);
    cred->mech_spec_cred = context;
    cred->type = cred->principal->type;
    return(GAA_S_SUCCESS);
}

/** gaaglobus_map_cred_verify()
 *
 * @ingroup gaa_gss_generic
 *
 * Verify a gss credential.  Make sure the gss context found in the
 * credential is valid and matches the credential's principal name.
 * This function is meant to be used as a cred_verify callback in gaa.
 *
 * @param cred
 *        Credential to verify.
 * @param params
 *        (char **) pointer to credential authority to expect.
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INVALID_ARG
 *         credential is null or missing required fields.
 * @retval GAA_S_CRED_VERIFY_FAILURE
 *         problem with raw credential (gss context)
 */
gaa_status
gaa_gss_generic_cred_verify(gaa_cred *	cred,
			  void *	params)
{
    gss_ctx_id_t			context;
    gss_OID				mech_type;
    OM_uint32				majstat;
    OM_uint32				minstat;
    OM_uint32				lifetime;
    gss_name_t				src_name;
    gss_buffer_desc			nbuf;
    gss_buffer_t			namebuf = &nbuf;
    char **				authp = (char **)params;

    if (authp == 0)
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    if (cred == 0 || cred->principal == 0 || cred->principal->authority == 0 ||
	strcmp(cred->principal->authority, *authp) ||
	cred->principal->value == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    if ((context = (gss_ctx_id_t)cred->mech_spec_cred) == 0)
	return(GAA_STATUS(GAA_S_CRED_VERIFY_FAILURE, 0));
    if ((majstat = gss_inquire_context(&minstat, context, &src_name,
				       0, &lifetime, &mech_type, 0, 0,
				       0)) != GSS_S_COMPLETE)
	return(GAA_STATUS(GAA_S_CRED_VERIFY_FAILURE, 0));
    if (lifetime == 0)
    {
	gaa_set_callback_err("GSS context has expired");
	return(GAA_STATUS(GAA_S_CRED_VERIFY_FAILURE, 0));
    }
    if ((majstat = gss_display_name(&minstat, src_name, namebuf,
				    0)) != GSS_S_COMPLETE)
	return(GAA_STATUS(GAA_S_CRED_VERIFY_FAILURE, 0));
    if (namebuf->value == 0 || strcmp(cred->principal->value, namebuf->value))
	return(GAA_STATUS(GAA_S_CRED_VERIFY_FAILURE, 0));
    return(GAA_S_SUCCESS);
}
