/**********************************************************************

gssutils.c

Description:
	Routines used internally by this implementation of GSSAPI

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <string.h>
#include <stdlib.h>

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/**********************************************************************
Function: gss_copy_name_to_name() 

Description:
	Copy a gssapi name to a new name. This should be
	 gss_duplicate_name

Parameters:
	pointer to a pointer to a name descriptor
    pointer to source name descriptor
   
Returns:
**********************************************************************/

OM_uint32 
gss_copy_name_to_name
(OM_uint32 *                    minor_status,
 gss_name_desc** 				output,
 const gss_name_desc* 			input)
{
	gss_name_desc* output_name ;
	X509_NAME * x509n;

	output_name = (gss_name_desc *) malloc(sizeof(gss_name_desc));
	if (output_name == NULL) {
		GSSerr(GSSERR_F_NAME_TO_NAME,ERR_R_MALLOC_FAILURE);
		return GSS_S_FAILURE ;
	}
 
	x509n = X509_NAME_dup(input->x509n);
 	if (x509n == NULL) {
		return GSS_S_FAILURE;
	}   

	output_name->name_oid = input->name_oid;

	output_name->x509n = x509n;
	*output = output_name;
 
	*minor_status = 0;
	return  GSS_S_COMPLETE;
}

/**********************************************************************
Function:  gss_create_and_fill_context

Description:
	Called by init_sec_context and accept_sec_context to 
	setup the initial context. This includes establishing the
	SSL session control blocks

Parameters:
   
Returns:
**********************************************************************/

OM_uint32 
gss_create_and_fill_context
(OM_uint32  * minor_status,
 gss_ctx_id_desc** context_handle_P,
 gss_cred_id_desc* cred_handle,
 const gss_cred_usage_t cred_usage,
 OM_uint32 req_flags)
{

	OM_uint32 major_status = GSS_S_COMPLETE;
	gss_ctx_id_desc* context = NULL;
	gss_cred_id_t output_cred_handle= NULL;
	int j;

	context = (gss_ctx_id_desc*) malloc(sizeof(gss_ctx_id_desc)) ;
	if (context == NULL) {
		GSSerr(GSSERR_F_CREATE_FILL,ERR_R_MALLOC_FAILURE);
		return GSS_S_FAILURE;
	}
	*context_handle_P = context;
  
	context->target_name = NULL;
	context->source_name = NULL; 
	context->cred_handle = (gss_cred_id_desc*) NULL ;
	context->ret_flags = 0;
	context->req_flags = req_flags;
	context->gs_ssl = NULL;
	context->gs_rbio = NULL;
	context->gs_wbio = NULL;
	context->gs_sslbio = NULL;
	context->gs_state = GS_CON_ST_HANDSHAKE;
	context->dpkey = NULL;
	context->dcert = NULL;
	context->locally_initiated = (cred_usage == GSS_C_INITIATE);

	proxy_verify_ctx_init(&(context->pvxd));
	proxy_verify_init(&(context->pvd), &(context->pvxd));

	if (cred_handle == GSS_C_NO_CREDENTIAL) {

		major_status = gss_acquire_cred(minor_status,
							GSS_C_NO_NAME,
							GSS_C_INDEFINITE,
							GSS_C_NO_OID_SET,
							cred_usage,
							&output_cred_handle,
							NULL,
							NULL) ;
		if (GSS_ERROR(major_status)) {
			return major_status ;
		}

#ifdef DEBUG
		fprintf(stderr,"Passed gss_acquire_cred\n");
#endif
		context->cred_handle = output_cred_handle;
		context->cred_obtained = 1 ;
	} else {
		context->cred_handle =  cred_handle ;
		context->cred_obtained = 0 ;
	}

	if (cred_usage == GSS_C_INITIATE) {
		major_status = gss_copy_name_to_name(minor_status,
								&context->source_name,
								context->cred_handle->globusid) ;
	} else {
		major_status = gss_copy_name_to_name(minor_status,
								&context->target_name,
								context->cred_handle->globusid) ;
	}

	/* Set the verify callback to test our proxy 
	 * policies. 
	 * The SSL_set_verify does not appear to work as 
	 * expected. The SSL_CTX_set_verify does more,
	 * it also sets the X509_STORE_set_verify_cb_func
	 * which is what we want. This occurs in both 
	 * SSLeay 0.8.1 and 0.9.0 
	 */

	if (context->cred_handle->pcd->certdir) {
		context->pvxd.certdir = strdup(context->cred_handle->pcd->certdir);
	}

	SSL_CTX_set_verify(context->cred_handle->pcd->gs_ctx,
		SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		proxy_verify_callback);

#ifdef DEBUG
	fprintf(stderr,"SSL_CTX_set_app_data to pvd %p\n",
			context->pvd);
#endif
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
	/*
	 * for now we will accept any purpose, as Globus does
     * nor have any restrictions such as this is an SSL client
	 * or SSL server. Globus certificates are not required
	 * to have these fields set today.
	 * DEE - Need  to look at this in future if we use 
	 * certificate extensions...  
	 */
	SSL_CTX_set_purpose(context->cred_handle->pcd->gs_ctx,
			X509_PURPOSE_ANY);
#endif

	/* setup the SSL  for the gs_shuffle routine */
  
        context->gs_ssl = SSL_new(context->cred_handle->pcd->gs_ctx);
	if (context->gs_ssl == NULL) {
		return GSS_S_FAILURE;
	}

	if (cred_usage == GSS_C_ACCEPT) {
		SSL_set_ssl_method(context->gs_ssl,SSLv23_method());
		SSL_set_options(context->gs_ssl,SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1);
	} else {
		SSL_set_ssl_method(context->gs_ssl,SSLv3_method());
	}

	SSL_set_ex_data(context->gs_ssl, PVD_SSL_EX_DATA_IDX, 
			(char *)&(context->pvd)); 

	/*
	 * If accept and caller set GSS_C_CONF_FLAG, remove
	 * the NULL encryptions.    
	 * If initiate and caller did not set the GSS_C_CONF_FLAG
	 * then move NULLs to begining.
	 * else, it is already set in the end, so nothing to do.
	 */

	if (cred_usage == GSS_C_ACCEPT) {
		if (context->req_flags & GSS_C_CONF_FLAG) {
			context->gs_ssl->cipher_list = sk_SSL_CIPHER_dup(
				context->cred_handle->pcd->gs_ctx->cipher_list);
	 		context->gs_ssl->cipher_list_by_id = sk_SSL_CIPHER_dup(
				context->cred_handle->pcd->gs_ctx->cipher_list_by_id);
		}
		if (context->gs_ssl->cipher_list_by_id 
			&& context->gs_ssl->cipher_list) {
		  for(j=0;j<context->cred_handle->pcd->num_null_enc_ciphers;j++) {
			/* need to delete_ptr to get the same cipher, if not at end */
			  sk_SSL_CIPHER_delete_ptr(context->gs_ssl->cipher_list_by_id,
				sk_SSL_CIPHER_pop(context->gs_ssl->cipher_list));
			}
		}
	} else {
		if (!(context->req_flags & GSS_C_CONF_FLAG)) {
			context->gs_ssl->cipher_list = sk_SSL_CIPHER_dup(
				context->cred_handle->pcd->gs_ctx->cipher_list);
			context->gs_ssl->cipher_list_by_id = sk_SSL_CIPHER_dup(
				context->cred_handle->pcd->gs_ctx->cipher_list_by_id);
		}
		if (context->gs_ssl->cipher_list) {
			for(j=0;j<context->cred_handle->pcd->num_null_enc_ciphers;j++) {
				sk_SSL_CIPHER_unshift(context->gs_ssl->cipher_list,
					sk_SSL_CIPHER_pop(context->gs_ssl->cipher_list));
			}
		}
	}

#ifdef DEBUG
	fprintf(stderr,"SSL is at %p\n",context->gs_ssl);
	fprintf(stderr,"SSL_set_app_data to pvd %p\n",
			context->pvd);
#endif

	
    
	if ((context->gs_rbio = BIO_new(BIO_s_mem())) == NULL) {
		return GSS_S_FAILURE;
	}

	if ((context->gs_wbio = BIO_new(BIO_s_mem())) == NULL) {
		return GSS_S_FAILURE;
	}

	if ((context->gs_sslbio = BIO_new(BIO_f_ssl())) == NULL) {
		return GSS_S_FAILURE;
	}
#ifdef DEBUG
	fprintf(stderr,"Setting the SSL state\n");
#endif

	if ( cred_usage == GSS_C_INITIATE) { 
		SSL_set_connect_state(context->gs_ssl);
	} else {
		SSL_set_accept_state(context->gs_ssl);
	}

	SSL_set_bio(context->gs_ssl,
				context->gs_rbio,
				context->gs_wbio);

	BIO_set_ssl(context->gs_sslbio, 
				context->gs_ssl, 
				BIO_NOCLOSE);

#ifdef DEBUG
	{
		char buff[256];
		int i;
		STACK *sk;

		fprintf(stderr,"Ciphers available:\n");
		sk=(STACK *)SSL_get_ciphers(context->gs_ssl);
		 for (i=0; i<sk_num(sk); i++) {
			SSL_CIPHER_description((SSL_CIPHER *)sk_value(sk,i),
					buff,256);
			fprintf(stderr,buff);
		 }
	}
#endif

	return GSS_S_COMPLETE;
}


/**********************************************************************
Function:  gs_put_token()

Description:
	Called by init_sec_context and accept_sec_context.
	An input token is placed in the SSL read BIO

Parameters:
   
Returns:
**********************************************************************/
OM_uint32
gs_put_token 
(OM_uint32 *                    minor_status,
 const gss_ctx_id_desc*         context_handle,
 const gss_buffer_t             input_token)
{

	/* add any input data onto the input for the SSL BIO */

	*minor_status = 0;
#ifdef DEBUG
	fprintf(stderr,"input token: len=%d\n",input_token->length);
#endif
	if (input_token->length > 0) {
		BIO_write(context_handle->gs_rbio,
		input_token->value,
		input_token->length);
#ifdef DEBUG
		BIO_dump(context_handle->cred_handle->gs_bio_err,
		input_token->value,
		input_token->length);
#endif
	} else {
		return GSS_S_DEFECTIVE_TOKEN;
	}
	return GSS_S_COMPLETE;
}


/**********************************************************************
Function:  gs_get_token()

Description:
	Called by init_sec_context and accept_sec_context.
	An output token is created from the  SSL write BIO,

Parameters:
   
Returns:
**********************************************************************/
OM_uint32
gs_get_token 
(OM_uint32 *                    minor_status,
 const gss_ctx_id_desc*         context_handle,
 const gss_buffer_t             output_token)
{

	*minor_status = 0;
	/* make out token */
	output_token->length = BIO_pending(context_handle->gs_wbio);
	if (output_token->length > 0) {
		output_token->value = (char *) malloc(output_token->length);
		if (output_token->value == NULL) {
			output_token->length = 0 ;
			GSSerr(GSSERR_F_GS_HANDSHAKE,ERR_R_MALLOC_FAILURE);
			return GSS_S_FAILURE;
		}
		BIO_read(context_handle->gs_wbio,
		output_token->value,
		output_token->length);
#ifdef DEBUG
		fprintf(stderr,"output token: len=%d\n",output_token->length);
#endif
#ifdef DEBUG
		BIO_dump(context_handle->cred_handle->gs_bio_err,
				output_token->value,
				output_token->length);
#endif
	} else {
		output_token->value = NULL;
	}
	return GSS_S_COMPLETE;
}



/**********************************************************************
Function:  gs_read()

Description:
	Called by init_sec_context and accept_sec_context.
	Attempt to read from the SSL BIO

Parameters:
   
Returns:
**********************************************************************/

OM_uint32    
gs_read 
(OM_uint32 *                    minor_status,
 const gss_ctx_id_desc*         context_handle,
 void *data,
 int length)
{
	OM_uint32 major_status = 0;
	int rc;

	*minor_status = 0;
	/*
	 * do the BIO_do_handshake which may produce output,
	 * and endup waiting for input
	 * when completed without error, connection established
	 */
	rc = BIO_read(context_handle->gs_sslbio,data,length);
	if (rc <= 0) {
		if (!BIO_should_retry(context_handle->gs_sslbio) || 
			!BIO_should_read(context_handle->gs_sslbio)) {

			/* problem! */
			major_status = GSS_S_DEFECTIVE_CREDENTIAL ;
		}
	}

	if (!GSS_ERROR(major_status)) {
		if (rc > 0) {
			major_status = GSS_S_COMPLETE ; 
#ifdef DEBUG
			fprintf(stderr,"SSL handshake finished\n");
#endif
		} else {
			major_status = GSS_S_CONTINUE_NEEDED ;
		}
	}
  
	return major_status ;
}
/**********************************************************************
Function:  gs_write()

Description:
	Called by init_sec_context and accept_sec_context.
	Write to the SSL BIO

Parameters:
   
Returns:
**********************************************************************/

OM_uint32    
gs_write 
(OM_uint32 *                    minor_status,
 const gss_ctx_id_desc*         context_handle)
{
	OM_uint32 major_status = 0;
	int rc;

	*minor_status = 0;
	/*
	 * do the BIO_do_handshake which may produce output,
	 * and endup waiting for input
	 * when completed without error, connection established
	 */
	rc = BIO_do_handshake(context_handle->gs_sslbio);
	if (rc <= 0) {
		if (!BIO_should_retry(context_handle->gs_sslbio) || 
			!BIO_should_read(context_handle->gs_sslbio)) {

			/* problem! */
			major_status = GSS_S_DEFECTIVE_CREDENTIAL ;
		}
	}

	if (!GSS_ERROR(major_status)) {
		if (rc > 0) {
			major_status = GSS_S_COMPLETE ; 
#ifdef DEBUG
			fprintf(stderr,"SSL handshake finished\n");
#endif
		} else {
			major_status = GSS_S_CONTINUE_NEEDED ;
		}
	}
  
	return major_status ;
}

/**********************************************************************
Function:  gs_handshake

Description:
	Called by init_sec_context and accept_sec_context.
 	the BIO_handshake is done again which causes the SSL 
	session to start or continue its handshake process,
	and when it waits return. 

Parameters:
   
Returns:
**********************************************************************/

OM_uint32    
gs_handshake 
(OM_uint32 *                    minor_status,
 gss_ctx_id_desc*               context_handle)
{
	OM_uint32 major_status = 0;
	int rc;

	*minor_status = 0;
	/*
	 * do the BIO_do_handshake which may produce output,
	 * and endup waiting for input
	 * when completed without error, connection established
	 */
	rc = BIO_do_handshake(context_handle->gs_sslbio);
	if (rc <= 0) {
		if (!BIO_should_retry(context_handle->gs_sslbio) || 
			!BIO_should_read(context_handle->gs_sslbio)) {

			/* problem! */
#ifdef DEBUG
			fprintf(stderr,"disp=%d,level=%d,desc=%d,left=%d\n",
				context_handle->gs_ssl->s3->alert_dispatch,
				context_handle->gs_ssl->s3->send_alert[0],
				context_handle->gs_ssl->s3->send_alert[1],
				context_handle->gs_ssl->s3->wbuf.left);
			
			fprintf(stderr,"SSL_get_error = %d\n",
			 SSL_get_error(context_handle->gs_ssl, rc));

			fprintf(stderr,"shutdown=%d\n",
			SSL_get_shutdown(context_handle->gs_ssl));
#endif
			GSSerr(GSSERR_F_GS_HANDSHAKE,GSSERR_R_HANDSHAKE);
			major_status = GSS_S_DEFECTIVE_CREDENTIAL ;
		}
	}

	if (!GSS_ERROR(major_status)) {
		if (rc > 0) {
			major_status = GSS_S_COMPLETE ; 

			/*
			 * Set  GSS_C_CONF_FLAG if cipher uses encryption
			 * which is at least 56 bit. SSL defines a number
			 * of different levels, we need to map to a single GSS
			 * flag. See the s3_lib.c for list of ciphers. 
			 * This could be changed to SSL_MIDUM or SSL_HIGH 
			 * if a site wants higher protection. 
			 */

#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
			if ((context_handle->gs_ssl->session->cipher->algo_strength
					& SSL_STRONG_MASK) >= SSL_LOW) {
				context_handle->ret_flags |= GSS_C_CONF_FLAG;
			}
#else
			if ((context_handle->gs_ssl->session->cipher->algorithms
					& SSL_STRONG_MASK) >= SSL_LOW) {
				context_handle->ret_flags |= GSS_C_CONF_FLAG;
			}
#endif

#ifdef DEBUG
			{
				char buff[256];

				fprintf(stderr,"SSL handshake finished\n");
				fprintf(stderr,"cred_usage=%d\n",
						context_handle->cred_handle->cred_usage);
				fprintf(stderr,"Cipher being used:\n");
				SSL_CIPHER_description(
					context_handle->gs_ssl->session->cipher,
					buff,256);
				fprintf(stderr,buff);
			}

#endif
		} else {
			major_status = GSS_S_CONTINUE_NEEDED ;
		}
	}
  
	return major_status ;
}

/**********************************************************************
Function:  gs_retrieve_peer

Description:
	Called after the handshake has completed sucessfully,
	and gets the subject name, so it can be returned to the
	call of the GSSAPI init_sec_context or accept_sec_context. 

Parameters:
   
Returns:
**********************************************************************/


OM_uint32
gs_retrieve_peer
(OM_uint32 *                    minor_status,
 gss_ctx_id_desc *              context_handle,
 const gss_cred_usage_t         cred_usage) 
{
	gss_name_desc * outname;
	X509 * peer = NULL;
	X509_NAME * subject;

	*minor_status = 0;
	if (context_handle->gs_ssl->session) {
		peer = context_handle->gs_ssl->session->peer;
	}
	if (peer == NULL) {
		return GSS_S_FAILURE;
	}

	subject = X509_NAME_dup(X509_get_subject_name(peer));

#ifdef DEBUG
	{
		char *s;
		s = X509_NAME_oneline(subject,NULL,0);
		fprintf(stderr,"gs_retrieve_peer: X509 subject: %s\n", s);
		free(s);
	}
#endif

	/*
	 * drop all the /CN=proxy entries 
	 */
	proxy_get_base_name(subject);

	outname = ( gss_name_desc *)malloc(sizeof(gss_name_desc));
	if (outname == NULL) {
		GSSerr(GSSERR_F_GS_RETRIVE_PEER,ERR_R_MALLOC_FAILURE);
		return GSS_S_FAILURE;
	}
	outname->name_oid =  GSS_C_NO_OID;
	outname->x509n = subject;

#ifdef DEBUG
	{ 
		char * s;
		s = X509_NAME_oneline(subject,NULL,0);
		fprintf(stderr,"X509 subject after proxy : %s\n", s);
		free(s);
	}
#endif
  
	if (cred_usage == GSS_C_INITIATE) {
		context_handle->target_name = outname;
	} else {
		context_handle->source_name = outname;
	}
	return GSS_S_COMPLETE ;
}

/**********************************************************************
Function:  gss_create_and_fill_cred

Description:
	Called by acquire_cred and accept_sec_context for a delegate.
	Setup the credential including the SSL_CTX

Parameters:
   
Returns:
**********************************************************************/

OM_uint32 
gss_create_and_fill_cred
(OM_uint32  * minor_status,
 gss_cred_id_t *           output_cred_handle_P,
 const gss_cred_usage_t cred_usage,
 X509   * ucert,
 EVP_PKEY	* upkey,
 STACK_OF(X509)  * cert_chain,
 BIO * bp) 
{
    gss_cred_id_desc** output_cred_handle = 
        (gss_cred_id_desc**) output_cred_handle_P ;
  
    OM_uint32 major_status = GSS_S_NO_CRED;
    gss_cred_id_desc* newcred ;
    int status;
	int i;

#ifdef DEBUG
	fprintf(stderr,"gss_create_and_fill_cred\n");
#endif
    *minor_status = 0;

	newcred = (gss_cred_id_desc*) malloc(sizeof(gss_cred_id_desc)) ;
	if (newcred == NULL) {
		GSSerr(GSSERR_F_ACQUIRE_CRED,ERR_R_MALLOC_FAILURE);
		return GSS_S_FAILURE ;
	}
	newcred->cred_usage = cred_usage ;
	newcred->globusid = NULL;
	newcred->gs_bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);

        if (!(newcred->pcd = proxy_cred_desc_new())) {
                GSSerr(GSSERR_F_ACQUIRE_CRED,ERR_R_MALLOC_FAILURE);
                return GSS_S_FAILURE ;
        }

	/* delegated certificate, save in pcd */

	if (ucert) {
		newcred->pcd->ucert = ucert;
	}
	if (upkey) {
		newcred->pcd->upkey = upkey;
	}
	if (cert_chain) {
    		/* Delegated credential is a proxy */
                newcred->pcd->type = CRED_TYPE_PROXY;   
		newcred->pcd->cert_chain = sk_X509_new_null();
		for(i=0;i<sk_X509_num(cert_chain);i++) {
			 sk_X509_insert(newcred->pcd->cert_chain,
			 	X509_dup(sk_X509_value(cert_chain,i)),
				sk_X509_num(cert_chain));
		}
	}


	/*
	 * setup SSLeay environment
	 * This will find the user's cert, key, proxy etc
	 */ 

	if ((status = proxy_init_cred(newcred->pcd, 
			proxy_password_callback_no_prompt, bp)))  {
		if (status == PRXYERR_R_CERT_EXPIERED) { 
			major_status =  GSS_S_CREDENTIALS_EXPIRED;
		}
		goto err;
	}

	/*
	 * The SSLeay when built by default excludes the NULL 
	 * encryption options: #ifdef SSL_ALLOW_ENULL in ssl_ciph.c
	 * Since the user obtains and builds the SSLeay, we have 
	 * no control over how it is built. 
	 *
	 * We have an export licence for this code, and don't
	 * need/want encryption. We will therefore turn off
	 * any encryption by placing the RSA_NULL_MD5 cipher
	 * first. See s3_lib.c ssl3_ciphers[]=  The RSA_NUL_MD5
	 * is the first, but the way to get at it is as  n-1 
	 *
	 * Now that we support encryption, we may still add
	 * RSA_NUL_MD5 but it may be at the begining or end
	 * of the list. This will allow for some compatability. 
	 * (But in this code we will put it last for now.)
	 *
	 * Where, if at all, RSA_NUL_MD5 is added:
	 *
	 *                 |  Initiate     Accept
	 * ----------------------------------------
	 * GSS_C_CONF_FLAG |
	 *     set         |  end        don't add
	 *   notset        |  begining   end
	 *                 ------------------------
	 *
	 * This gives the initiator control over the encryption
	 * but lets the server force encryption.
	 *
	 *                         Acceptor
	 *                   |    yes     no    either
	 * ----------------------------------------------
	 *             yes   |    yes    reject  yes
	 * Initiator   no    |    reject  no     no
	 *             either|    yes     no     no
	 * 
	 * When encryption is selected, the ret_flags will have
	 * ret_flags set with GSS_C_CONF_FLAG. The initiator and
	 * acceptor can then decied if this was acceptable, i.e.
	 * reject the connection. 
	 *                 
	 * 
	 * This method may need to be checked with new versions
	 * of the SSLeay packages. 
	 */ 

	{
		int n;
		int m;
		int i;
		int j;
		SSL_CIPHER * cipher;

		j = 0;
		n = ((*newcred->pcd->gs_ctx->method->num_ciphers))();
		for (i=0; i<n; i++) {
			cipher = (*(newcred->pcd->gs_ctx->method->get_cipher))(i);
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
#define MY_NULL_MASK 0x130021L
#else
#define MY_NULL_MASK 0x830021L
#endif
			if (cipher && 
				((cipher->algorithms & MY_NULL_MASK) == MY_NULL_MASK)) {
				j++;
#ifdef DEBUG
				fprintf(stderr,"adding cipher %d %d\n", i, j);
#endif
		
				sk_SSL_CIPHER_push(
				    newcred->pcd->gs_ctx->cipher_list, cipher);
				sk_SSL_CIPHER_push(
				    newcred->pcd->gs_ctx->cipher_list_by_id, cipher);
			}
		}
		newcred->pcd->num_null_enc_ciphers = j;
	}

	/*
	 * get the globusid, which is the subject name - any proxy entries
	 */

	newcred->globusid = (gss_name_desc*) malloc(sizeof(gss_name_desc)) ;
	if (newcred->globusid == NULL) {
		GSSerr(GSSERR_F_ACQUIRE_CRED,ERR_R_MALLOC_FAILURE);
		goto err;
	}
	newcred->globusid->name_oid = GSS_C_NO_OID;
	newcred->globusid->x509n =
                 X509_NAME_dup(X509_get_subject_name(newcred->pcd->ucert));
	if (newcred->globusid->x509n == NULL) {
		GSSerr(GSSERR_F_ACQUIRE_CRED,GSSERR_R_PROCESS_CERT);
		goto err;
	}
	
	/* now strip off any /CN=proxy entries */

	proxy_get_base_name(newcred->globusid->x509n);
	
	major_status = GSS_S_COMPLETE;

err:
	/* user will call delete_sec_context to cleanup the cred. */

	*output_cred_handle = newcred;

#ifdef DEBUG
	fprintf(stderr,"gss_create_and_fill_cred:major_status:%08x\n",major_status);
#endif
	return major_status;
}
