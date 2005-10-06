#include "myproxy_common.h"	/* all needed headers included here */

#if defined(HAVE_LIBPAM)
#include "auth_pam.h"
#endif

struct authorization_func {
   char * (*create_server_data) (void);
   char * (*create_client_data) (authorization_data_t *data, 
	                         void *extra_data, 
				 size_t extra_data_len,
				 size_t *client_data_len);
   int (*check_client) (authorization_data_t *client_auth_data,
			struct myproxy_creds *creds, /* o co zada */
			char *client_name, myproxy_server_context_t* config);
   author_method_t method;
   char *name; /* arbitrary ASCII string without a colon (':') */
};

static struct authorization_func * _find_func(author_method_t method);

static authorization_data_t * 
_find_data(author_method_t method, authorization_data_t **data);


/*
 * Implementation of password-based authorization
 */
char * 
auth_passwd_create_server_data(void)
{
   return strdup("Put your password for the Myproxy server");
}

char * 
auth_passwd_create_client_data(authorization_data_t *data, 
                               void *extra_data, size_t extra_data_len,
			       size_t *client_data_len)
{ 
   char *tmp;

   tmp = malloc(extra_data_len + 1);
   if (tmp == NULL)
      return NULL;
   memcpy(tmp, extra_data, extra_data_len);
   tmp[extra_data_len] = '\0';
   *client_data_len = extra_data_len + 1;
   return tmp;
}

int auth_passwd_check_client(authorization_data_t *client_auth_data,
                             struct myproxy_creds *creds, char *client_name,
			     myproxy_server_context_t* config)
{ 
   int encrypted, empty_passphrase, cred_passphrase_match;
#if defined(HAVE_LIBPAM)
   char* pam_policy = NULL;
   char* pam_id = NULL;
   int pam_required, pam_sufficient, pam_disabled;
#endif

   /* 1. Check whether the credentials are encrypted. */
   encrypted = myproxy_creds_encrypted(creds);
   empty_passphrase = (client_auth_data->client_data_len <= 0) ? 1 : 0;

   /* 2. Check whether the password the user gave matches the
    *    credential passphrase */
   cred_passphrase_match = 0;
   if (encrypted)
   {
      if (client_auth_data->client_data_len >= MIN_PASS_PHRASE_LEN &&
	  client_auth_data->client_data != NULL &&
	  myproxy_creds_verify_passphrase(creds,
					  client_auth_data->client_data) == 1)
	 cred_passphrase_match = 1;
   }
   /* unencrypted --> passphrase matches if it is blank. */
   else 
      cred_passphrase_match = (client_auth_data->client_data_len <= 0) ? 1 : 0;
   
#if defined(HAVE_LIBPAM)

   /* Tangent: figure out PAM configuration. */
   pam_policy = config ? config->pam_policy : NULL;
   pam_id     = config ? config->pam_id : NULL;

   /* Default value is "disabled". */
   if (pam_policy == NULL) pam_policy = "disabled";

   pam_required   = (strcmp(pam_policy, "required"  ) == 0 ? 1 : 0);
   pam_sufficient = (strcmp(pam_policy, "sufficient") == 0 ? 1 : 0);
   pam_disabled   = (strcmp(pam_policy, "disabled"  ) == 0 ? 1 : 0);

   /* Note: if pam_policy is not recognized, it will fall through to
    * the disabled case below, and a debug message will be printed. */

   /* 3. If the passphrase matches the credentials, and PAM config is
    *    "sufficient", then we're done, and we don't need to check
    *    PAM, as long as a passphrase was actually entered. */
   if (pam_sufficient && cred_passphrase_match && !empty_passphrase)
   {
      myproxy_debug("Passphrase matches credentials, and PAM config is \"%s\"; "
		    "authentication succeeds without checking PAM.", pam_policy);
      return 1;
   }

   /* 4. If PAM is "required", *always* check it, regardless of
    *    whether the credential passphrase matches, so that any
    *    logging, pausing, etc. can occur.  Also, if PAM is sufficient
    *    and we've gotten this far, it means that the credential
    *    passphrase is blank and therefore we need to check PAM. */
   else if (pam_required || pam_sufficient)
   {
      char* auth_pam_result = NULL;
      int pam_success = 0;
      if (pam_id == NULL) pam_id = "myproxy";
      myproxy_debug
	 ("Checking passphrase via PAM.  PAM policy: \"%s\"; PAM ID: \"%s\"\n",
	  pam_policy, pam_id);

      auth_pam_result = auth_pam(creds->username,
				 client_auth_data->client_data, pam_id, NULL);
      if (auth_pam_result && strcmp("OK", auth_pam_result) == 0) {
         pam_success = 1;
      }
      else
      {
         if (auth_pam_result) {
            /* The Cyrus SASL convention is to prepend the error
               message with "NO ".  We can chop that off. */
            if (strlen(auth_pam_result) > 3
                && strncmp(auth_pam_result, "NO ", 3) == 0)
            {
               verror_put_string(auth_pam_result + 3);
            }
            else verror_put_string(auth_pam_result);
         }
         else
            verror_put_string("PAM authentication failed");
      }
      if (auth_pam_result != NULL)
	 free(auth_pam_result);

      return pam_success;
   }

   /* 5. If PAM is disabled, check only the credential passphrase. */
   else
   {
      if (!pam_disabled)
	 myproxy_log("Unknown PAM policy: \"%s\"; not using PAM.\n", pam_policy);
      return cred_passphrase_match;
   }

#else /* defined(HAVE_LIBPAM) */

   return cred_passphrase_match;

#endif /* defined(HAVE_LIBPAM) */
}

struct authorization_func authorization_passwd = {
   auth_passwd_create_server_data,
   auth_passwd_create_client_data,
   auth_passwd_check_client,
   AUTHORIZETYPE_PASSWD,
   "password"
};

/* 
 * Implementation of certificate-based authorization
 */

#define CHALLENGE_SIZE  16

char * auth_cert_create_server_data(void)
{
   unsigned char random[CHALLENGE_SIZE];
   char *challenge; 
   int i;
   
   /* RAND_bytes() will fail if the PRNG has not been seeded with
      enough randomness to ensure an unpredictable byte sequence. */
   if (RAND_bytes(random, sizeof(random)) == 0) {
      verror_put_string("RAND_bytes failed");
      ssl_error_to_verror();
      return NULL;
   }

   challenge = malloc(CHALLENGE_SIZE * 2 + 1);
   if (challenge == NULL) {
      verror_put_string("malloc()");
      verror_put_errno(errno);
      return NULL;
   }

   for (i = 0; i < CHALLENGE_SIZE; i++) {
      int     dd = random[i] & 0x0f;
      challenge[2*i+1] = dd<10 ? dd+'0' : dd-10+'a';
      dd = random[i] >> 4;
      challenge[2*i] = dd<10 ? dd+'0' : dd-10+'a';
   }
   challenge[CHALLENGE_SIZE * 2] = '\0';

   return challenge;
}

 
/* the extra data parameter must contain a filename with a certificate to 
   authorization */
char * auth_cert_create_client_data (authorization_data_t *data, 
      void *extra_data, size_t extra_data_len, size_t *client_data_len )
{
   char * return_data = NULL;
   SSL_CREDENTIALS *proxy = NULL;
   unsigned char *signature = NULL;
   unsigned int signature_len;
   char *output = NULL;
   char *p;
   unsigned char *creds_buf = NULL;
   int creds_buf_len;
   
   proxy = ssl_credentials_new();
   if (proxy == NULL)
      return NULL;

   if (ssl_proxy_load_from_file(proxy, (char *)extra_data, NULL) == SSL_ERROR) {
      verror_prepend_string("ssl_proxy_load_from_file()");
      goto end;
   }

   if (ssl_sign((unsigned char *)data->server_data,
		strlen(data->server_data), proxy,
	        &signature, (int *)&signature_len) == SSL_ERROR) {
      verror_prepend_string("ssl_sign()");
      goto end;
   }

   if (ssl_creds_to_buffer(proxy, &creds_buf, &creds_buf_len) == SSL_ERROR) {
      verror_prepend_string("ssl_creds_to_buffer()");
      goto end;
   }

   *client_data_len = 4 + signature_len + creds_buf_len;
   output = malloc(*client_data_len);
   if (output == NULL) {
      verror_put_string("malloc failed");
      verror_put_errno(errno);
      goto end;
   }

   p = output;

   *(unsigned int*)p = htonl(signature_len);
   p += 4;

   memcpy(p, signature, signature_len);
   p += signature_len;

   memcpy(p, creds_buf, creds_buf_len);

   return_data = output;
   output = NULL;

end:
   ssl_credentials_destroy(proxy);
   if (signature)
      free(signature);
   if (output)
      free(output);
   if (creds_buf)
      free(creds_buf);

   return return_data;
}

int auth_cert_check_client (authorization_data_t *auth_data,
                            struct myproxy_creds *creds, 
			    char *client_name,
			    myproxy_server_context_t* config)
{ 
   SSL_CREDENTIALS *chain = NULL;
   unsigned char *signature = NULL;
   unsigned char *p;
   unsigned int signature_len;
   char * authorization_subject = NULL;
   int return_status = 0;

   p = (unsigned char *)auth_data->client_data;

   signature_len = ntohl(*(unsigned int*)p);
   p += 4;

   signature = p;
   p += signature_len;

   if (ssl_creds_from_buffer(p, auth_data->client_data_len - 4 - signature_len,
	                     &chain) == SSL_ERROR) {
      verror_prepend_string("internal error: ssl_creds_from_buffer() failed");
      goto end;
   }

   if (ssl_verify((unsigned char *)auth_data->server_data, 
	          strlen(auth_data->server_data), 
	          chain, signature, signature_len) == SSL_ERROR) {
      verror_prepend_string("certificate verification failed");
      goto end;
   }

   if (ssl_verify_gsi_chain(chain) == SSL_ERROR) {
       verror_prepend_string("certificate chain verification failed");
       goto end;
   }

   if (ssl_get_base_subject(chain, &authorization_subject) == SSL_ERROR) {
       verror_prepend_string("internal error: ssl_get_base_subject() failed");
       goto end;
   }

   /* if (strcmp(authorization_subject, creds->owner_name) != 0) { */
   if (strcmp(authorization_subject, creds->username) != 0) {
       verror_prepend_string("certificate subject does not match credential to be renewed");
       goto end;
   }

   return_status = 1;
   
end:
   if (chain)
      ssl_credentials_destroy(chain);
   if (authorization_subject)
      free(authorization_subject);

   return return_status;
}
   

struct authorization_func authorization_cert = {
   auth_cert_create_server_data,
   auth_cert_create_client_data,
   auth_cert_check_client,
   AUTHORIZETYPE_CERT,
   "X509_certificate"
};


#if defined(HAVE_LIBSASL2)
/* 
 * Implementation of SASL-based authorization
 */

char * auth_sasl_create_server_data(void)
{
   char *challenge = strdup("SASL authorization negotiation server"); 
   
   return challenge;
}

 
/* the extra data parameter must contain a filename with a certificate to 
   authorization */
char * auth_sasl_create_client_data (authorization_data_t *data, 
      void *extra_data, size_t extra_data_len, size_t *client_data_len )
{
   char *tmp;

   tmp = malloc(extra_data_len + 1);
   if (tmp == NULL)
      return NULL;
   memcpy(tmp, extra_data, extra_data_len);
   tmp[extra_data_len] = '\0';
   *client_data_len = extra_data_len + 1;
   return tmp;
}

int auth_sasl_check_client (authorization_data_t *auth_data,
                            struct myproxy_creds *creds, 
			    char *client_name,
			    myproxy_server_context_t* config)
{ 
   int return_status = 1;

   return return_status;
}
   


struct authorization_func authorization_sasl = {
   auth_sasl_create_server_data,
   auth_sasl_create_client_data,
   auth_sasl_check_client,
   AUTHORIZETYPE_SASL,
   "SASL"
};
#endif /* defined(HAVE_LIBSASL2) */


static struct authorization_func *authorization_funcs[] = {
   &authorization_passwd,
#if defined(HAVE_LIBSASL2)
   &authorization_sasl,
#endif
   &authorization_cert
};

static int num_funcs = sizeof(authorization_funcs) / sizeof(authorization_funcs[0]);

int
authorization_init_server(authorization_data_t ***data,
			  author_method_t methods[])
{
   authorization_data_t **auth_data;
   int i=0, j=0, num_methods=0;

   auth_data = malloc(sizeof(authorization_data_t *) * (num_funcs + 1));
   if (auth_data == NULL) {
      verror_put_string("malloc() failed");
      verror_put_errno(errno);
      return -1;
   }
   memset(auth_data, 0, sizeof(authorization_data_t *) * (num_funcs + 1));
   for (i = 0; methods[i] != AUTHORIZETYPE_NULL; i++) {
       for (j = 0; j < num_funcs; j++) {
	   if (authorization_funcs[j]->method == methods[i]) {
	       auth_data[num_methods] = malloc(sizeof(authorization_data_t));
	       if (auth_data[num_methods] == NULL) {
		   verror_put_string("malloc() failed");
		   verror_put_errno(errno);
		   authorization_data_free(auth_data);
		   return -1;
	       }
	       auth_data[num_methods]->server_data =
		   authorization_funcs[j]->create_server_data();
	       auth_data[num_methods]->client_data = NULL;
	       auth_data[num_methods]->client_data_len = 0;
	       auth_data[num_methods]->method = authorization_funcs[j]->method;
	       num_methods++;
	   }
       }
   }
   auth_data[num_methods] = NULL;

   *data = auth_data;

   return 0;
}

void
authorization_data_free_contents(authorization_data_t *data)
{
   if (data == NULL)
      return;
   if (data->server_data) {
      free (data->server_data);
      data->server_data = NULL;
   }
   if (data->client_data) {
      free (data->client_data);
      data->client_data = NULL;
   }
}

void
authorization_data_free(authorization_data_t **data)
{
   authorization_data_t **p = data;
   
   if (data == NULL)
      return;
   while (*p) {
      authorization_data_free_contents(*p);
      free(*p);
      p++;
   }
   free(data);
}

authorization_data_t *
authorization_store_response(char *buffer, 
                             size_t bufferlen, 
                             author_method_t method, 
			     authorization_data_t **data)
{
   authorization_data_t *d;

   d = _find_data(method, data);
   if (d) {
      d->client_data = malloc (bufferlen);
      if (d->client_data == NULL)
	 return NULL;
      memcpy(d->client_data, buffer, bufferlen);
      d->client_data_len = bufferlen;
   }
   return d;
}

static struct authorization_func *
_find_func(author_method_t method)
{
   int i;

   for (i = 0; i < num_funcs;  i++)
      if (authorization_funcs[i]->method == method)
	 return authorization_funcs[i];
   return NULL;
}

static authorization_data_t *
_find_data(author_method_t method, authorization_data_t **data)
{
   authorization_data_t **d = data;

   if (data == NULL)
      return NULL;
   while (*d) {
      if ((*d)->method == method)
	 return (*d);
      d++;
   }

   return NULL;
}

char *
authorization_get_name(author_method_t method)
{
   struct authorization_func *af = _find_func(method);

   if (af == NULL)
      return NULL;
   
   return(af->name);
}

author_method_t
authorization_get_method(char *name)
{
   int i;
   for (i = 0; i < num_funcs; i++)
      if (strcmp(authorization_funcs[i]->name, name) == 0)
	 return authorization_funcs[i]->method;
   return AUTHORIZETYPE_NULL;
}

int
authorization_check(authorization_data_t *client_auth_data,
                    struct myproxy_creds *creds,
		    char *client_name)
{
   return authorization_check_ex(client_auth_data, creds, client_name, NULL);
}

int
authorization_check_ex(authorization_data_t *client_auth_data,
		       struct myproxy_creds *creds,
		       char *client_name,
		       myproxy_server_context_t* config)
{
   struct authorization_func *af = _find_func(client_auth_data->method);
   if (af == NULL) {
      verror_put_string("Not supported authorization method");
      return -1;
   }
   return (af->check_client(client_auth_data, creds, client_name, config));
}

authorization_data_t *
authorization_create_response(authorization_data_t **data, 
                              author_method_t method, 
			      void *extra_data, 
			      size_t extra_data_len)
{
   authorization_data_t *d;
   struct authorization_func *af = _find_func(method);

   if (af == NULL) {
      verror_put_string("Not supported authorization method");
      return NULL;
   }

   d = _find_data(method, data);
   if (d == NULL) {
      verror_put_string("No appropriate authorization data available");
      return NULL;
   }

   if ((d->client_data = af->create_client_data(d, extra_data, extra_data_len,
	                 &d->client_data_len)) == NULL)
      return NULL;

   return d;
}
