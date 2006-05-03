#include "myproxy_common.h"	/* all needed headers included here */

struct authorization_func {
   char * (*create_server_data) (void);
   char * (*create_client_data) (authorization_data_t *data, 
	                         void *extra_data, 
				 size_t extra_data_len,
				 size_t *client_data_len);
   int (*check_client) (authorization_data_t *client_auth_data,
			struct myproxy_creds *creds, /* o co zada */
			char *client_name);
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
                             struct myproxy_creds *creds, char *client_name)
{ 
   char *tmp1;

   if (creds->passphrase != NULL &&
       client_auth_data->client_data_len >= MIN_PASS_PHRASE_LEN &&
       client_auth_data->client_data != NULL && 
       (tmp1 = (char *)des_crypt(client_auth_data->client_data,
		    &creds->owner_name[strlen(creds->owner_name)-3])) != NULL &&
       strcmp(creds->passphrase, tmp1) == 0) {
      return 1;
   }
   else 
      return 0;
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
   
   /* XXX */
   if (RAND_load_file("/dev/urandom", 128) == 0) {
      verror_put_string("RAND_load_file(): %s");
      ssl_error_to_verror();
      return NULL;
   }

   RAND_bytes(random, sizeof(random));

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
			    char *client_name)
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

   if (strcmp(authorization_subject, creds->owner_name) != 0) {
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

static struct authorization_func *authorization_funcs[] = {
   &authorization_passwd,
   &authorization_cert
};

static int num_funcs = sizeof(authorization_funcs) / sizeof(authorization_funcs[0]);

int
authorization_init_server(authorization_data_t ***data)
{
   authorization_data_t **auth_data;
   int i;

   auth_data = malloc(sizeof(*auth_data) * (num_funcs + 1));
   if (auth_data == NULL) {
      verror_put_string("malloc() failed");
      verror_put_errno(errno);
      return -1;
   }
   for (i = 0; i < num_funcs; i++) {
      auth_data[i] = malloc(sizeof(**auth_data));
      if (auth_data == NULL) {
	 verror_put_string("malloc() failed");
	 verror_put_errno(errno);
	 free(auth_data);
	 return -1;
      }
      auth_data[i]->server_data = authorization_funcs[i]->create_server_data();
      auth_data[i]->client_data = NULL;
      auth_data[i]->client_data_len = 0;
      auth_data[i]->method = authorization_funcs[i]->method;
   }
   auth_data[num_funcs] = NULL;

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
   struct authorization_func *af = _find_func(client_auth_data->method);
   if (af == NULL) {
      verror_put_string("Not supported authorization method");
      return -1;
   }
   return (af->check_client(client_auth_data, creds, client_name));
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
