/*
 * CA extension implementation file
 *
 */

#include "certauth_extensions.h"

#define BUF_SIZE 16384

#define USE_EXTERNAL_CALLOUT 1

struct _gsi_socket 
{
    int                         sock;
    int                         allow_anonymous; /* Boolean */
    /* All these variables together indicate the last error we saw */
    char                        *error_string;
    int                         error_number;
    gss_ctx_id_t                gss_context;
    OM_uint32                   major_status;
    OM_uint32                   minor_status;
    char                        *peer_name;
};

struct _ssl_credentials
{
  X509 *certificate;
  EVP_PKEY *private_key;
  STACK * certificate_chain;

  globus_gsi_proxy_handle_t proxy_req;
};

static char path_to_program[256];
static char name_of_program[256];

static char external_certificate[256];

/* this function is temporary until we get a codified scheme for this info */

int check_paths(void) {

  struct stat st;

  int return_value = 1;

  memset(path_to_program, '\0', 256);
  memset(name_of_program, '\0', 256);

  memset(external_certificate, '\0', 256);

  /* check if the paths to the external program was set */

  if ( getenv("CALLOUT_PATH") ) {
    sprintf( path_to_program, "%s", getenv("CALLOUT_PATH"));
  } else {
    verror_put_string("check_paths(): CALLOUT_PATH not set");
    goto error;
  }

  if ( getenv("CALLOUT_PROG") ) {
    sprintf( name_of_program, "%s", getenv("CALLOUT_PROG"));
  } else {
    verror_put_string("check_paths(): CALLOUT_PROG not set");
    goto error;
  }

  /* fish for the cert that the server is using..... */

  if ( stat("/etc/grid-security/hostcert.pem", &st) == 0 ) {
    sprintf(external_certificate, "%s", "/etc/grid-security/hostcert.pem");
    goto ok;
  }

  if ( getenv("X509_USER_CERT") ) {
    sprintf(external_certificate, "%s", getenv("X509_USER_CERT"));
    goto ok;
  }

  if ( getenv("X509_USER_PROXY") ) {
    sprintf(external_certificate, "%s", getenv("X509_USER_PROXY"));
    goto ok;
  }

  /* if we got here, then we have not found a certificate to load */

  verror_put_string("check_paths(): Can't find the cert the server is using");
  goto error;

 ok:
  return_value = 0;

 error:
  return(return_value);

}

int read_cert_request(GSI_SOCKET *self,
		      unsigned char **buffer,
		      size_t *length) {

  int             return_value = 1;
  unsigned char * input_buffer = NULL;
  size_t          input_buffer_length;

  SSL_CREDENTIALS * creds = NULL;

  if (self == NULL) {
    verror_put_string("read_cert_request(): Socket is null");
    goto error;
  }

  if (self->gss_context == GSS_C_NO_CONTEXT) {
    verror_put_string("read_cert_request(): Socket not authenticated");
    goto error;
  }

  /* a proxy or certificate need to be loaded into this SSL_CREDS struct
   * to hold up our end of the SSL_read() from the client.  We are just
   * using the certificate that the server is running.
   */

  creds = ssl_credentials_new();

  myproxy_debug("Loading %s for socket read", external_certificate);

  if (ssl_certificate_load_from_file( creds, external_certificate ) 
      == SSL_ERROR ) {
    verror_put_string("read_cert_request(): certificate load failed");
    goto error;
  }

  if (GSI_SOCKET_read_token(self, &input_buffer,
			    &input_buffer_length) == GSI_SOCKET_ERROR) {
    verror_put_string("read_cert_request(): Read from socket failed");
    goto error;
  }

  *buffer = input_buffer;
  *length = input_buffer_length;

  return_value = 0;

 error:
  if ( return_value ) {
    if ( input_buffer != NULL ) {
      myproxy_debug("freeing buffer");
      free(input_buffer);
      input_buffer = NULL;
    }
  }
  if ( creds != NULL ) {
    ssl_credentials_destroy(creds);
  }

  return return_value;

}

int send_certificate(GSI_SOCKET *self,
		     unsigned char *buffer,
		     size_t length) {

  if (GSI_SOCKET_write_buffer(self, (const char *)buffer, 
			      length) == GSI_SOCKET_ERROR) {
    verror_put_string("Error writing certificate to client!");
    return 1;
  }

  return 0;

}

void add_key_value( char * key, char * value, char buffer[] ) {

  strcat( buffer, key );
  strcat( buffer, "=" );
  if ( value == NULL ) {
    strcat( buffer, "NULL" );
  } else {
    strcat( buffer, value );
  }
  strcat( buffer, "\n" );
}


int external_callout( X509_REQ                 *request, 
		       X509                     **cert,
		       myproxy_request_t        *client_request,
		       myproxy_server_context_t *server_context) {

  int return_value = 1;

  char buffer[BUF_SIZE];
  char intbuf[128];

  pid_t pid;
  int p0[2], p1[2], p2[2];
  int status;

  FILE * pipestream = NULL;
  X509 * certificate = NULL;

  memset(buffer, '\0', BUF_SIZE);
  memset(intbuf, '\0', 128);

  /* create pipe */

  if ( pipe(p0) < 0 || pipe(p1) < 0 || pipe(p2) < 0 ) {
    verror_put_string("pipe() failed");
    verror_put_errno(errno);
    goto error;
  }

  /* create child */

  if ( (pid = fork()) < 0 ) {
    verror_put_string("fork() failed");
    verror_put_errno(errno);
    goto error;
  }

  /* attach pipes to appropriate streams in child and exec */

  if (pid == 0) {
    close(p0[1]); close(p1[0]); close(p2[0]);
    dup2(p0[0], 0); /*in*/
    dup2(p1[1], 1); /*out*/
    dup2(p2[1], 2); /*error*/
    execl(path_to_program, name_of_program, NULL);
    perror("exec");
    fprintf(stderr, "failed to run %s: %s\n",
	    path_to_program, strerror(errno));
    exit(1);
  }

  /* close unused pipes on the parent side */

  close(p0[0]);
  close(p1[1]);
  close(p2[1]);

  /* writing to program */

  pipestream = fdopen( p0[1], "w" );

  if ( pipestream == NULL ) {
    verror_put_string("File stream to stdin pipe creation problem.");
    return 1;
  }

  add_key_value( "username", client_request->username, buffer );
  add_key_value( "passphrase", client_request->passphrase, buffer );

  sprintf( intbuf, "%d", client_request->proxy_lifetime );
  add_key_value( "proxy_lifetime", (char*)intbuf, buffer );
  intbuf[0] = '\0';

  add_key_value( "retrievers", client_request->retrievers, buffer );
  add_key_value( "renewers", client_request->renewers, buffer );
  add_key_value( "credname", client_request->credname, buffer );
  add_key_value( "creddesc", client_request->creddesc, buffer );
  add_key_value( "authzcreds", client_request->authzcreds, buffer );
  add_key_value( "keyretrieve", client_request->keyretrieve, buffer );

  sprintf( intbuf, "%d", server_context->max_proxy_lifetime );
  add_key_value( "max_proxy_lifetime", (char*)intbuf, buffer );
  intbuf[0] = '\0';

  fprintf( pipestream, "%s\n", buffer );

  PEM_write_X509_REQ( pipestream, request );

  fflush( pipestream );

  fclose( pipestream );

  close(p0[1]);

  /* wait for program to exit */

  if( waitpid(pid, &status, 0) == -1 ) {
    verror_put_string("wait() failed for external callout child");
    verror_put_errno(errno);
    goto error;
  }

  /* check status and read appropriate content */

  /* if exit != 0 - read and log message from program stderr */

  if ( status != 0 ) {
    verror_put_string("external process exited abnormally\n");
    memset(buffer, '\0', BUF_SIZE);
    if ( read( p2[0], buffer, BUF_SIZE ) > 0 ) {
      verror_put_string(buffer);
    } else {
      verror_put_string("did not recieve an error string from callout");
    }
    goto error;
  }

  /* retrieve the certificate */

  pipestream = fdopen( p1[0], "r" );

  if ( pipestream == NULL ) {
    verror_put_string("File stream to stdout pipe creation problem.");
    goto error;
  }

  certificate = PEM_read_X509( pipestream, NULL, NULL, NULL );

  if (certificate == NULL) {
    verror_put_string("Error reading certificate from external program.");
    goto error;
  } else {
    myproxy_debug("Recieved certificate from external callout.");
  }

  fclose( pipestream );

  close(p1[0]);
  close(p2[0]);

  /* good to go */

  *cert = certificate;

  return_value = 0;

 error:

  memset(buffer, '\0', BUF_SIZE);
  memset(intbuf, '\0', 128);

  return return_value;

}

int generate_certificate( X509_REQ                 *request, 
			  X509                     **certificate,
			  EVP_PKEY                 *pkey,
			  myproxy_request_t        *client_request,
			  myproxy_server_context_t *server_context) { 

  /* This code is currently being retained to serve as and example
   * of how a certificate would be generated internally using the 
   * C openssl api.  But currently, we expect the callout interface 
   * to be used.  It will not currently work due to the path
   * to the cakey and it's passphrase being hardcoded.
   *
   * This may be turned into something functional in the near future.
   */

  int           return_value = 1;  
  int           serial;
  unsigned char serial_string[256];

  X509          * cert = NULL;

  myproxy_debug("Generating sample certificate internally.");

  cert = X509_new();

  if (cert == NULL) {
    verror_put_string("Problem creating new X509.");
    goto error;
  } 

  /* issuer info */

  X509_NAME * issuer = X509_get_issuer_name(cert);

  X509_NAME_add_entry_by_txt( issuer, "O", MBSTRING_ASC, 
			      "Scrotely Whizzbangs", -1, -1, 0);
  X509_NAME_add_entry_by_txt( issuer, "O", MBSTRING_ASC, 
			      "Vouch 4 U Inc.", -1, -1, 0);

  /* subject info */

  X509_NAME * subject = X509_get_subject_name(cert);

  X509_NAME_add_entry_by_txt( subject, "O", MBSTRING_ASC, 
			      "Scrotely Whizzbangs", -1, -1, 0);
  X509_NAME_add_entry_by_txt( subject, "O", MBSTRING_ASC, 
			      "Vouch 4 U Inc.", -1, -1, 0);
  X509_NAME_add_entry_by_txt( subject, "OU", MBSTRING_ASC, 
			      "People", -1, -1, 0);
  X509_NAME_add_entry_by_txt( subject, "CN", MBSTRING_ASC, 
			      "Jon Q. Public", -1, -1, 0);

  srand(time(NULL));

  serial = rand();

  memset( &serial_string, '\0', 256 );

  sprintf( serial_string, "%d", serial );

  X509_NAME_add_entry_by_txt( subject, "CN", MBSTRING_ASC, 
			      serial_string, -1, -1, 0);

  serial_string[0] = '\0';

  /* version, ttl, etc */

  X509_set_version(cert, 0x2); /* this is actually version 3 */

  ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*24*1);
  
  X509_set_pubkey(cert, pkey);

  /* extensions */

  X509_EXTENSION *ex = NULL;

  ex = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
			   "critical,Digital Signature, Key Encipherment, Data Encipherment");

  X509_add_ext(cert,ex,-1);
  X509_EXTENSION_free(ex);

  /* This is where you would load up your signing key */

  /* load ca key */

  const char keyfile[] = "/path/to/cakey.pem";

  FILE * inkey = fopen( keyfile, "r");
  EVP_PKEY * cakey = NULL;

  if (!inkey) {
    myproxy_debug("Could not open cakey file handle");
    goto error;

  }

  cakey = PEM_read_PrivateKey( inkey, NULL, NULL, "cakeypassphrase" );

  fclose(inkey);

  if ( cakey == NULL ) {
    verror_put_string("Could not load cakey for certificate signing.");
    goto error;
  }

  /* sign it */

  myproxy_debug("Signing internally generated certificate.");

  if (!X509_sign(cert, cakey, EVP_md5() ) ) {
    myproxy_debug("Certificate/cakey sign failed.");
    goto error;
  } 

  EVP_PKEY_free( cakey );

  return_value = 0;

  *certificate = cert;

 error:
  if (return_value) {
    if ( cert != NULL ) {
      X509_free(cert);
    }
  }
  return return_value;

  

}

int handle_certificate(unsigned char            *input_buffer,
		       size_t                   input_buffer_length,
		       unsigned char            **output_buffer,
		       int                      *output_buffer_length,
		       myproxy_request_t        *client_request,
		       myproxy_server_context_t *server_context) {

  myproxy_debug("handle_certificate()");

  int           return_value = 1;
  int           verify;
  unsigned char number_of_certs;
  char        * buf = NULL;
  int           buf_len;

  BIO      * request_bio  = NULL;
  X509_REQ * req          = NULL;
  EVP_PKEY * pkey         = NULL;
  X509     * cert         = NULL;
  BIO      * return_bio   = NULL;

  /* load proxy request into bio */
  request_bio = BIO_new(BIO_s_mem());
  if (request_bio == NULL) {
    verror_put_string("BIO_new() failed");
    goto error;
  }

  if (BIO_write(request_bio, input_buffer, input_buffer_length) < 0) {
    verror_put_string("BIO_write() failed");
    goto error;
  }

  /* feed bio into req structure, extract private key and verify */

  req = d2i_X509_REQ_bio(request_bio, NULL);

  if (req == NULL) {
    verror_put_string("Request load failed");
    goto error;
  } else {
    myproxy_debug("Cert request loaded.");
  }

  pkey = X509_REQ_get_pubkey(req);

  if (pkey == NULL) {
    verror_put_string("Could not extract public key from request.");
    goto error;
  } 

  verify = X509_REQ_verify(req, pkey);

  if ( verify != 1 ) {
    verror_put_string("Req/key did not verify: %d", verify );
    goto error;
  } 

#if USE_EXTERNAL_CALLOUT

  myproxy_debug("Using external callout interface.");

  if( external_callout( req, &cert, client_request, server_context ) ) {
    verror_put_string("External callout failed.");
    goto error;
  }

#else

  /* This calls an example of using the openssl libs internally and is
   * provided for eductational purposes only
   */

  myproxy_debug("Using example internal openssl code");

  if ( generate_certificate( req, &cert, pkey, 
			     client_request, server_context ) ) {
    verror_put_string("Internal cert generation failed");
    goto error;
  }

#endif

  /* a bit of sanity */

  if (cert == NULL) {
    verror_put_string("Cert pointer NULL - unknown generation failure!");
    goto error;
  }

  return_bio = BIO_new(BIO_s_mem());
  if (return_bio == NULL) {
    verror_put_string("BIO_new() failed");
    goto error;
  }

  /* send number of certificates in reply for backward compatibility */

  /* NOTE: this "backwards compatibility" issue is a quirk of myproxy.
   * If this is not set, then it causes a problem when the client
   * reads the response a writes things back to the bio.  Since this 
   * is acting as a CA and returning a short-lived identity certificate
   * it is currently set up to return "1". 
   */

  number_of_certs = 1; /* in this case */

  if (BIO_write(return_bio, &number_of_certs, 
		sizeof(number_of_certs)) == SSL_ERROR) {
    verror_put_string("Failed dumping proxy certificate to buffer (BIO_write() failed)");
    goto error;
  }

  if (i2d_X509_bio(return_bio, cert) == SSL_ERROR) {
    verror_put_string("Could not write signed certificate to bio.");
    goto error;
  }

  /* Convert the bio to a buffer and return to the calling function */

  /* Basically cribbed from bio_to_buffer from ssl_utils.c - it is not
   * publically exposed via the ssl_utils.h header and if it were that
   * would be used. */

  buf_len = BIO_pending( return_bio );

  buf = malloc( buf_len );

  if ( buf == NULL ) {
    verror_put_string("Return buffer malloc() failed.");
    goto error;
  }

  if ( BIO_read(return_bio, buf, buf_len ) == SSL_ERROR ) {
    verror_put_string("Failed dumping bio to return buffer.");
    goto error;
  }

  *output_buffer = (unsigned char *)buf;
  *output_buffer_length = buf_len;

  /* We're good to go */

  return_value = 0;

 error:
  if ( request_bio != NULL ) {
    BIO_free(request_bio);
  }
  if ( req != NULL ) {
    X509_REQ_free( req );
  }
  if ( pkey != NULL ) {
    EVP_PKEY_free( pkey );
  }
  if ( cert != NULL ) {
    X509_free( cert );
  }
  if ( return_bio != NULL ) {
    BIO_free( return_bio );
  }
  if ( return_value ) {
    if ( buf != NULL ) {
      free( buf );
    }
  }

  return return_value;

}

void get_certificate_authority(myproxy_socket_attrs_t   *server_attrs, 
			       myproxy_creds_t          *creds,
			       myproxy_request_t        *client_request,
			       myproxy_response_t       *response,
			       myproxy_server_context_t *server_context) {

  unsigned char * input_buffer = NULL;
  size_t	  input_buffer_length;
  unsigned char	* output_buffer = NULL;
  int		  output_buffer_length;

  myproxy_debug("Calling CA Extensions");

  response->response_type = MYPROXY_ERROR_RESPONSE;

  verror_clear();

  if ( check_paths() ) {
    verror_put_string("File path check failed");
    myproxy_log_verror();
    response->error_string = strdup("Unable to set up CA paths.\n");
    goto error;
  }

  if ( read_cert_request( server_attrs->gsi_socket, 
			  &input_buffer, &input_buffer_length) ) {
    verror_put_string("Unable to read request from client");
    myproxy_log_verror();
    response->error_string = \
      strdup("Unable to read cert request from client.\n");
    goto error;
  }

  if ( handle_certificate( input_buffer, input_buffer_length,
			   &output_buffer, &output_buffer_length,
			   client_request, server_context ) ) {
    verror_put_string("CA failed to generate certificate");
    response->error_string = strdup("Certificate generation failure.\n");
    myproxy_log_verror();
    goto error;
  }

  if ( send_certificate( server_attrs->gsi_socket,
			 output_buffer, output_buffer_length ) ) {
    myproxy_log_verror();
    myproxy_debug("Failure to send response to client!");
    goto error;
  }

  response->response_type = MYPROXY_OK_RESPONSE;

 error:
  if ( input_buffer != NULL ) {
    GSI_SOCKET_free_token( input_buffer );
  }
  if ( output_buffer != NULL ) {
    ssl_free_buffer( output_buffer );
  }

}

