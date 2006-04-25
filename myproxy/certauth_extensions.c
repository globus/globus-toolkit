/*
 * CA extension implementation file
 *
 */

#include "myproxy_common.h"

#define BUF_SIZE 16384

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

#define SECONDS_PER_HOUR (60 * 60)

static int 
read_cert_request(GSI_SOCKET *self,
		  unsigned char **buffer,
		  size_t *length) {

  int             return_value = 1;
  unsigned char * input_buffer = NULL;
  size_t          input_buffer_length;

  if (self == NULL) {
    verror_put_string("read_cert_request(): Socket is null");
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

  return return_value;

}

static int 
send_certificate(GSI_SOCKET *self,
		 unsigned char *buffer,
		 size_t length) {

  if (GSI_SOCKET_write_buffer(self, (const char *)buffer, 
			      length) == GSI_SOCKET_ERROR) {
    verror_put_string("Error writing certificate to client!");
    return 1;
  }

  return 0;

}

static void 
add_key_value( char * key, char * value, char buffer[] ) {

  strcat( buffer, key );
  strcat( buffer, "=" );
  if ( value == NULL ) {
    strcat( buffer, "NULL" );
  } else {
    strcat( buffer, value );
  }
  strcat( buffer, "\n" );
}


static int 
external_callout( X509_REQ                 *request, 
		  X509                     **cert,
		  myproxy_request_t        *client_request,
		  myproxy_server_context_t *server_context) {

  int return_value = 1;

  char buffer[BUF_SIZE];
  char intbuf[128];

  pid_t pid;
  int fds[3];
  int status;

  FILE * pipestream = NULL;
  X509 * certificate = NULL;

  memset(buffer, '\0', BUF_SIZE);
  memset(intbuf, '\0', 128);

  myproxy_debug("callout using: %s", 
		server_context->certificate_issuer_program);

  if ((pid = myproxy_popen(fds,
			   server_context->certificate_issuer_program,
			   NULL)) < 0) {
    return -1; /* myproxy_popen will set verror */
  }

  /* writing to program */
  pipestream = fdopen( fds[0], "w" );

  if ( pipestream == NULL ) {
    verror_put_string("File stream to stdin pipe creation problem.");
    return 1;
  }

  add_key_value( "username", client_request->username, buffer );
  add_key_value( "passphrase", client_request->passphrase, buffer );

  sprintf( intbuf, "%d", client_request->proxy_lifetime );
  add_key_value( "proxy_lifetime", (char*)intbuf, buffer );
  memset(intbuf, '\0', 128);

  add_key_value( "retrievers", client_request->retrievers, buffer );
  add_key_value( "renewers", client_request->renewers, buffer );
  add_key_value( "credname", client_request->credname, buffer );
  add_key_value( "creddesc", client_request->creddesc, buffer );
  add_key_value( "authzcreds", client_request->authzcreds, buffer );
  add_key_value( "keyretrieve", client_request->keyretrieve, buffer );
  add_key_value( "trusted_retrievers", client_request->trusted_retrievers,
		 buffer );

  sprintf( intbuf, "%d", server_context->max_cert_lifetime );
  add_key_value( "max_cert_lifetime", (char*)intbuf, buffer );
  memset(intbuf, '\0', 128);

  fprintf( pipestream, "%s\n", buffer );

  PEM_write_X509_REQ( pipestream, request );

  fflush( pipestream );

  fclose( pipestream );

  close(fds[0]);

  /* wait for program to exit */

  if( waitpid(pid, &status, 0) == -1 ) {
    verror_put_string("waitpid() failed for external callout child");
    verror_put_errno(errno);
    goto error;
  }

  /* check status and read appropriate content */

  /* if exit != 0 - read and log message from program stderr */

  if ( status != 0 ) {
    verror_put_string("external process exited abnormally\n");
    memset(buffer, '\0', BUF_SIZE);
    if ( read( fds[2], buffer, BUF_SIZE ) > 0 ) {
      verror_put_string(buffer);
    } else {
      verror_put_string("did not recieve an error string from callout");
    }
    goto error;
  }

  /* retrieve the certificate */

  pipestream = fdopen( fds[1], "r" );

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

  close(fds[1]);
  close(fds[2]);

  /* good to go */

  *cert = certificate;

  return_value = 0;

 error:

  memset(buffer, '\0', BUF_SIZE);
  memset(intbuf, '\0', 128);

  return return_value;

}

static int 
tokenize_to_x509_name( char * dn, X509_NAME * name ) {

  int return_value = 0;

  char * tmp;

  char * tok;
  char * tmpTok = NULL;
  char * subtok;
  char * toksplit;

  int i;

  myproxy_debug( "tokenizing: %s", dn );

  tmp = strdup(dn);

  tok = strtok( tmp, "/" );

  while ( tok != NULL ) {

    subtok = strchr( tok, '=' );
    toksplit = subtok;

    subtok++;
    *toksplit = '\0';

    /* if short prefixes are being used, they need to be capped before
       feeding to the add entry function. tok must be strdup()ed because
       messing with the strtok() buffer is bad. */

    tmpTok = strdup( tok );

    if ( strlen( tmpTok ) < 3 ) {
      i = 0;
      while( i < strlen( tmpTok ) ) {
	tmpTok[i] = toupper( tmpTok[i] );
	i = i + 1;
      }
    }

    myproxy_debug( "adding: %s = %s", tmpTok, subtok );

    if (!X509_NAME_add_entry_by_txt( name, tmpTok, MBSTRING_ASC, 
				     (unsigned char *) subtok, -1, -1, 0 )) {
      verror_put_string("Error adding %s = %s to x509 name", tmpTok, subtok );
      verror_put_string("Invalid field name");
      return_value = 1;
      goto end;
    }

    subtok = NULL;
    toksplit = NULL;

    free( tmpTok );
    tmpTok = NULL;

    tok = strtok( NULL, "/" );
  }

 end:

  free(tmp);

  return return_value;

}

/* Use fcntl() for POSIX file locking. Lock is released when file is closed. */
static int
lock_file(int fd)
{
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    while( fcntl( fd, F_SETLKW, &fl ) < 0 )
    {
	if ( errno != EINTR )
	{
	    return -1;
	}
    }
    return 0;
}

/*
 * serial number handling liberally borrowed from KCA with the addition
 * of file locking
 */

static int 
assign_serial_number( X509 *cert, 
		      myproxy_server_context_t *server_context ) {

  int increment  = 1;
  int retval = 1;
  long serialset;

  BIGNUM       * serial = NULL;
  ASN1_INTEGER * current = NULL, * next = NULL;
  char buf[1024];
  char *serialfile = NULL;

  /* all the io variables */

  BIO   * serialbio = NULL;
  int     fd;
  FILE  * serialstream = NULL;

  myproxy_debug("Assigning serial number");

  serial  = BN_new();
  current = ASN1_INTEGER_new();

  if ( (serial ==NULL) || (current==NULL) ) {
    verror_put_string("Bignum/asn1 INT init failure\n");
    goto error;
  }

  if (server_context->certificate_serialfile) {
      serialfile = server_context->certificate_serialfile;
  } else {
      const char *sdir;
      sdir = myproxy_get_storage_dir();
      if (sdir == NULL) {
	  goto error;
      }
      serialfile = malloc(strlen(sdir)+strlen("/serial")+1);
      sprintf(serialfile, "%s/serial", sdir);
  }

  /* open(), lock, open stream and create BIO */

  fd = open( serialfile, O_RDWR|O_CREAT, 0600 );

  if ( fd == -1 ) {
    verror_put_string("Call to open() failed on %s\n", serialfile);
    goto error;
  }

  if ( lock_file(fd) == -1 ) {
    verror_put_string("Failed to get lock on file descriptor\n");
    verror_put_errno(errno);
    goto error;
  }

  serialstream = fdopen( fd, "w+" );

  if ( serialstream == NULL ) {
    verror_put_string("Unable to open file stream\n");
    goto error;
  }

  /* check if file is empty, and if so, initialize with 1 */
  if (fseek(serialstream, 0L, SEEK_END) < 0) {
    verror_put_string("Unable to seek file stream\n");
    goto error;
  }

  serialset = ftell(serialstream);
  if (serialset) rewind(serialstream);

  serialbio = BIO_new_fp( serialstream, BIO_CLOSE );

  if ( serialbio == NULL ) {
    verror_put_string("BIO_new_fp failure.\n");
    goto error;
  }

  if (serialset) {
      if (!a2i_ASN1_INTEGER(serialbio, current, buf, sizeof(buf))) {
	  verror_put_string("Asn1 int read/conversion error\n");
	  goto error;
      } else {
	  myproxy_debug("Loaded serial number %s from %s", buf, serialfile);
      }
  } else {
      ASN1_INTEGER_set(current, 1);
  }

  serial = BN_bin2bn( current->data, current->length, serial );
  if ( serial == NULL ) {
    verror_put_string("Error converting to bignum\n");
    goto error;
  }

  if (!BN_add_word(serial, increment)) {
    verror_put_string("Error incrementing serial number\n");
    goto error;
  }

  if (!(next = BN_to_ASN1_INTEGER(serial, NULL))) {
    verror_put_string("Error converting new serial to ASN1\n");
    goto error;
  }

  BIO_reset(serialbio);
  i2a_ASN1_INTEGER(serialbio, next);
  BIO_puts(serialbio, "\n");


  /* the call to BIO_free with the CLOSE flags will take care of
   * the underlying file stream and close()ing the file descriptor,
   * which will release the lock.
   */
  
  BIO_free(serialbio);
  serialbio    = NULL;
  serialstream = NULL;

  if (!X509_set_serialNumber(cert, current)) {
    verror_put_string("Error assigning serialnumber\n");
    goto error;
  }

  myproxy_debug("serial number assigned");

  retval = 0;

 error:
  if (serial)
    BN_free(serial);
  if (current)
    ASN1_INTEGER_free(current);
  if(next)
    ASN1_INTEGER_free(next);
  if(serialbio)
    BIO_free(serialbio);
  if(serialstream)
    serialstream = NULL;


  return(retval);


}

static void
add_ext(X509V3_CTX *ctxp, X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, ctxp, nid, value);
    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
}

static int 
generate_certificate( X509_REQ                 *request, 
		      X509                     **certificate,
		      EVP_PKEY                 *pkey,
		      myproxy_request_t        *client_request,
		      myproxy_server_context_t *server_context) { 

  int             return_value = 1;  
  int             not_after;
  char          * userdn;
  char          * certificate_issuer = NULL;

  X509           * issuer_cert = NULL;
  X509           * cert = NULL;
  X509_NAME      * subject = NULL;
  EVP_PKEY       * cakey = NULL;
  X509V3_CTX       ctx, *ctxp;

  FILE * inkey = NULL;
  FILE * issuer_cert_file = NULL;

  myproxy_debug("Generating certificate internally.");

  cert = X509_new();

  ctxp = &ctx;		/* needed for X509V3 macros */
  X509V3_set_ctx_nodb(ctxp);

  if (cert == NULL) {
    verror_put_string("Problem creating new X509.");
    goto error;
  }

  /* subject info */

  /* this has already been called successfully, but... */

  if ( user_dn_lookup( client_request->username, &userdn,
		       server_context ) ) {
    verror_put_string("User DN lookup failure");
    goto error;
  }

  myproxy_debug("DN for user %s: %s", client_request->username, userdn);

  subject = X509_get_subject_name(cert);

  if( tokenize_to_x509_name( userdn, subject ) ) {
    verror_put_string("tokenize_to_x509_name() failed");
    goto error;
  }

  /* issuer info */

  issuer_cert_file = fopen(server_context->certificate_issuer_cert, "r");
  if (issuer_cert_file == NULL) {
      verror_put_string("Error opening certificate file %s",
			server_context->certificate_issuer_cert);
      verror_put_errno(errno);
      goto error;
  }
  
  if ((issuer_cert = PEM_read_X509(issuer_cert_file,
				   NULL, NULL, NULL)) == NULL)
  {
      verror_put_string("Error reading certificate %s",
			server_context->certificate_issuer_cert);
      ssl_error_to_verror();
      fclose(issuer_cert_file);
      goto error;
  }
  fclose(issuer_cert_file);

  X509_set_issuer_name(cert, X509_get_subject_name(issuer_cert));

  X509V3_set_ctx(ctxp, issuer_cert, cert, NULL, NULL, 0);

  /* version, ttl, etc */

  X509_set_version(cert, 0x2); /* this is actually version 3 */

  if (assign_serial_number(cert, server_context)) {
    verror_put_string("Error assigning serial number to cert");
    goto error;
  }

  if (!server_context->max_cert_lifetime) {
    not_after = MIN(client_request->proxy_lifetime,
		    SECONDS_PER_HOUR * MYPROXY_DEFAULT_DELEG_HOURS);
  } else {
    not_after = MIN(client_request->proxy_lifetime,
		    server_context->max_cert_lifetime);
  }

  myproxy_debug("cert lifetime: %d", not_after );

  X509_gmtime_adj(X509_get_notBefore(cert), -5*60); /* allow 5m clock skew */
  X509_gmtime_adj(X509_get_notAfter(cert), (long)not_after);
  
  X509_set_pubkey(cert, pkey);

  /* extensions */

  if (server_context->certificate_extfile ||
      server_context->certificate_extapp) {
      CONF *extconf = NULL;
      long errorline = -1;
      extconf = NCONF_new(NULL);
      if (server_context->certificate_extfile) {
	  if (NCONF_load(extconf, server_context->certificate_extfile,
			 &errorline) <= 0) {
	      if (errorline <= 0) {
		  verror_put_string("OpenSSL error loading the certificate_extfile '%s'", server_context->certificate_extfile);
	      } else {
		  verror_put_string("OpenSSL error on line %ld of certificate_extfile '%s'\n", errorline, server_context->certificate_extfile);
	      }
	      goto error;
	  }
	  myproxy_debug("Successfully loaded extensions file %s.",
			server_context->certificate_extfile);
      } else {
	  pid_t childpid;
	  int fds[3];
	  int exit_status;
	  FILE *nconf_stream = NULL;
	  myproxy_debug("calling %s", server_context->certificate_extapp);
	  if ((childpid = myproxy_popen(fds,
					server_context->certificate_extapp,
					client_request->username,
					NULL)) < 0) {
	      return -1; /* myproxy_popen will set verror */
	  }
	  close(fds[0]);
	  if (waitpid(childpid, &exit_status, 0) == -1) {
	      verror_put_string("wait() failed for extapp child");
	      verror_put_errno(errno);
	      return -1;
	  }
	  if (exit_status != 0) {
	      FILE *fp = NULL;
	      char buf[100];
	      verror_put_string("Certificate extension call-out returned non-zero.");
	      fp = fdopen(fds[1], "r");
	      if (fp) {
		  while (fgets(buf, 100, fp) != NULL) {
		      verror_put_string(buf);
		  }
		  fclose(fp);
	      }
	      fp = fdopen(fds[2], "r");
	      if (fp) {
		  while (fgets(buf, 100, fp) != NULL) {
		      verror_put_string(buf);
		  }
		  fclose(fp);
	      }
	      goto error;
	  }
	  close(fds[2]);
	  nconf_stream = fdopen(fds[1], "r");
	  if (NCONF_load_fp(extconf, nconf_stream, &errorline) <= 0) {
	      if (errorline <= 0) {
		  verror_put_string("OpenSSL error parsing output of certificate_extfile call-out.");
	      } else {
		  verror_put_string("OpenSSL error parsing line %ld of of certificate_extfile call-out output.", errorline);
	      }
	      fclose(nconf_stream);
	      goto error;
	  }
	  fclose(nconf_stream);
      }
      X509V3_set_nconf(&ctx, extconf);
      if (!X509V3_EXT_add_nconf(extconf, &ctx, "default", cert))
      {
	  verror_put_string("OpenSSL error adding extensions.");
	  goto error;
      }
      myproxy_debug("Successfully added extensions.");
  } else {			/* add some defaults */
      add_ext(ctxp, cert, NID_key_usage, "critical,Digital Signature, Key Encipherment, Data Encipherment");
      add_ext(ctxp, cert, NID_basic_constraints, "critical,CA:FALSE");
      add_ext(ctxp, cert, NID_subject_key_identifier, "hash");
  }
  if (server_context->certificate_issuer_email_domain) {
      char *email;
      email = malloc(strlen(client_request->username)+strlen("email:@")+1+
		     strlen(server_context->certificate_issuer_email_domain));
      sprintf(email, "email:%s@%s", client_request->username,
	      server_context->certificate_issuer_email_domain);
      add_ext(ctxp, cert, NID_subject_alt_name, email);
      free(email);
  }

  /* load ca key */

  inkey = fopen( server_context->certificate_issuer_key, "r");

  if (!inkey) {
    myproxy_debug("Could not open cakey file handle: %s",
		  server_context->certificate_issuer_key);
    goto error;

  }

  /* cakey must be unencrypted */

  cakey = PEM_read_PrivateKey( inkey, NULL, NULL,
	       (char *)server_context->certificate_issuer_key_passphrase );

  fclose(inkey);

  if ( cakey == NULL ) {
    verror_put_string("Could not load cakey for certificate signing.");
    goto error;
  } else {
    myproxy_debug("CAkey: %s", server_context->certificate_issuer_key );
  }

  /* sign it */

  myproxy_debug("Signing internally generated certificate.");

  if (!X509_sign(cert, cakey, EVP_sha1() ) ) {
    myproxy_debug("Certificate/cakey sign failed.");
    goto error;
  } 

  return_value = 0;

  *certificate = cert;

 error:
  if (return_value) {
    if ( cert != NULL ) {
      X509_free(cert);
    }
  }
  if (cakey)
    EVP_PKEY_free( cakey );
  if (userdn) {
    free(userdn);
    userdn = NULL;
  }
  if (certificate_issuer)
    free(certificate_issuer);

  return return_value;

}

static int 
handle_certificate(unsigned char            *input_buffer,
		   size_t                   input_buffer_length,
		   unsigned char            **output_buffer,
		   int                      *output_buffer_length,
		   myproxy_request_t        *client_request,
		   myproxy_server_context_t *server_context) {

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

  myproxy_debug("handle_certificate()");

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

  /* check to see if the configuration is sound, and call the appropriate
   * cert generation method based on what has been defined
   */

  if ( ( server_context->certificate_issuer_program != NULL ) && 
       ( server_context->certificate_issuer_cert != NULL ) ) {
    verror_put_string("CA config error: both issuer and program defined");
    goto error;
  } 

  if ( ( server_context->certificate_issuer_program == NULL ) && 
       ( server_context->certificate_issuer_cert == NULL ) ) {
    verror_put_string("CA config error: neither issuer or program defined");
    goto error;
  }

  if ( ( server_context->certificate_issuer_cert != NULL ) && 
       ( server_context->certificate_issuer_key == NULL ) ) {
    verror_put_string("CA config error: issuer defined but no key defined");
    goto error;
  }

  if ( ( server_context->certificate_issuer_cert != NULL ) && 
       ( server_context->certificate_issuer_key != NULL ) ) {
    myproxy_debug("Using internal openssl/generate_certificate() code");

    if ( generate_certificate( req, &cert, pkey, 
			       client_request, server_context ) ) {
      verror_put_string("Internal cert generation failed");
      goto error;
    }
  } else {
    myproxy_debug("Using external callout interface.");

    if( external_callout( req, &cert, client_request, server_context ) ) {
      verror_put_string("External callout failed.");
      goto error;
    }
  }

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

