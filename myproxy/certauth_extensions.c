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
  int p0[2], p1[2], p2[2];
  int status;

  FILE * pipestream = NULL;
  X509 * certificate = NULL;

  memset(buffer, '\0', BUF_SIZE);
  memset(intbuf, '\0', 128);

  myproxy_debug("callout using: %s", 
		server_context->certificate_issuer_program);

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
    execl(server_context->certificate_issuer_program, 
	  server_context->certificate_issuer_program, NULL);
    perror("exec");
    fprintf(stderr, "failed to run %s: %s\n",
	    server_context->certificate_issuer_program, strerror(errno));
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
  memset(intbuf, '\0', 128);

  add_key_value( "retrievers", client_request->retrievers, buffer );
  add_key_value( "renewers", client_request->renewers, buffer );
  add_key_value( "credname", client_request->credname, buffer );
  add_key_value( "creddesc", client_request->creddesc, buffer );
  add_key_value( "authzcreds", client_request->authzcreds, buffer );
  add_key_value( "keyretrieve", client_request->keyretrieve, buffer );

  sprintf( intbuf, "%d", server_context->max_cert_lifetime );
  add_key_value( "max_cert_lifetime", (char*)intbuf, buffer );
  memset(intbuf, '\0', 128);

  fprintf( pipestream, "%s\n", buffer );

  PEM_write_X509_REQ( pipestream, request );

  fflush( pipestream );

  fclose( pipestream );

  close(p0[1]);

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

static void 
tokenize_to_x509_name( char * dn, X509_NAME * name ) {

  char * tmp;

  char * tok;
  char * subtok;
  char * toksplit;

  myproxy_debug( "tokenizing: %s", dn );

  tmp = strdup(dn);

  tok = strtok( tmp, "/" );

  while ( tok != NULL ) {

    subtok = strchr( tok, '=' );
    toksplit = subtok;

    subtok++;
    *toksplit = '\0';

    myproxy_debug( "adding: %s = %s", tok, subtok );

    X509_NAME_add_entry_by_txt( name, tok, MBSTRING_ASC, 
				(unsigned char *) subtok, -1, -1, 0 );

    subtok = NULL;
    toksplit = NULL;

    tok = strtok( NULL, "/" );
  }

  free(tmp);

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

static int 
generate_certificate( X509_REQ                 *request, 
		      X509                     **certificate,
		      EVP_PKEY                 *pkey,
		      myproxy_request_t        *client_request,
		      myproxy_server_context_t *server_context) { 

  int             return_value = 1;  
  int             not_after;
  char          * userdn;

  X509           * cert = NULL;
  X509_NAME      * issuer = NULL;
  X509_NAME      * subject = NULL;
  X509_EXTENSION * ex = NULL;
  EVP_PKEY       * cakey = NULL;

  FILE * inkey = NULL;

  myproxy_debug("Generating certificate internally.");

  cert = X509_new();

  if (cert == NULL) {
    verror_put_string("Problem creating new X509.");
    goto error;
  }

  /* issuer info */

  issuer = X509_get_issuer_name(cert);

  tokenize_to_x509_name( server_context->certificate_issuer, issuer );

  /* subject info */

  /* this has already been called successfully, but... */
  
  if ( globus_gss_assist_map_local_user( client_request->username,
					 &userdn ) ) {
    verror_put_string("Could not resolve user to grid mapfile");
    goto error;
  }

  myproxy_debug("DN for user %s: %s", client_request->username, userdn);

  subject = X509_get_subject_name(cert);

  tokenize_to_x509_name( userdn, subject );

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

  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), (long)not_after);
  
  X509_set_pubkey(cert, pkey);

  /* extensions */

  ex = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
			   "critical,Digital Signature, Key Encipherment, Data Encipherment");

  X509_add_ext(cert,ex,-1);
  X509_EXTENSION_free(ex);

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

  if (!X509_sign(cert, cakey, EVP_md5() ) ) {
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
       ( server_context->certificate_issuer != NULL ) ) {
    verror_put_string("CA config error: both issuer and program defined");
    goto error;
  } 

  if ( ( server_context->certificate_issuer_program == NULL ) && 
       ( server_context->certificate_issuer == NULL ) ) {
    verror_put_string("CA config error: neither issuer or program defined");
    goto error;
  }

  if ( ( server_context->certificate_issuer != NULL ) && 
       ( server_context->certificate_issuer_key == NULL ) ) {
    verror_put_string("CA config error: issuer defined but no key defined");
    goto error;
  }

  if ( ( server_context->certificate_issuer != NULL ) && 
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

