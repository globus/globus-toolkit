/*
 * Copyright (c) 2001,2002 Simon Wilkinson. All rights reserved. *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef GSSAPI

#include "ssh.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "buffer.h"
#include "bufaux.h"
#include "packet.h"
#include "compat.h"
#include <openssl/evp.h>
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "compat.h"
#include "monitor_wrap.h"

#include <netdb.h>

#include "ssh-gss.h"

/* Assorted globals for tracking the clients identity once they've
 * authenticated */
 
gss_buffer_desc gssapi_client_name = {0,NULL}; /* Name of our client */
gss_cred_id_t   gssapi_client_creds = GSS_C_NO_CREDENTIAL; /* Their credentials */
enum ssh_gss_id gssapi_client_type = GSS_LAST_ENTRY;

unsigned char ssh1_key_digest[16]; /* used for ssh1 gssapi */

/* The mechanism name used in the list below is defined in the internet
 * draft as the Base 64 encoding of the MD5 hash of the ASN.1 DER encoding 
 * of the underlying GSSAPI mechanism's OID.
 *
 * Also from the draft, before considering adding SPNEGO, bear in mind that
 * "mechanisms ... MUST NOT use SPNEGO as the underlying GSSAPI mechanism"
 */

/* These must be in the same order as ssh_gss_id, in ssh-gss.h */

ssh_gssapi_mech supported_mechs[]= {
#ifdef KRB5
 /* Official OID - 1.2.850.113554.1.2.2 */
 {"Se3H81ismmOC3OE+FwYCiQ==","Kerberos",
 	{9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"}},
#endif
#ifdef GSI
 /* gssapi_ssleay 1.3.6.1.4.1.3536.1.1 */
 {"N3+k7/4wGxHyuP8Yxi4RhA==",
  "GSI",
  {9, "\x2B\x06\x01\x04\x01\x9B\x50\x01\x01"}
 },
#endif /* GSI */
 {NULL,NULL,{0,0}}
};

char gssprefix[]=KEX_GSS_SHA1;

/* Return a list of the gss-group1-sha1-x mechanisms supported by this
 * program.
 *
 * We only support the mechanisms that we've indicated in the list above,
 * but we check that they're supported by the GSSAPI mechanism on the 
 * machine. We also check, before including them in the list, that
 * we have the necesary information in order to carry out the key exchange
 * (that is, that the user has credentials, the server's creds are accessible,
 * etc)
 *
 * The way that this is done is fairly nasty, as we do a lot of work that
 * is then thrown away. This should possibly be implemented with a cache
 * that stores the results (in an expanded Gssctxt structure), which are
 * then used by the first calls if that key exchange mechanism is chosen.
 */
 
char * 
ssh_gssapi_mechanisms(int server,char *host) {
	gss_OID_set 	supported;
	OM_uint32	maj_status, min_status;
	Buffer		buf;
	int 		i = 0;
	int		present;
	char *		mechs;
	Gssctxt *	ctx = NULL;	

	if (datafellows & SSH_OLD_GSSAPI) return NULL;
	
	gss_indicate_mechs(&min_status, &supported);
	
	buffer_init(&buf);	

	do {
		if ((maj_status=gss_test_oid_set_member(&min_status,
						   	&supported_mechs[i].oid,
						   	supported,
						   	&present))) {
			present=0;
		}
		if (present) {
		    	if ((server && 
		    	     !GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctx,
		    	  			            &supported_mechs[i].oid)))) 
		    	    || (!server &&
		    	        !GSS_ERROR(ssh_gssapi_client_ctx(&ctx,
		    	 			       &supported_mechs[i].oid,
		    	 			       host)))) {
				/* Append gss_group1_sha1_x to our list */
				buffer_append(&buf, gssprefix,
					      strlen(gssprefix));
		        	buffer_append(&buf, 
		        		      supported_mechs[i].enc_name,
	        	      		      strlen(supported_mechs[i].enc_name));
	               }
 		}
	} while (supported_mechs[++i].name != NULL);
	
	buffer_put_char(&buf,'\0');
	
	mechs=xmalloc(buffer_len(&buf));
	buffer_get(&buf,mechs,buffer_len(&buf));
	buffer_free(&buf);
	if (strlen(mechs)==0)
	   return(NULL);
	else
	   return(mechs);
}

void ssh_gssapi_supported_oids(gss_OID_set *oidset) {
	enum ssh_gss_id i =0;
	OM_uint32 maj_status,min_status;
	int present;
	gss_OID_set supported;
	
	gss_create_empty_oid_set(&min_status,oidset);
	gss_indicate_mechs(&min_status, &supported);

	while (supported_mechs[i].name!=NULL) {
		if ((maj_status=gss_test_oid_set_member(&min_status,
						       &supported_mechs[i].oid,
						       supported,
						       &present))) {
			present=0;
		}
		if (present) {
			gss_add_oid_set_member(&min_status,
					       &supported_mechs[i].oid,
				       	       oidset);	
		}
		i++;
	}
}	

/* Set the contexts OID from a data stream */
void ssh_gssapi_set_oid_data(Gssctxt *ctx, void *data, size_t len) { 
  if (ctx->oid != GSS_C_NO_OID) {
	xfree(ctx->oid->elements);
   	xfree(ctx->oid);
  }
  ctx->oid=xmalloc(sizeof(gss_OID_desc));
  ctx->oid->length=len;
  ctx->oid->elements=xmalloc(len);
  memcpy(ctx->oid->elements,data,len);
}

/* Set the contexts OID */
void ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid) {  
  ssh_gssapi_set_oid_data(ctx,oid->elements,oid->length);
}

/* Find out which GSS type (out of the list we define in ssh-gss.h) a
 * particular connection is using 
 */
enum ssh_gss_id ssh_gssapi_get_ctype(Gssctxt *ctxt) {
	enum ssh_gss_id i=0;
	
	while(supported_mechs[i].name!=NULL) {
	   if (supported_mechs[i].oid.length == ctxt->oid->length &&
	       (memcmp(supported_mechs[i].oid.elements,
		       ctxt->oid->elements,ctxt->oid->length) == 0))
	       return i;
	   i++;
	}
	return(GSS_LAST_ENTRY);
}

/* Set the GSS context's OID to the oid indicated by the given key exchange
 * name. */
gss_OID ssh_gssapi_id_kex(Gssctxt *ctx, char *name) {
  enum ssh_gss_id i=0;
  
  if (strncmp(name, gssprefix, strlen(gssprefix)-1) !=0) {
     return(NULL);
  }
  
  name+=strlen(gssprefix); /* Move to the start of the MIME string */
  
  while (supported_mechs[i].name!=NULL &&
  	 strcmp(name,supported_mechs[i].enc_name)!=0) {
  	i++;
  }

  if (supported_mechs[i].name==NULL)
     return (NULL);

  if (ctx) ssh_gssapi_set_oid(ctx,&supported_mechs[i].oid);

  return &supported_mechs[i].oid;
}


/* All this effort to report an error ... */
static void
ssh_gssapi_error_ex(OM_uint32 major_status,OM_uint32 minor_status,
		    int send_packet) {
	OM_uint32 lmaj, lmin;
        gss_buffer_desc msg;
        OM_uint32 ctx;
        
        ctx = 0;
	/* The GSSAPI error */
        do {
        	lmaj = gss_display_status(&lmin, major_status,
        				  GSS_C_GSS_CODE,
        				  GSS_C_NULL_OID,
        				  &ctx, &msg);
        	if (lmaj == GSS_S_COMPLETE) {
        	    	debug((char *)msg.value);
			if (send_packet) packet_send_debug((char *)msg.value);
        	    	(void) gss_release_buffer(&lmin, &msg);
        	}
        } while (ctx!=0);	   

        /* The mechanism specific error */
        do {
        	lmaj = gss_display_status(&lmin, minor_status,
        				  GSS_C_MECH_CODE,
        				  GSS_C_NULL_OID,
        				  &ctx, &msg);
        	if (lmaj == GSS_S_COMPLETE) {
        	    	debug((char *)msg.value);
			if (send_packet) packet_send_debug((char *)msg.value);
        	    	(void) gss_release_buffer(&lmin, &msg);
        	}
        } while (ctx!=0);
}

void
ssh_gssapi_error(OM_uint32 major_status,OM_uint32 minor_status) {
    ssh_gssapi_error_ex(major_status, minor_status, 0);
}

void
ssh_gssapi_send_error(OM_uint32 major_status,OM_uint32 minor_status) {
    ssh_gssapi_error_ex(major_status, minor_status, 1);
}




/* Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
void
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx=xmalloc(sizeof (Gssctxt));
	(*ctx)->context=GSS_C_NO_CONTEXT;
	(*ctx)->name=GSS_C_NO_NAME;
	(*ctx)->oid=GSS_C_NO_OID;
	(*ctx)->creds=GSS_C_NO_CREDENTIAL;
	(*ctx)->client=GSS_C_NO_NAME;
	(*ctx)->client_creds=GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
void
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;
	
	/* Return if there's no context */
	if ((*ctx)==NULL)
		return;
		
	if ((*ctx)->context != GSS_C_NO_CONTEXT) 
		gss_delete_sec_context(&ms,&(*ctx)->context,GSS_C_NO_BUFFER);
	if ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms,&(*ctx)->name);
	if ((*ctx)->oid != GSS_C_NO_OID) {
		xfree((*ctx)->oid->elements);
		xfree((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	if ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms,&(*ctx)->creds);
	if ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms,&(*ctx)->client);	
	if ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms,&(*ctx)->client_creds);
	
	xfree(*ctx);
	*ctx=NULL; 
}

/* Wrapper to init_sec_context 
 * Requires that the context contains:
 *	oid
 * 	server name (from ssh_gssapi_import_name)
 */
OM_uint32 
ssh_gssapi_init_ctx(Gssctxt *ctx, int deleg_creds, gss_buffer_desc *recv_tok,
       	      	    gss_buffer_desc* send_tok, OM_uint32 *flags) 
{
      	OM_uint32 maj_status, min_status;
	int deleg_flag = 0;
	
	if (deleg_creds) {
		deleg_flag=GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}
	      	
      	maj_status=gss_init_sec_context(&min_status,
      					GSS_C_NO_CREDENTIAL, /* def. cred */
      					&ctx->context,
      					ctx->name,
      					ctx->oid,
      					GSS_C_MUTUAL_FLAG |
      					GSS_C_INTEG_FLAG |
      					deleg_flag,
      					0, /* default lifetime */
      					NULL, /* no channel bindings */
      					recv_tok,
      					NULL,
      					send_tok,
      					flags,
      					NULL);
	ctx->status=maj_status;
      	if (GSS_ERROR(maj_status)) {
      		ssh_gssapi_error(maj_status,min_status);
      	}
      	return(maj_status);
}

/* Wrapper arround accept_sec_context
 * Requires that the context contains:
 *    oid		
 *    credentials	(from ssh_gssapi_acquire_cred)
 */
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *ctx,gss_buffer_desc *recv_tok,
				gss_buffer_desc *send_tok, OM_uint32 *flags) 
{
	OM_uint32 maj_status, min_status;
	gss_OID mech;
	
	maj_status=gss_accept_sec_context(&min_status,
					  &ctx->context,
					  ctx->creds,
					  recv_tok,
					  GSS_C_NO_CHANNEL_BINDINGS,
					  &ctx->client,
					  &mech,
					  send_tok,
					  flags,
					  NULL,
					  &ctx->client_creds);
	if (GSS_ERROR(maj_status)) {
		ssh_gssapi_send_error(maj_status,min_status);
	}
	
	if (ctx->client_creds) {
		debug("Received some client credentials");
	} else {
		debug("Got no client credentials");
	}

	/* FIXME: We should check that the me
	 * the one that we asked for (in ctx->oid) */

	ctx->status=maj_status;
	
	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */
	
	if (((flags==NULL) || ((*flags & GSS_C_MUTUAL_FLAG) && 
	                       (*flags & GSS_C_INTEG_FLAG))) &&
	    (maj_status == GSS_S_COMPLETE)) {
		if (ssh_gssapi_getclient(ctx,&gssapi_client_type,
	  			         &gssapi_client_name,
	  			         &gssapi_client_creds))
	  		fatal("Couldn't convert client name");
	}

	return(maj_status);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, const char *host) {
	gss_buffer_desc gssbuf;
	OM_uint32 maj_status, min_status;
	struct hostent *hostinfo = NULL;
	char *xhost;
	
	/* Make a copy of the host name, in case it was returned by a
	 * previous call to gethostbyname(). */	
	xhost = xstrdup(host);

	/* Make sure we have the FQDN. Some GSSAPI implementations don't do
	 * this for us themselves */
	
	hostinfo = gethostbyname(xhost);
	
	if ((hostinfo == NULL) || (hostinfo->h_name == NULL)) {
		debug("Unable to get FQDN for \"%s\"", xhost);
	} else {
		xfree(xhost);
		xhost = xstrdup(hostinfo->h_name);
	}
		
        gssbuf.length = sizeof("host@")+strlen(xhost);

        gssbuf.value = xmalloc(gssbuf.length);
        if (gssbuf.value == NULL) {
		xfree(xhost);
		return(-1);
        }
        snprintf(gssbuf.value,gssbuf.length,"host@%s",xhost);
        if ((maj_status=gss_import_name(&min_status,
                                   	&gssbuf,
                                        GSS_C_NT_HOSTBASED_SERVICE,
                                        &ctx->name))) {
		ssh_gssapi_error(maj_status,min_status);
	}
	
	xfree(xhost);
	xfree(gssbuf.value);
	return(maj_status);
}

/* Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */
 
/* Returns a GSSAPI error code */
OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx) {
	OM_uint32 maj_status, min_status;
	char lname[MAXHOSTNAMELEN];
	gss_OID_set oidset;
	
	gss_create_empty_oid_set(&min_status,&oidset);
	gss_add_oid_set_member(&min_status,ctx->oid,&oidset);
	
        if (gethostname(lname, MAXHOSTNAMELEN)) {
                return(-1);
        }

	if ((maj_status=ssh_gssapi_import_name(ctx,lname))) {
		return(maj_status);
	}
	if ((maj_status=gss_acquire_cred(&min_status,
			 	    ctx->name,
				    0,
				    oidset,
				    GSS_C_ACCEPT,
				    &ctx->creds,
				    NULL,
				    NULL))) {
		ssh_gssapi_error(maj_status,min_status);
	}
				
	gss_release_oid_set(&min_status, &oidset);
	return(maj_status);
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

OM_uint32 
ssh_gssapi_getclient(Gssctxt *ctx, enum ssh_gss_id *type,
		     gss_buffer_desc *name, gss_cred_id_t *creds) {

	OM_uint32 maj_status,min_status;
	
	*type=ssh_gssapi_get_ctype(ctx);
	if ((maj_status=gss_display_name(&min_status,ctx->client,name,NULL))) {
		ssh_gssapi_error(maj_status,min_status);
	}
	
	/* This is icky. There appears to be no way to copy this structure,
	 * rather than the pointer to it, so we simply copy the pointer and
	 * mark the originator as empty so we don't destroy it. 
	 */
	*creds=ctx->client_creds;
	ctx->client_creds=GSS_C_NO_CREDENTIAL;
	return(maj_status);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_desc *buffer, gss_buffer_desc *hash) {
	OM_uint32 maj_status,min_status;
	
	/* ssh1 needs to exchange the hash of the keys */
	/* will us this hash to return it */
	if (!compat20) {
		if ((maj_status=gss_wrap(&min_status,ctx->context,
					0,
					GSS_C_QOP_DEFAULT,
					buffer,
					NULL,
					hash)))
			ssh_gssapi_error(maj_status,min_status);
	}
	else

	if ((maj_status=gss_get_mic(&min_status,ctx->context,
				    GSS_C_QOP_DEFAULT, buffer, hash))) {
		ssh_gssapi_error(maj_status,min_status);
	}
	
	return(maj_status);
}

OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx,gss_OID oid) {
	if (*ctx) ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx,oid);
	return(ssh_gssapi_acquire_cred(*ctx));
}

OM_uint32 
ssh_gssapi_client_ctx(Gssctxt **ctx,gss_OID oid, char *host) {
	gss_buffer_desc token;
	OM_uint32 major,minor;
	
	if (*ctx) ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx,oid);
	ssh_gssapi_import_name(*ctx,host);
	major=ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token, NULL);
	gss_release_buffer(&minor,&token);
	return(major);
}
                                                                                        
#endif /* GSSAPI */
