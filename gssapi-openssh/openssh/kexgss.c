  /*
 * Copyright (c) 2001,2002 Simon Wilkinson. All rights reserved.
 *
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

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include "xmalloc.h"
#include "buffer.h"
#include "bufaux.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "ssh-gss.h"

/* This is now the same as the DH hash ... */

u_char *
kex_gssapi_hash(
    char *client_version_string,
    char *server_version_string,
    char *ckexinit, int ckexinitlen,
    char *skexinit, int skexinitlen,
    u_char *serverhostkeyblob, int sbloblen,
    BIGNUM *client_dh_pub,
    BIGNUM *server_dh_pub,
    BIGNUM *shared_secret)
{
	Buffer b;
	static u_char digest[EVP_MAX_MD_SIZE];
	EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX md;

	buffer_init(&b);
	buffer_put_string(&b, client_version_string, strlen(client_version_string));
	buffer_put_string(&b, server_version_string, strlen(server_version_string));

	/* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	buffer_put_int(&b, ckexinitlen+1);
	buffer_put_char(&b, SSH2_MSG_KEXINIT);
	buffer_append(&b, ckexinit, ckexinitlen);
	buffer_put_int(&b, skexinitlen+1);
	buffer_put_char(&b, SSH2_MSG_KEXINIT);
	buffer_append(&b, skexinit, skexinitlen);

	buffer_put_string(&b, serverhostkeyblob, sbloblen);
	buffer_put_bignum2(&b, client_dh_pub);
	buffer_put_bignum2(&b, server_dh_pub);
	buffer_put_bignum2(&b, shared_secret);

#ifdef DEBUG_KEX
	buffer_dump(&b);
#endif
	EVP_DigestInit(&md, evp_md);
	EVP_DigestUpdate(&md, buffer_ptr(&b), buffer_len(&b));
	EVP_DigestFinal(&md, digest, NULL);

	buffer_free(&b);

#ifdef DEBUG_KEX
	dump_digest("hash", digest, evp_md->md_size);
#endif
	return digest;
}

void
kexgss_client(Kex *kex)
{
	gss_buffer_desc gssbuf,send_tok,recv_tok, msg_tok, *token_ptr;
	Gssctxt ctxt;
	OM_uint32 maj_status, min_status, ret_flags;
	unsigned int klen, kout;
	DH *dh; 
	BIGNUM *dh_server_pub = 0;
	BIGNUM *shared_secret = 0;	
	unsigned char *kbuf;
	unsigned char *hash;
	unsigned char *serverhostkey;
	int type = 0;
	int first = 1;
	int slen = 0;
	
	/* Initialise our GSSAPI world */
	ssh_gssapi_build_ctx(&ctxt);
	if (ssh_gssapi_id_kex(&ctxt,kex->name)) {
		fatal("Couldn't identify host exchange");
	}
	if (ssh_gssapi_import_name(&ctxt,kex->host)) {
		fatal("Couldn't import hostname ");
	}
	
	/* This code should match that in ssh_dh1_client */
		
	/* Step 1 - e is dh->pub_key */
	dh = dh_new_group1();
	dh_gen_key(dh, kex->we_need * 8);

	/* This is f, we initialise it now to make life easier */
    	dh_server_pub = BN_new();
    	if (dh_server_pub == NULL) {
    		fatal("dh_server_pub == NULL");
    	}
    		
	token_ptr = GSS_C_NO_BUFFER;
			 
	do {
		debug("Calling gss_init_sec_context");
		
		maj_status=ssh_gssapi_init_ctx(&ctxt,
					       kex->options.gss_deleg_creds,
					       token_ptr,&send_tok,
					       &ret_flags);

		if (GSS_ERROR(maj_status)) {
			fatal("gss_init_context failed");
		} 

		/* If we've got an old receive buffer get rid of it */
		if (token_ptr != GSS_C_NO_BUFFER)
	  		(void) gss_release_buffer(&min_status, &recv_tok);
 	
		
		if (maj_status == GSS_S_COMPLETE) {
			/* If mutual state flag is not true, kex fails */
			if (!(ret_flags & GSS_C_MUTUAL_FLAG)) {
				fatal("Mutual authentication failed");
			}
			/* If integ avail flag is not true kex fails */
			if (!(ret_flags & GSS_C_INTEG_FLAG)) {
				fatal("Integrity check failed");
			}
		}
		
		/* If we have data to send, then the last message that we
		 * received cannot have been a 'complete'. */
		if (send_tok.length !=0) {
			if (first) {
				packet_start(SSH2_MSG_KEXGSS_INIT);
				packet_put_string(send_tok.value,
					  	  send_tok.length);
				packet_put_bignum2(dh->pub_key);
				first=0;
			} else {
				packet_start(SSH2_MSG_KEXGSS_CONTINUE);
				packet_put_string(send_tok.value,
						  send_tok.length);
			}
			packet_send();
			packet_write_wait();

			
			/* If we've sent them data, they'd better be polite
			 * and reply. */
		
			type = packet_read();
			switch (type) {
			case SSH2_MSG_KEXGSS_HOSTKEY:
				debug("Received KEXGSS_HOSTKEY");
				serverhostkey=packet_get_string(&slen);
				break;
			case SSH2_MSG_KEXGSS_CONTINUE:
				debug("Received GSSAPI_CONTINUE");
				if (maj_status == GSS_S_COMPLETE) 
					fatal("GSSAPI Continue received from server when complete");
				recv_tok.value=packet_get_string(&recv_tok.length);
				break;
			case SSH2_MSG_KEXGSS_COMPLETE:
				debug("Received GSSAPI_COMPLETE");
			        packet_get_bignum2(dh_server_pub);
			    	msg_tok.value=
			    	    packet_get_string(&msg_tok.length);

				/* Is there a token included? */
				if (packet_get_char()) {
					recv_tok.value=
					    packet_get_string(&recv_tok.length);
					/* If we're already complete - protocol error */
					if (maj_status == GSS_S_COMPLETE)
						packet_disconnect("Protocol error: received token when complete");
				} else {
				   	/* No token included */
				   	if (maj_status != GSS_S_COMPLETE)
				   		packet_disconnect("Protocol error: did not receive final token");
				}
				break;
			default:
				packet_disconnect("Protocol error: didn't expect packet type %d",
		    		type);
			}
			token_ptr=&recv_tok;
		}

    	} while (maj_status & GSS_S_CONTINUE_NEEDED);
    	
    	/* We _must_ have received a COMPLETE message in reply from the 
    	 * server, which will have set dh_server_pub and msg_tok */
    	 
    	if (type!=SSH2_MSG_KEXGSS_COMPLETE)
    	   fatal("Didn't receive a SSH2_MSG_KEXGSS_COMPLETE when I expected it");
    	 	    	
	/* Check f in range [1, p-1] */
        if (!dh_pub_is_valid(dh, dh_server_pub))
                        packet_disconnect("bad server public DH value");
                        
        /* compute K=f^x mod p */
        klen = DH_size(dh);
        kbuf = xmalloc(klen);
        kout = DH_compute_key(kbuf, dh_server_pub, dh);
        
        shared_secret = BN_new();
        BN_bin2bn(kbuf,kout, shared_secret);
        memset(kbuf, 0, klen);
        xfree(kbuf);
        
        hash = kex_gssapi_hash(
 	    kex->client_version_string,
            kex->server_version_string,
            buffer_ptr(&kex->my), buffer_len(&kex->my),
            buffer_ptr(&kex->peer), buffer_len(&kex->peer),
            serverhostkey, slen, /* server host key */
            dh->pub_key,	/* e */
            dh_server_pub,	/* f */
            shared_secret	/* K */
        );
        
        gssbuf.value=hash;
        gssbuf.length=20;
        
        /* Verify that H matches the token we just got. */
                if ((maj_status = gss_verify_mic(&min_status,
        	       		         ctxt.context,
        	                         &gssbuf,
        	                         &msg_tok,
        	                         NULL))) {

		packet_disconnect("Hash's MIC didn't verify");
      	}	
        
        DH_free(dh);
       	ssh_gssapi_delete_ctx(&ctxt);
        /* save session id */
        if (kex->session_id == NULL) {
        	kex->session_id_len = 20;
        	kex->session_id = xmalloc(kex->session_id_len);
        	memcpy(kex->session_id, hash, kex->session_id_len);
        }
        
	kex_derive_keys(kex, hash, shared_secret);
	BN_clear_free(shared_secret);
        kex_finish(kex);
}




void
kexgss_server(Kex *kex)
{

	OM_uint32 maj_status, min_status;
	
	/* Some GSSAPI implementations use the input value of ret_flags (an
 	 * output variable) as a means of triggering mechanism specific 
 	 * features. Initializing it to zero avoids inadvertently 
 	 * activating this non-standard behaviour.*/

	OM_uint32 ret_flags = 0;
	gss_buffer_desc gssbuf,send_tok,recv_tok,msg_tok;
	Gssctxt ctxt;
        unsigned int klen, kout;
        unsigned char *kbuf;
        unsigned char *hash;
        DH *dh;
        BIGNUM *shared_secret = NULL;
        BIGNUM *dh_client_pub = NULL;
	int type =0;
	
	/* Initialise GSSAPI */

	ssh_gssapi_build_ctx(&ctxt);
        if (ssh_gssapi_id_kex(&ctxt,kex->name))
		fatal("Unknown gssapi mechanism");
        if (ssh_gssapi_acquire_cred(&ctxt))
        	fatal("Unable to acquire credentials for the server");
                                                                                                                                
	do {
		debug("Wait SSH2_MSG_GSSAPI_INIT");
		type = packet_read();
		switch(type) {
		case SSH2_MSG_KEXGSS_INIT:
			if (dh_client_pub!=NULL) 
				fatal("Received KEXGSS_INIT after initialising");
			recv_tok.value=packet_get_string(&recv_tok.length);

		        dh_client_pub = BN_new();
		        
		        if (dh_client_pub == NULL)
        			fatal("dh_client_pub == NULL");
		  	packet_get_bignum2(dh_client_pub);
		  	
		  	/* Send SSH_MSG_KEXGSS_HOSTKEY here, if we want */
			break;
		case SSH2_MSG_KEXGSS_CONTINUE:
			if (dh_client_pub == NULL)
				fatal("Received KEXGSS_CONTINUE without initialising");
			recv_tok.value=packet_get_string(&recv_tok.length);
			break;
		default:
			packet_disconnect("Protocol error: didn't expect packet type %d",
					   type);
		}
		maj_status=ssh_gssapi_accept_ctx(&ctxt,&recv_tok, &send_tok,
						 &ret_flags);

		gss_release_buffer(&min_status,&recv_tok);
		
		if (maj_status & GSS_S_CONTINUE_NEEDED) {
			debug("Sending GSSAPI_CONTINUE");
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value,send_tok.length);
			packet_send();
			packet_write_wait();
			gss_release_buffer(&min_status, &send_tok);
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	if (GSS_ERROR(maj_status))
		fatal("gss_accept_context died");
	
	debug("gss_complete");
	if (!(ret_flags & GSS_C_MUTUAL_FLAG))
		fatal("mutual authentication flag wasn't set");
		
	if (!(ret_flags & GSS_C_INTEG_FLAG))
		fatal("Integrity flag wasn't set");
		
	
	dh = dh_new_group1();
	dh_gen_key(dh, kex->we_need * 8);
	
        if (!dh_pub_is_valid(dh, dh_client_pub))
                packet_disconnect("bad client public DH value");

        klen = DH_size(dh);
        kbuf = xmalloc(klen); 
        kout = DH_compute_key(kbuf, dh_client_pub, dh);

	shared_secret = BN_new();
	BN_bin2bn(kbuf, kout, shared_secret);
	memset(kbuf, 0, klen);
	xfree(kbuf);
	
        hash = kex_gssapi_hash(
            kex->client_version_string,
            kex->server_version_string,
            buffer_ptr(&kex->peer), buffer_len(&kex->peer),
            buffer_ptr(&kex->my), buffer_len(&kex->my),
            NULL, 0, /* Change this if we start sending host keys */
            dh_client_pub,
            dh->pub_key,
            shared_secret
	);
	BN_free(dh_client_pub);
		
	if (kex->session_id == NULL) {
		kex->session_id_len = 20;
		kex->session_id = xmalloc(kex->session_id_len);
		memcpy(kex->session_id, hash, kex->session_id_len);
	}
	                        
	gssbuf.value = hash;
	gssbuf.length = 20; /* Hashlen appears to always be 20 */
	
	if ((maj_status=gss_get_mic(&min_status,
			       ctxt.context,
			       GSS_C_QOP_DEFAULT,
			       &gssbuf,
			       &msg_tok))) {
		ssh_gssapi_error(maj_status,min_status);
		fatal("Couldn't get MIC");
	}	
			      
	packet_start(SSH2_MSG_KEXGSS_COMPLETE);
	packet_put_bignum2(dh->pub_key);
	packet_put_string((char *)msg_tok.value,msg_tok.length);

	if (send_tok.length!=0) {
		packet_put_char(1); /* true */
		packet_put_string((char *)send_tok.value,send_tok.length);
	} else {
		packet_put_char(0); /* false */
	}
 	packet_send();
	packet_write_wait();

	/* Store the client name, and the delegated credentials for later
	 * use */
	if (ssh_gssapi_getclient(&ctxt,&gssapi_client_type, 
				       &gssapi_client_name, 
				       &gssapi_client_creds)) {
		fatal("Couldn't convert client name");
	}
	
	gss_release_buffer(&min_status, &send_tok);	
	ssh_gssapi_delete_ctx(&ctxt);
	DH_free(dh);

	kex_derive_keys(kex, hash, shared_secret);
	BN_clear_free(shared_secret);
	kex_finish(kex);
}

void 
kexgss(Kex *kex)
{
	if (kex->server)
		kexgss_server(kex);
	else
		kexgss_client(kex);
}

#endif /* GSSAPI */
