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

#ifndef _SSH_GSS_H
#define _SSH_GSS_H

#ifdef GSSAPI

#include "kex.h"
#include "buffer.h"

#include <gssapi.h>

#ifndef MECHGLUE
#ifdef KRB5
#ifndef HEIMDAL
#include <gssapi_generic.h>

/* MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#ifndef GSS_C_NT_HOSTBASED_SERVICE
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif /* GSS_C_NT_... */
#endif /* !HEIMDAL */
#endif /* KRB5 */
#endif /* !MECHGLUE */

/* draft-ietf-secsh-gsskeyex-03 */
#define SSH2_MSG_KEXGSS_INIT				30
#define SSH2_MSG_KEXGSS_CONTINUE 			31
#define SSH2_MSG_KEXGSS_COMPLETE 			32
#define SSH2_MSG_KEXGSS_HOSTKEY				33
#define SSH2_MSG_KEXGSS_ERROR				34
#define SSH2_MSG_USERAUTH_GSSAPI_RESPONSE     		60
#define SSH2_MSG_USERAUTH_GSSAPI_TOKEN        		61
#define SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63    
#define SSH2_MSG_USERAUTH_GSSAPI_ERROR			64  

#define KEX_GSS_SHA1					"gss-group1-sha1-"

enum ssh_gss_id {
#ifdef KRB5
	GSS_KERBEROS,
#endif
#ifdef GSI
	GSS_GSI,
#endif /* GSI */
	GSS_LAST_ENTRY
};

typedef struct ssh_gss_mech_struct {
        char *enc_name;
        char *name;
        gss_OID_desc oid;
} ssh_gssapi_mech;

typedef struct {
	OM_uint32	status; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	name; /* both */
	gss_OID		oid; /* both */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* server */
} Gssctxt;

extern ssh_gssapi_mech supported_mechs[];
extern gss_buffer_desc gssapi_client_name;
extern gss_cred_id_t   gssapi_client_creds;
extern enum ssh_gss_id gssapi_client_type;

char *ssh_gssapi_mechanisms(int server, char *host);
gss_OID ssh_gssapi_id_kex(Gssctxt *ctx, char *name);
void ssh_gssapi_set_oid_data(Gssctxt *ctx, void *data, size_t len);
void ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid);
void ssh_gssapi_supported_oids(gss_OID_set *oidset);
enum ssh_gss_id ssh_gssapi_get_ctype(Gssctxt *ctxt);

OM_uint32 ssh_gssapi_import_name(Gssctxt *ctx, const char *host);
OM_uint32 ssh_gssapi_acquire_cred(Gssctxt *ctx);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *ctx, int deleg_creds,
			      gss_buffer_desc *recv_tok, 
			      gss_buffer_desc *send_tok, OM_uint32 *flags);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *ctx,
				gss_buffer_desc *recv_tok,
				gss_buffer_desc *send_tok,
				OM_uint32 *flags);
OM_uint32 ssh_gssapi_getclient(Gssctxt *ctx,
				enum ssh_gss_id *type,
				gss_buffer_desc *name,
				gss_cred_id_t *creds);
void ssh_gssapi_error(gss_OID mech,
		      OM_uint32 major_status, OM_uint32 minor_status);
void ssh_gssapi_send_error(gss_OID mech,
			   OM_uint32 major_status,OM_uint32 minor_status);
void ssh_gssapi_build_ctx(Gssctxt **ctx);
void ssh_gssapi_delete_ctx(Gssctxt **ctx);
OM_uint32 ssh_gssapi_client_ctx(Gssctxt **ctx,gss_OID oid,char *host);
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **ctx,gss_OID oid);

/* In the client */
void ssh_gssapi_client(Kex *kex, char *host, struct sockaddr *hostaddr,
                       Buffer *client_kexinit, Buffer *server_kexinit);

/* In the server */
int ssh_gssapi_userok(char *name);
int ssh_gssapi_localname(char **lname);
void ssh_gssapi_server(Kex *kex, Buffer *client_kexinit, 
		       Buffer *server_kexinit);

OM_uint32 ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_desc *buffer, 
					gss_buffer_desc *hash);

void ssh_gssapi_do_child(char ***envp, u_int *envsizep);                 
void ssh_gssapi_cleanup_creds(void *ignored);
void ssh_gssapi_storecreds();
void ssh_gssapi_clean_env();

#ifdef GSI
int gsi_gridmap(char *subject_name, char **mapped_name);
#ifdef _HAVE_GSI_EXTENDED_GSSAPI
#define HAVE_GSSAPI_EXT
#endif
#endif

#ifdef MECHGLUE
void gss_initialize();
gss_cred_id_t __gss_get_mechanism_cred
   (gss_cred_id_t,	/* union_cred */
    gss_OID		/* mech_type */
   );
#ifndef _HAVE_GSI_EXTENDED_GSSAPI
#define HAVE_GSSAPI_EXT
OM_uint32 gss_export_cred
    (OM_uint32 *,        /* minor_status */
     const gss_cred_id_t,/* cred_handle */
     const gss_OID,      /* desired mech */
     OM_uint32,          /* option req */
     gss_buffer_t);      /* output buffer */
#endif
#endif
#endif /* GSSAPI */

#endif /* _SSH_GSS_H */
