/* open.c
 *
 * Copyright (c) 1996-2001 Mike Gleason, NCEMRSoft.
 * All rights reserved.
 *
 * Modified Mar 31, 2000 by JWB
 * Don't use the doAuth variable when GSSAPI is not defined
 *
 * Modified Feb 22, 2000 by JWB
 * Added GSSAPI calls / states to the authentication state machine
 * Force FTPQueryFeatures to run HELP SITE even if FEAT fails with an
 * unknown FTP server type.
 * Changed default port to be 2811 (gsiftp service)
 *
 * Modified June 7, 2000 by JWB
 * Parse gsiftp:// URLs with a different default port than ftp:// URLs
 */

#include "syshdrs.h"

#ifdef HAVE_GSSAPI
#ifdef WIN32
/*
 * For some reason we get a memory fault trying to read this value 
 * from the DLL, so include it here for now.
 */
static gss_OID_desc oids[] = {
   {10, "\052\206\110\206\367\022\001\002\001\004"},
};

gss_OID GSS_C_NT_HOSTBASED_SERVICE = oids+0;
#endif
#endif

static void
FTPDeallocateHost(const FTPCIPtr cip)
{
	/* Requires the cip->bufSize field set,
	 * and the cip->buf set if the
	 * buffer is allocated.
	 */
	if (cip->buf != NULL) {
		(void) memset(cip->buf, 0, cip->bufSize);
		free(cip->buf);
		cip->buf = NULL;
	}

	if (cip->startingWorkingDirectory != NULL) {
		free(cip->startingWorkingDirectory);
		cip->startingWorkingDirectory = NULL;
	}

#if USE_SIO
	DisposeSReadlineInfo(&cip->ctrlSrl);
#endif
	DisposeLineListContents(&cip->lastFTPCmdResultLL);
}	/* FTPDeallocateHost */





static int
FTPAllocateHost(const FTPCIPtr cip)
{
	char *buf;

	/* Requires the cip->bufSize field set,
	 * and the cip->buf cleared if the
	 * buffer is not allocated.
	 */
	if (cip->buf == NULL) {
		buf = (char *) calloc((size_t) 1, cip->bufSize);
		if (buf == NULL) {
			Error(cip, kDontPerror, "Malloc failed.\n");
			cip->errNo = kErrMallocFailed;
			return (kErrMallocFailed);
		}
		cip->buf = buf;
	}
	return (kNoErr);
}	/* FTPAllocateHost */




void
FTPInitializeOurHostName(const FTPLIPtr lip)
{
	if (lip == NULL)
		return;
	if (strcmp(lip->magic, kLibraryMagic))
		return;

	if (lip->htried == 0) {
		(void) memset(lip->ourHostName, 0, sizeof(lip->ourHostName));
		lip->hresult = GetOurHostName(lip->ourHostName, sizeof(lip->ourHostName));
	}
	lip->htried++;
}	/* FTPInitializeOurHostName */




void
FTPInitializeAnonPassword(const FTPLIPtr lip)
{
	if (lip == NULL)
		return;
	if (strcmp(lip->magic, kLibraryMagic))
		return;

	FTPInitializeOurHostName(lip);

	if (lip->defaultAnonPassword[0] == '\0') {
#ifdef SPAM_PROBLEM_HAS_BEEN_SOLVED_FOREVER
		GetUsrName(lip->defaultAnonPassword, sizeof(lip->defaultAnonPassword));
		(void) STRNCAT(lip->defaultAnonPassword, "@");

		/* Default to the "user@" notation
		 * supported by NcFTPd and wu-ftpd.
		 */
		if (lip->htried > 0)
			(void) STRNCAT(lip->defaultAnonPassword, lip->ourHostName);
#else
		(void) STRNCPY(lip->defaultAnonPassword, "NcFTP@");
#endif
	}
}	/* FTPInitializeAnonPassword */




int
FTPLoginHost(const FTPCIPtr cip)
{
	ResponsePtr rp;
	int result = kErrLoginFailed;
	int anonLogin;
	int sentpass = 0;
	int fwloggedin;
	int firstTime;
	char cwd[512];
#if HAVE_GSSAPI
	int i;
	char realhostname[128];
	struct hostent *hp;
	OM_uint32 maj_stat, min_stat;
	gss_name_t target_name = GSS_C_NO_NAME;
	gss_buffer_desc send_tok, recv_tok, *token_ptr;
	char stbuf[128+5];
	struct gss_channel_bindings_struct chan;
	gss_OID name_type;
	OM_uint32 req_flags = 0;
	char *gssapi_mech = NULL;
	gss_qop_t qop_state;
	int conf_state;
	char * service_name[] = {"ftp", "host", NULL};
	char **service_ptr = service_name+1; /* ftp@hostname doesn't seem to work */
#endif

	if (cip == NULL)
		return (kErrBadParameter);
	if ((cip->firewallType < kFirewallNotInUse) || (cip->firewallType > kFirewallLastType))
		return (kErrBadParameter);

	if (strcmp(cip->magic, kLibraryMagic))
		return (kErrBadMagic);

	anonLogin = 0;
	if (cip->user[0] == '\0')
		(void) STRNCPY(cip->user, "anonymous");
	if ((strcmp(cip->user, "anonymous") == 0) || (strcmp(cip->user, "ftp") == 0)) {
		anonLogin = 1;
		/* Try to get the email address if you didn't specify
		 * a password when the user is anonymous.
		 */
		if (cip->pass[0] == '\0') {
			FTPInitializeAnonPassword(cip->lip);
			(void) STRNCPY(cip->pass, cip->lip->defaultAnonPassword);
		}
	}

	rp = InitResponse();
	if (rp == NULL) {
		result = kErrMallocFailed;
		cip->errNo = kErrMallocFailed;
		goto done2;
	}

	for (firstTime = 1, fwloggedin = 0; ; ) {
		/* Here's a mini finite-automaton for the login process.
		 *
		 * Originally, the FTP protocol was designed to be entirely
		 * implementable from a FA.  It could be done, but I don't think
		 * it's something an interactive process could be the most
		 * effective with.
		 */

		if (firstTime != 0) {
			rp->code = 220;
#if HAVE_GSSAPI
			if (cip->port != 21) {
				cip->doAuth = 1;
			}
#endif
			firstTime = 0;
		} else if (result < 0) {
			goto done;
		}

		switch (rp->code) {
			case 220:	/* Welcome, ready for new user. */
#if HAVE_GSSAPI
				if ((cip->doAuth) && !cip->authenticated) {
					ReInitResponse(cip, rp),
					result = RCmd(cip, rp, "AUTH GSSAPI");
				} else
#endif
				if ((cip->firewallType == kFirewallNotInUse) || (fwloggedin != 0)) {
					ReInitResponse(cip, rp);
#if HAVE_GSSAPI
					if ((cip->doAuth) && cip->authenticated && strcmp(cip->user, "anonymous") == 0)
						result = RCmd(cip, rp, "USER :globus-mapping:");
					else

#endif
					result = RCmd(cip, rp, "USER %s", cip->user);
				} else if (cip->firewallType == kFirewallUserAtSite) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "USER %s@%s", cip->user, cip->host);
				} else if (cip->firewallType == kFirewallUserAtUserPassAtPass) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "USER %s@%s@%s", cip->user, cip->firewallUser, cip->host);
				} else if (cip->firewallType == kFirewallUserAtSiteFwuPassFwp) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "USER %s@%s %s", cip->user, cip->host, cip->firewallUser);
				} else if (cip->firewallType == kFirewallFwuAtSiteFwpUserPass) {
					/* only reached when !fwloggedin */
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "USER %s@%s", cip->firewallUser, cip->host);
				} else if (cip->firewallType > kFirewallNotInUse) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "USER %s", cip->firewallUser);
				} else {
					goto unknown;
				}
				break;

			case 230:	/* 230 User logged in, proceed. */
			case 231:	/* User name accepted. */
			case 202:	/* Command not implemented, superfluous at this site. */
				if ((cip->firewallType == kFirewallNotInUse) || (fwloggedin != 0))
					goto okay;

				/* Now logged in to the firewall. */
				fwloggedin++;

				if (cip->firewallType == kFirewallLoginThenUserAtSite) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "USER %s@%s", cip->user, cip->host);
				} else if (cip->firewallType == kFirewallUserAtUserPassAtPass) {
					goto okay;
				} else if (cip->firewallType == kFirewallOpenSite) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "OPEN %s", cip->host);
				} else if (cip->firewallType == kFirewallSiteSite) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "SITE %s", cip->host);
				} else if (cip->firewallType == kFirewallFwuAtSiteFwpUserPass) {
					/* only reached when !fwloggedin */
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "USER %s", cip->user);
				} else /* kFirewallUserAtSite */ {
					goto okay;
				}
				break;

			case 421:	/* 421 Service not available, closing control connection. */
				result = kErrHostDisconnectedDuringLogin;
				goto done;
				
			case 331:	/* 331 User name okay, need password. */
#if HAVE_GSSAPI
				if(cip->doAuth && cip->authenticated && cip->pass[0] == '\0' &&
					(strcmp(cip->user, ":globus-mapping:") == 0 || strcmp(cip->user, "anonymous") == 0)) {
					strcpy(cip->pass, "dummy");
				}

#endif
				if ((cip->firewallType == kFirewallNotInUse) || (fwloggedin != 0)) {
					if ((cip->pass[0] == '\0') && (cip->passphraseProc != NoGetPassphraseProc))
						(*cip->passphraseProc)(cip, &rp->msg, cip->pass, sizeof(cip->pass));
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "PASS %s", cip->pass);
				} else if (cip->firewallType == kFirewallUserAtSite) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "PASS %s", cip->pass);
				} else if (cip->firewallType == kFirewallUserAtUserPassAtPass) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "PASS %s@%s", cip->pass, cip->firewallPass);
				} else if (cip->firewallType == kFirewallUserAtSiteFwuPassFwp) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "PASS %s", cip->pass);
				} else if (cip->firewallType == kFirewallFwuAtSiteFwpUserPass) {
					/* only reached when !fwloggedin */
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "PASS %s", cip->firewallPass);
				} else if (cip->firewallType > kFirewallNotInUse) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "PASS %s", cip->firewallPass);
				} else {
					goto unknown;
				}
				sentpass++;
				break;
#if HAVE_GSSAPI
			case 334:	/* Using authentication type GSSAPI; ADAT must follow */
          				chan.initiator_addrtype = GSS_C_AF_INET; /* OM_uint32  */
          				chan.initiator_address.length = 4;
          				chan.initiator_address.value = &cip->ourCtlAddr.sin_addr.s_addr;
          				chan.acceptor_addrtype = GSS_C_AF_INET; /* OM_uint32 */
          				chan.acceptor_address.length = 4;
          				chan.acceptor_address.value = &cip->servCtlAddr.sin_addr.s_addr;
          				chan.application_data.length = 0;
          				chan.application_data.value = 0;

					/*
					 *  Look up actual host name, from connection IP.
					 */
#					if defined(INADDR_LOOPBACK)
					if (ntohl(cip->servCtlAddr.sin_addr.s_addr) == INADDR_LOOPBACK) {
					    gethostname(realhostname, sizeof(realhostname));
					    hp = gethostbyname(realhostname);

					    if (hp)
							strncpy(realhostname, hp->h_name, sizeof(realhostname));
					} else
#					endif
					{
						hp = gethostbyaddr((char *) &cip->servCtlAddr.sin_addr, 4, AF_INET);
						if (hp)
							strncpy(realhostname, hp->h_name, sizeof(realhostname));
						else
							strncpy(realhostname, cip->actualHost, sizeof(realhostname));
					}
					/*
					 * To work around the GSI GSSAPI library being case sensitive
					 * convert the hostname to lower case as noone seems to
					 * request uppercase name certificates.
					 */
					{
						int i;

						for (i=0; realhostname[i] && (i < sizeof(realhostname)) ; i++) {
							realhostname[i] = tolower(realhostname[i]);
						}
					}
					/* ftp@hostname first, the host@hostname */
					/* the V5 GSSAPI binding canonicalizes this for us... */
					sprintf(stbuf, "%s@%s", *service_ptr, realhostname);
					service_ptr++;

					name_type = GSS_C_NT_HOSTBASED_SERVICE;

					/* Do mutual authentication */
					req_flags |= GSS_C_MUTUAL_FLAG;

					/* Do limited delegation */
					req_flags |= GSS_C_MUTUAL_FLAG;
					req_flags |= GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG;

					send_tok.value = stbuf;
					send_tok.length = strlen(stbuf) + 1;
					maj_stat = gss_import_name(&min_stat, &send_tok, name_type, &target_name);
					if(maj_stat != GSS_S_COMPLETE) {
						goto unknown;
					}
					token_ptr = GSS_C_NO_BUFFER;
					cip->connectionContext = GSS_C_NO_CONTEXT;

			case 235:	/* authentication completed */
			case 335:	/* ADAT continue */

					/* Decode response LineList into gss buffer */
					if(rp->code == 235 || rp->code == 335) {
						char * in_buf;
						char * out_buf;
						int len = 0;
						char * p;

						in_buf = rp->msg.first->line;
						len = strlen(in_buf);

						out_buf = malloc((len + 1) * 6 / 8 + 1);
						radix_encode(in_buf + strlen("ADAT="), out_buf, &len, 1);

						recv_tok.value = out_buf;
						recv_tok.length = len;
						token_ptr = &recv_tok;
					}
					maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
									&cip->connectionContext,
									target_name,
									GSS_C_NULL_OID,
									req_flags,
									0,
									&chan,
									token_ptr,
									NULL,
									&send_tok,
									NULL,
									NULL);
					if(token_ptr != GSS_C_NO_BUFFER) {
						gss_release_buffer(&min_stat, token_ptr);
					}

					if(maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
						char * str;

						ReInitResponse(cip,rp);
						rp->code = 535;
						rp->codeType = 5;
						globus_gss_assist_display_status_str(&str, "Authentication Failure: ", maj_stat, min_stat, 0);
						(void) AddLine(&rp->msg, str);
						free(str);

						if((*service_ptr) != NULL) {
							/* Try again with the next service name prefix */
							DisposeLineListContents(&rp->msg);
							rp->code = 220;
							if(target_name != GSS_C_NO_NAME) {
								gss_release_name(&min_stat, &target_name);
								target_name = GSS_C_NO_NAME;
							}

							break;
						}
						
						result = kErrLoginFailed;

						goto done;
					}
					if(send_tok.length != 0) {
						int len = send_tok.length;
						int kerror;

						char * out_buf = malloc(send_tok.length * 8 / 6 + 4);

						kerror = radix_encode(send_tok.value, out_buf, &len, 0);
						if(kerror) {
							goto unknown;
						}
						ReInitResponse(cip, rp);
						result = RCmd(cip, rp, "ADAT %s", out_buf);
						free(out_buf);
						gss_release_buffer(&min_stat, &send_tok);
					}
					if(maj_stat == GSS_S_COMPLETE)
					{
						cip->authenticated = 1;
						rp->code = 220;
					}
					break;
			case 232:	/* 232 User logged in, authorized by security data exchange. */
				if(cip->doAuth && cip->authenticated) {
					if(cip->serverType == kServerTypeWuFTPd) {
						rp->code = 230;
					} else {
						rp->code = 331;
					}
				}
				break;
#endif
			case 332:	/* 332 Need account for login. */
			case 532: 	/* 532 Need account for storing files. */
				if ((cip->firewallType == kFirewallNotInUse) || (fwloggedin != 0)) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "ACCT %s", cip->acct);
				} else if (cip->firewallType == kFirewallUserAtSiteFwuPassFwp) {
					ReInitResponse(cip, rp);
					result = RCmd(cip, rp, "ACCT %s", cip->firewallPass);
				} else {
					/* ACCT not supported on firewall. */
					goto unknown;
				}
				break;

			case 530:	/* Not logged in. */
#if HAVE_GSSAPI
				if(cip->doAuth && !cip->authenticated) {
					if(sentpass == 0) {
						cip->doAuth = 0;
						rp->code = 220;
						break;
					}
				} 
#endif
				result = (sentpass != 0) ? kErrBadRemoteUserOrPassword : kErrBadRemoteUser;
				goto done;
#if HAVE_GSSAPI
			case 533:	/* Command protection level denied for policy reasons. */
			case 534: 	/* Request denied for policy reasons. */
			case 535: 	/* Failed security check (hash, sequence, etc). */
			case 536: 	/* Requested PROT level not supported by mechanism. */
			case 537: 	/* Command protection level not supported by security mechanism. */
#endif

			case 501:	/* Syntax error in parameters or arguments. */
			case 503:	/* Bad sequence of commands. */
			case 550:	/* Can't set guest privileges. */
			case 431: 	/* Need some unavailable resource to process security. */
				goto done;
				

			default:
			unknown:
				if (rp->msg.first == NULL) {
					Error(cip, kDontPerror, "Lost connection during login.\n");
				} else {
					Error(cip, kDontPerror, "Unexpected response: %s\n",
						rp->msg.first->line
					);
				}
				goto done;
		}
	}

okay:
	/* Do the application's connect message callback, if present. */
	if (cip->onLoginMsgProc != 0)
		(*cip->onLoginMsgProc)(cip, rp);
	DoneWithResponse(cip, rp);
	result = 0;
	cip->loggedIn = 1;

	/* Make a note of what our root directory is.
	 * This is often different from "/" when not
	 * logged in anonymously.
	 */
	if (cip->startingWorkingDirectory != NULL) {
		free(cip->startingWorkingDirectory);
		cip->startingWorkingDirectory = NULL;
	}
	if ((cip->doNotGetStartingWorkingDirectory == 0) &&
		(FTPGetCWD(cip, cwd, sizeof(cwd)) == kNoErr))
	{
		cip->startingWorkingDirectory = StrDup(cwd);
	}

	/* When a new site is opened, ASCII mode is assumed (by protocol). */
	cip->curTransferType = 'A';
	/* When a new site is opened, Authenticate only protection is assumed
	 * (by protocol).
	 */

	PrintF(cip, "Logged in to %s as %s.\n", cip->host, cip->user);

	/* Don't leave cleartext password in memory. */
	if ((anonLogin == 0) && (cip->leavePass == 0))
		(void) memset(cip->pass, '*', strlen(cip->pass));

	if (result < 0)
		cip->errNo = result;
#if HAVE_GSSAPI
	if(target_name != GSS_C_NO_NAME) {
		gss_release_name(&min_stat, &target_name);
	}
#endif
	return result;

done:
	DoneWithResponse(cip, rp);

done2:
	/* Don't leave cleartext password in memory. */
	if ((anonLogin == 0) && (cip->leavePass == 0))
		(void) memset(cip->pass, '*', strlen(cip->pass));
	if (result < 0)
		cip->errNo = result;
#if HAVE_GSSAPI
	if(target_name != GSS_C_NO_NAME) {
		gss_release_name(&min_stat, &target_name);
	}
#endif
	return result;
}	/* FTPLoginHost */




static void
FTPExamineMlstFeatures(const FTPCIPtr cip, const char *features)
{
	char buf[256], *feat;
	int flags;

	flags = 0;
	STRNCPY(buf, features);
	feat = strtok(buf, ";*");
	while (feat != NULL) {
		if (ISTRNEQ(feat, "OS.", 3))
			feat += 3;
		if (ISTREQ(feat, "type")) {
			flags |= kMlsOptType;
		} else if (ISTREQ(feat, "size")) {
			flags |= kMlsOptSize;
		} else if (ISTREQ(feat, "modify")) {
			flags |= kMlsOptModify;
		} else if (ISTREQ(feat, "UNIX.mode")) {
			flags |= kMlsOptUNIXmode;
		} else if (ISTREQ(feat, "UNIX.owner")) {
			flags |= kMlsOptUNIXowner;
		} else if (ISTREQ(feat, "UNIX.group")) {
			flags |= kMlsOptUNIXgroup;
		} else if (ISTREQ(feat, "perm")) {
			flags |= kMlsOptPerm;
		} else if (ISTREQ(feat, "UNIX.uid")) {
			flags |= kMlsOptUNIXuid;
		} else if (ISTREQ(feat, "UNIX.gid")) {
			flags |= kMlsOptUNIXgid;
		} else if (ISTREQ(feat, "UNIX.gid")) {
			flags |= kMlsOptUnique;
		}
		feat = strtok(NULL, ";*");
	}

	cip->mlsFeatures = flags;
}	/* FTPExamineMlstFeatures */




int
FTPQueryFeatures(const FTPCIPtr cip)
{
	ResponsePtr rp;
	int result;
	LinePtr lp;
	char *cp, *p;

	if (cip == NULL)
		return (kErrBadParameter);
	if (strcmp(cip->magic, kLibraryMagic))
		return (kErrBadMagic);

	if (cip->serverType == kServerTypeNetWareFTP) {
		/* NetWare 5.00 server freaks out when
		 * you give it a command it doesn't
		 * recognize, so cheat here and return.
		 */
		cip->hasPASV = kCommandAvailable;
		cip->hasSIZE = kCommandNotAvailable;
		cip->hasMDTM = kCommandNotAvailable;
		cip->hasREST = kCommandNotAvailable;
		cip->NLSTfileParamWorks = kCommandAvailable;
		cip->hasUTIME = kCommandNotAvailable;
		cip->hasCLNT = kCommandNotAvailable;
		cip->hasMLST = kCommandNotAvailable;
		cip->hasMLSD = kCommandNotAvailable;
		return (kNoErr);
	}

	rp = InitResponse();
	if (rp == NULL) {
		cip->errNo = kErrMallocFailed;
		result = cip->errNo;
	} else {
		rp->printMode = (kResponseNoPrint|kResponseNoSave);
		result = RCmd(cip, rp, "FEAT");
		if (result < kNoErr) {
			DoneWithResponse(cip, rp);
			return (result);
		} else if (result != 2) {
			/* We cheat here and pre-populate some
			 * fields when the server is wu-ftpd.
			 * This server is very common and we
			 * know it has always had these.
			 */
			 if (cip->serverType == kServerTypeWuFTPd) {
				cip->hasPASV = kCommandAvailable;
				cip->hasSIZE = kCommandAvailable;
				cip->hasMDTM = kCommandAvailable;
				cip->hasREST = kCommandAvailable;
				cip->NLSTfileParamWorks = kCommandAvailable;
			} else if (cip->serverType == kServerTypeNcFTPd) {
				cip->hasPASV = kCommandAvailable;
				cip->hasSIZE = kCommandAvailable;
				cip->hasMDTM = kCommandAvailable;
				cip->hasREST = kCommandAvailable;
				cip->NLSTfileParamWorks = kCommandAvailable;
			}

			/* Newer commands are only shown in FEAT,
			 * so we don't have to do the "try it,
			 * then save that it didn't work" thing.
			 */
			cip->hasMLST = kCommandNotAvailable;
			cip->hasMLSD = kCommandNotAvailable;
			result = 0;
		} else {
			cip->hasFEAT = kCommandAvailable;

			for (lp = rp->msg.first; lp != NULL; lp = lp->next) {
				/* If first character was not a space it is
				 * either:
				 *
				 * (a) The header line in the response;
				 * (b) The trailer line in the response;
				 * (c) A protocol violation.
				 */
				cp = lp->line;
				if (*cp++ != ' ')
					continue;
				if (ISTRNCMP(cp, "PASV", 4) == 0) {
					cip->hasPASV = kCommandAvailable;
				} else if (ISTRNCMP(cp, "SIZE", 4) == 0) {
					cip->hasSIZE = kCommandAvailable;
				} else if (ISTRNCMP(cp, "MDTM", 4) == 0) {
					cip->hasMDTM = kCommandAvailable;
				} else if (ISTRNCMP(cp, "REST", 4) == 0) {
					cip->hasREST = kCommandAvailable;
				} else if (ISTRNCMP(cp, "UTIME", 5) == 0) {
					cip->hasUTIME = kCommandAvailable;
				} else if (ISTRNCMP(cp, "MLST", 4) == 0) {
					cip->hasMLST = kCommandAvailable;
					cip->hasMLSD = kCommandAvailable;
					FTPExamineMlstFeatures(cip, cp + 5);
				} else if (ISTRNCMP(cp, "CLNT", 4) == 0) {
					cip->hasCLNT = kCommandAvailable;
#if HAVE_GSSAPI
				} else if(ISTRNCMP( cp, "DCAU", 4) == 0) {
					cip->hasDCAU = kCommandAvailable;
					cip->hasPROT = kCommandAvailable;
					cip->hasPBSZ = kCommandAvailable;
					cip->curProtectionLevel = kProtectionLevelAuthenticated;
#endif
				} else if (ISTRNCMP(cp, "Compliance Level: ", 18) == 0) {
					/* Probably only NcFTPd will ever implement this.
					 * But we use it internally to differentiate
					 * between different NcFTPd implementations of
					 * IETF extensions.
					 */
					cip->ietfCompatLevel = atoi(cp + 18);
				}
			}
		}

		ReInitResponse(cip, rp);
		result = RCmd(cip, rp, "HELP SITE");
		if (result == 2) {
			for (lp = rp->msg.first; lp != NULL; lp = lp->next) {
				cp = lp->line;
				if (strstr(cp, "RETRBUFSIZE") != NULL)
					cip->hasRETRBUFSIZE = kCommandAvailable;
				if (strstr(cp, "RBUFSZ") != NULL)
					cip->hasRBUFSZ = kCommandAvailable;
				/* See if RBUFSIZ matches (but not STORBUFSIZE) */
				if (
					((p = strstr(cp, "RBUFSIZ")) != NULL) &&
					(
					 	(p == cp) ||
						((p > cp) && (!isupper(p[-1])))
					)
				)
					cip->hasRBUFSIZ = kCommandAvailable;
				if (strstr(cp, "STORBUFSIZE") != NULL)
					cip->hasSTORBUFSIZE = kCommandAvailable;
				if (strstr(cp, "SBUFSIZ") != NULL)
					cip->hasSBUFSIZ = kCommandAvailable;
				if (strstr(cp, "SBUFSZ") != NULL)
					cip->hasSBUFSZ = kCommandAvailable;
				if (strstr(cp, "BUFSIZE") != NULL)
					cip->hasBUFSIZE = kCommandAvailable;
			}
		}
		DoneWithResponse(cip, rp);
	}

	return (kNoErr);
}	/* FTPQueryFeatures */



int
FTPCloseHost(const FTPCIPtr cip)
{
	ResponsePtr rp;
	int result;

	if (cip == NULL)
		return (kErrBadParameter);
	if (strcmp(cip->magic, kLibraryMagic))
		return (kErrBadMagic);

	/* Data connection shouldn't be open normally. */
	if (cip->dataSocket != kClosedFileDescriptor)
		FTPAbortDataTransfer(cip);

	result = kNoErr;
	if (cip->connected != 0) {
		rp = InitResponse();
		if (rp == NULL) {
			cip->errNo = kErrMallocFailed;
			result = cip->errNo;
		} else {
			rp->eofOkay = 1;	/* We are expecting EOF after this cmd. */
			cip->eofOkay = 1;
			(void) RCmd(cip, rp, "QUIT");
			DoneWithResponse(cip, rp);
		}
	}
	
	CloseControlConnection(cip);

	/* Dispose dynamic data structures, so you won't leak
	 * if you OpenHost with this again.
	 */
	FTPDeallocateHost(cip);
	return (result);
}	/* FTPCloseHost */




void
FTPShutdownHost(const FTPCIPtr cip)
{
#ifdef SIGPIPE
	FTPSigProc osigpipe;
#endif

	if (cip == NULL)
		return;
	if (strcmp(cip->magic, kLibraryMagic))
		return;

#ifdef SIGPIPE
	osigpipe = signal(SIGPIPE, (FTPSigProc) SIG_IGN);
#endif

	/* Linger could cause close to block, so unset it. */
	if (cip->dataSocket != kClosedFileDescriptor)
		(void) SetLinger(cip, cip->dataSocket, 0);
	CloseDataConnection(cip);	/* Shouldn't be open normally. */

	/* Linger should already be turned off for this. */
	CloseControlConnection(cip);

	FTPDeallocateHost(cip);

#ifdef SIGPIPE
	(void) signal(SIGPIPE, (FTPSigProc) osigpipe);
#endif
}	/* FTPShutdownHost */




void
URLCopyToken(char *dst, size_t dsize, const char *src, size_t howmuch)
{
	char *dlim;
	const char *slim;
	unsigned int hc;
	int c;
	char h[4];

	dlim = dst + dsize - 1;		/* leave room for \0 */
	slim = src + howmuch;
	while (src < slim) {
		c = *src++;
		if (c == '\0')
			break;
		if (c == '%') {
			/* hex representation */
			if (src < slim + 2) {
				h[0] = *src++;
				h[1] = *src++;
				h[2] = '\0';
				hc = 0xeeff;
				if ((sscanf(h, "%x", &hc) >= 0) && (hc != 0xeeff)) {
					if (dst < dlim) {
						*(unsigned char *)dst = (unsigned char) hc;
						dst++;
					}
				}
			} else {
				break;
			}
		} else {
			*dst++ = (char) c;
		}
	}
	*dst = '\0';
}	/* URLCopyToken */




int
FTPDecodeURL(
	const FTPCIPtr cip,	/* area pointed to may be modified */
	char *const url,	/* always modified */
	LineListPtr cdlist,	/* always modified */
	char *const fn,		/* always modified */
	const size_t fnsize,
	int *const xtype,	/* optional; may be modified */
	int *const wantnlst	/* optional; always modified */
)
{
	char *cp;
	char *hstart, *hend;
	char *h2start;
	char *at1;
	char portstr[32];
	int port;
	int sc;
	char *lastslash;
	char *parsestr;
	char *tok;
	char subdir[128];
	char *semi;
	int default_port = 0;

	InitLineList(cdlist);
	*fn = '\0';
	if (wantnlst != NULL)
		*wantnlst = 0;
	if (xtype != NULL)
		*xtype = kTypeBinary;

	cp = NULL;	/* shut up warnings */
#ifdef HAVE_STRCASECMP
	if (strncasecmp(url, "<URL:ftp://", 11) == 0) {
		cp = url + strlen(url) - 1;
		if (*cp != '>')
			return (kMalformedURL);	/* missing closing > */
		*cp = '\0';
		cp = url + 11;
		default_port = 21;
	} else if (strncasecmp(url, "ftp://", 6) == 0) {
		cp = url + 6;
		default_port = 21;
	} else if (strncasecmp(url, "<URL:gsiftp://", 14) == 0) {
		cp = url + strlen(url) - 1;
		if(*cp != '>')
			return (kMalformedURL); /* missing closing > */
		*cp = '\0';
		cp = url + 14;
		default_port = 2811;
#if HAVE_GSSAPI
		cip->doAuth = 1;
#endif
	} else if (strncasecmp(url, "gsiftp://", 9) == 0) {
		cp = url + 9;
		default_port = 2811;
#if HAVE_GSSAPI
		cip->doAuth = 1;
#endif
	} else {
		return (-1);		/* not a RFC 1738 URL */
	}
#else	/* HAVE_STRCASECMP */
	if (strncmp(url, "<URL:ftp://", 11) == 0) {
		cp = url + strlen(url) - 1;
		if (*cp != '>')
			return (kMalformedURL);	/* missing closing > */
		*cp = '\0';
		cp = url + 11;
		default_port = 21;
	} else if (strncmp(url, "ftp://", 6) == 0) {
		cp = url + 6;
		default_port = 21;
	} else if (strncmp(url, "<URL:gsiftp://", 14) == 0) {
		cp = url + strlen(url) - 1;
		if(*cp != '>')
			return (kMalformedURL); /* missing closing > */
		*cp = '\0';
		cp = url + 14;
		default_port = 2811;
#if HAVE_GSSAPI
		cip->doAuth = 1;
#endif
	} else if (strncmp(url, "gsiftp://", 9) == 0) {
		cp = url + 9;
		default_port = 2811;
#if HAVE_GSSAPI
		cip->doAuth = 1;
#endif
	} else {
		return (-1);		/* not a RFC 1738 URL */
	}
#endif	/* HAVE_STRCASECMP */

	/* //<user>:<password>@<host>:<port>/<url-path> */

	at1 = NULL;
	for (hstart = cp; ; cp++) {
		if (*cp == '@') {
			if (at1 == NULL)
				at1 = cp;
			else 
				return (kMalformedURL);
		} else if ((*cp == '\0') || (*cp == '/')) {
			hend = cp;
			break;
		}
	}

	sc = *hend;
	*hend = '\0';
	if (at1 == NULL) {
		/* no user or password */
		h2start = hstart;
	} else {
		*at1 = '\0';
		cp = strchr(hstart, ':');
		if (cp == NULL) {
			/* whole thing is the user name then */
			URLCopyToken(cip->user, sizeof(cip->user), hstart, (size_t) (at1 - hstart));
		} else if (strchr(cp + 1, ':') != NULL) {
			/* Too many colons */
			return (kMalformedURL);
		} else {
			URLCopyToken(cip->user, sizeof(cip->user), hstart, (size_t) (cp - hstart));
			URLCopyToken(cip->pass, sizeof(cip->pass), cp + 1, (size_t) (at1 - (cp + 1)));
		}
		*at1 = '@';
		h2start = at1 + 1;
	}

	cp = strchr(h2start, ':');
	if (cp == NULL) {
		/* whole thing is the host then */
		cip->port = default_port;
		URLCopyToken(cip->host, sizeof(cip->host), h2start, (size_t) (hend - h2start));
	} else if (strchr(cp + 1, ':') != NULL) {
		/* Too many colons */
		return (kMalformedURL);
	} else {
		URLCopyToken(cip->host, sizeof(cip->host), h2start, (size_t) (cp - h2start));
		URLCopyToken(portstr, sizeof(portstr), cp + 1, (size_t) (hend - (cp + 1)));
		port = default_port;
		port = atoi(portstr);
		if (port > 0)
			cip->port = port;
	}

	*hend = (char) sc;
	if ((*hend == '\0') || ((*hend == '/') && (hend[1] == '\0'))) {
		/* no path, okay */
		return (0);
	}

	lastslash = strrchr(hend, '/');
	if (lastslash == NULL) {
		/* no path, okay */
		return (0);
	}	
	*lastslash = '\0';

	if ((semi = strchr(lastslash + 1, ';')) != NULL) {
		*semi++ = '\0';
#ifdef HAVE_STRCASECMP
		if (strcasecmp(semi, "type=i") == 0) {
			if (xtype != NULL)
				*xtype = kTypeBinary;
		} else if (strcasecmp(semi, "type=a") == 0) {
			if (xtype != NULL)
				*xtype = kTypeAscii;
		} else if (strcasecmp(semi, "type=b") == 0) {
			if (xtype != NULL)
				*xtype = kTypeBinary;
		} else if (strcasecmp(semi, "type=d") == 0) {
			if (wantnlst != NULL) {
				*wantnlst = 1;
				if (xtype != NULL)
					*xtype = kTypeAscii;
			} else {
				/* You didn't want these. */
				return (kMalformedURL);
			}
		}
#else	/* HAVE_STRCASECMP */
		if (strcmp(semi, "type=i") == 0) {
			if (xtype != NULL)
				*xtype = kTypeBinary;
		} else if (strcmp(semi, "type=a") == 0) {
			if (xtype != NULL)
				*xtype = kTypeAscii;
		} else if (strcmp(semi, "type=b") == 0) {
			if (xtype != NULL)
				*xtype = kTypeBinary;
		} else if (strcmp(semi, "type=d") == 0) {
			if (wantnlst != NULL) {
				*wantnlst = 1;
				if (xtype != NULL)
					*xtype = kTypeAscii;
			} else {
				/* You didn't want these. */
				return (kMalformedURL);
			}
		}
#endif	/* HAVE_STRCASECMP */
	}
	URLCopyToken(fn, fnsize, lastslash + 1, strlen(lastslash + 1));
	for (parsestr = hend; (tok = strtok(parsestr, "/")) != NULL; parsestr = NULL) {
		URLCopyToken(subdir, sizeof(subdir), tok, strlen(tok));
		(void) AddLine(cdlist, subdir);
	}
	*lastslash = '/';
	return (kNoErr);
}	/* FTPDecodeURL */




int
FTPOpenHost(const FTPCIPtr cip)
{
	int result;
	time_t t0, t1;
	int elapsed;
	int dials;

	if (cip == NULL)
		return (kErrBadParameter);
	if (strcmp(cip->magic, kLibraryMagic))
		return (kErrBadMagic);

	if (cip->host[0] == '\0') {
		cip->errNo = kErrBadParameter;
		return (kErrBadParameter);
	}

	for (	result = kErrConnectMiscErr, dials = 0;
		cip->maxDials < 0 || dials < cip->maxDials;
		dials++)
	{
		/* Allocate (or if the host was closed, reallocate)
		 * the transfer data buffer.
		 */
		result = FTPAllocateHost(cip);
		if (result < 0)
			return (result);

		if (dials > 0)
			PrintF(cip, "Retry Number: %d\n", dials);
		if (cip->redialStatusProc != 0)
			(*cip->redialStatusProc)(cip, kRedialStatusDialing, dials);
		(void) time(&t0);
		result = OpenControlConnection(cip, cip->host, cip->port);
		(void) time(&t1);
		if (result == kNoErr) {
			/* We were hooked up successfully. */
			PrintF(cip, "Connected to %s.\n", cip->host);

			result = FTPLoginHost(cip);
			if (result == kNoErr) {
				(void) FTPQueryFeatures(cip);
				break;
			}

			/* Close and try again. */
			(void) FTPCloseHost(cip);

			/* Originally we also stopped retyring if
			 * we got kErrBadRemoteUser and non-anonymous,
			 * but some FTP servers apparently do their
			 * max user check after the username is sent.
			 */
			if (result == kErrBadRemoteUserOrPassword /* || (result == kErrBadRemoteUser) */) {
				if (strcmp(cip->user, "anonymous") != 0) {
					/* Non-anonymous login was denied, and
					 * retrying is not going to help.
					 */
					break;
				}
			}
		} else if ((result != kErrConnectRetryableErr) && (result != kErrConnectRefused) && (result != kErrRemoteHostClosedConnection)) {
			/* Irrecoverable error, so don't bother redialing.
			 * The error message should have already been printed
			 * from OpenControlConnection().
			 */
			PrintF(cip, "Cannot recover from miscellaneous open error %d.\n", result);
			return result;
		}

		/* Retryable error, wait and then redial. */
		if (cip->redialDelay > 0) {
			/* But don't sleep if this is the last loop. */
			if ((cip->maxDials < 0) || (dials < (cip->maxDials - 1))) {
				elapsed = (int) (t1 - t0);
				if (elapsed < cip->redialDelay) {
					PrintF(cip, "Sleeping %u seconds.\n",
						(unsigned) cip->redialDelay - elapsed);
					if (cip->redialStatusProc != 0)
						(*cip->redialStatusProc)(cip, kRedialStatusSleeping, cip->redialDelay - elapsed);
					(void) sleep((unsigned) cip->redialDelay - elapsed);
				}
			}
		}
	}
	return (result);
}	/* FTPOpenHost */




int
FTPOpenHostNoLogin(const FTPCIPtr cip)
{
	int result;
	time_t t0, t1;
	int elapsed;
	int dials;

	if (cip == NULL)
		return (kErrBadParameter);
	if (strcmp(cip->magic, kLibraryMagic))
		return (kErrBadMagic);

	if (cip->host[0] == '\0') {
		cip->errNo = kErrBadParameter;
		return (kErrBadParameter);
	}

	for (	result = kErrConnectMiscErr, dials = 0;
		cip->maxDials < 0 || dials < cip->maxDials;
		dials++)
	{

		/* Allocate (or if the host was closed, reallocate)
		 * the transfer data buffer.
		 */
		result = FTPAllocateHost(cip);
		if (result < 0)
			return (result);

		if (dials > 0)
			PrintF(cip, "Retry Number: %d\n", dials);
		if (cip->redialStatusProc != 0)
			(*cip->redialStatusProc)(cip, kRedialStatusDialing, dials);
		(void) time(&t0);
		result = OpenControlConnection(cip, cip->host, cip->port);
		(void) time(&t1);
		if (result == kNoErr) {
			/* We were hooked up successfully. */
			PrintF(cip, "Connected to %s.\n", cip->host);

			/* Not logging in... */
			if (result == kNoErr)
				break;
		} else if ((result != kErrConnectRetryableErr) && (result != kErrConnectRefused) && (result != kErrRemoteHostClosedConnection)) {
			/* Irrecoverable error, so don't bother redialing.
			 * The error message should have already been printed
			 * from OpenControlConnection().
			 */
			PrintF(cip, "Cannot recover from miscellaneous open error %d.\n", result);
			return result;
		}

		/* Retryable error, wait and then redial. */
		if (cip->redialDelay > 0) {
			/* But don't sleep if this is the last loop. */
			if ((cip->maxDials < 0) || (dials < (cip->maxDials - 1))) {
				elapsed = (int) (t1 - t0);
				if (elapsed < cip->redialDelay) {
					PrintF(cip, "Sleeping %u seconds.\n",
						(unsigned) cip->redialDelay - elapsed);
					if (cip->redialStatusProc != 0)
						(*cip->redialStatusProc)(cip, kRedialStatusSleeping, cip->redialDelay - elapsed);
					(void) sleep((unsigned) cip->redialDelay - elapsed);
				}
			}
		}
	}
	return (result);
}	/* FTPOpenHostNoLogin */




int
FTPInitConnectionInfo(const FTPLIPtr lip, const FTPCIPtr cip, size_t bufSize)
{
	size_t siz;

	if ((lip == NULL) || (cip == NULL) || (bufSize == 0))
		return (kErrBadParameter);

	siz = sizeof(FTPConnectionInfo);
	(void) memset(cip, 0, siz);

	if (strcmp(lip->magic, kLibraryMagic))
		return (kErrBadMagic);

	cip->buf = NULL;	/* denote that it needs to be allocated. */
	cip->bufSize = bufSize;
	cip->port = lip->defaultPort;
	cip->firewallPort = lip->defaultPort;
	cip->maxDials = kDefaultMaxDials;
	cip->redialDelay = kDefaultRedialDelay;
	cip->xferTimeout = kDefaultXferTimeout;
	cip->connTimeout = kDefaultConnTimeout;
	cip->ctrlTimeout = kDefaultCtrlTimeout;
	cip->abortTimeout = kDefaultAbortTimeout;
	cip->ctrlSocketR = kClosedFileDescriptor;
	cip->ctrlSocketW = kClosedFileDescriptor;
	cip->dataPortMode = kSendPortMode;
	cip->dataSocket = kClosedFileDescriptor;
	cip->lip = lip;
	cip->hasPASV = kCommandAvailabilityUnknown;
	cip->hasSIZE = kCommandAvailabilityUnknown;
	cip->hasMDTM = kCommandAvailabilityUnknown;
	cip->hasREST = kCommandAvailabilityUnknown;
	cip->hasNLST_d = kCommandAvailabilityUnknown;
	cip->hasUTIME = kCommandAvailabilityUnknown;
	cip->hasFEAT = kCommandAvailabilityUnknown;
	cip->hasMLSD = kCommandAvailabilityUnknown;
	cip->hasMLST = kCommandAvailabilityUnknown;
	cip->hasCLNT = kCommandAvailabilityUnknown;
	cip->hasRETRBUFSIZE = kCommandAvailabilityUnknown;
	cip->hasRBUFSIZ = kCommandAvailabilityUnknown;
	cip->hasRBUFSZ = kCommandAvailabilityUnknown;
	cip->hasSTORBUFSIZE = kCommandAvailabilityUnknown;
	cip->hasSBUFSIZ = kCommandAvailabilityUnknown;
	cip->hasSBUFSZ = kCommandAvailabilityUnknown;
	cip->STATfileParamWorks = kCommandAvailabilityUnknown;
	cip->NLSTfileParamWorks = kCommandAvailabilityUnknown;
	cip->firewallType = kFirewallNotInUse;
	cip->startingWorkingDirectory = NULL;
	cip->doAuth = 1;
	cip->authenticated = 0;
	cip->hasPROT = kCommandAvailabilityUnknown;
	cip->hasPBSZ = kCommandAvailabilityUnknown;
	cip->connectionContext = GSS_C_NO_CONTEXT;
	cip->protectionLevel = kProtectionLevelClear;
	cip->curProtectionLevel = kProtectionLevelClear;

	(void) STRNCPY(cip->magic, kLibraryMagic);
	(void) STRNCPY(cip->user, "anonymous");
	return (kNoErr);
}	/* FTPInitConnectionInfo */




int
FTPRebuildConnectionInfo(const FTPLIPtr lip, const FTPCIPtr cip)
{
	char *buf;

	cip->lip = lip;
	cip->debugLog = NULL;
	cip->errLog = NULL;
	cip->debugLogProc = NULL;
	cip->errLogProc = NULL;
	cip->buf = NULL;
	cip->cin = NULL;
	cip->cout = NULL;
	cip->errNo = 0;
	cip->progress = NULL;
	cip->rname = NULL;
	cip->lname = NULL;
	cip->onConnectMsgProc = NULL;
	cip->redialStatusProc = NULL;
	cip->printResponseProc = NULL;
	cip->onLoginMsgProc = NULL;
	cip->passphraseProc = NULL;
	cip->startingWorkingDirectory = NULL;
	cip->asciiFilenameExtensions = NULL;

	(void) memset(&cip->lastFTPCmdResultLL, 0, sizeof(LineList));

	/* Allocate a new buffer. */
	buf = (char *) calloc((size_t) 1, cip->bufSize);
	if (buf == NULL) {
		cip->errNo = kErrMallocFailed;
		return (kErrMallocFailed);
	}
	cip->buf = buf;

	/* Reattach the FILE pointers for use with the Std I/O library
	 * routines.
	 */
	if ((cip->cin = fdopen(cip->ctrlSocketR, "r")) == NULL) {
		cip->errNo = kErrFdopenR;
		cip->ctrlSocketR = kClosedFileDescriptor;
		cip->ctrlSocketW = kClosedFileDescriptor;
		return (kErrFdopenR);
	}

	if ((cip->cout = fdopen(cip->ctrlSocketW, "w")) == NULL) {
		CloseFile(&cip->cin);
		cip->errNo = kErrFdopenW;
		cip->ctrlSocketR = kClosedFileDescriptor;
		cip->ctrlSocketW = kClosedFileDescriptor;
		return (kErrFdopenW);
	}

#if USE_SIO
	if (InitSReadlineInfo(&cip->ctrlSrl, cip->ctrlSocketR, cip->srlBuf, sizeof(cip->srlBuf), (int) cip->ctrlTimeout, 1) < 0) {
		cip->errNo = kErrFdopenW;
		CloseFile(&cip->cin);
		cip->errNo = kErrFdopenW;
		cip->ctrlSocketR = kClosedFileDescriptor;
		cip->ctrlSocketW = kClosedFileDescriptor;
		return (kErrFdopenW);
	}
#endif
	return (kNoErr);
}	/* FTPRebuildConnectionInfo */




int
FTPInitLibrary(const FTPLIPtr lip)
{
	struct servent *ftp;	

	if (lip == NULL)
		return (kErrBadParameter);

	(void) memset(lip, 0, sizeof(FTPLibraryInfo));
#ifdef HAVE_GSSAPI
	if ((ftp = getservbyname("gsiftp", "tcp")) == NULL)
#else
	if ((ftp = getservbyname("ftp", "tcp")) == NULL)
#endif
		lip->defaultPort = (unsigned int) kDefaultFTPPort;
	else
		lip->defaultPort = (unsigned int) ntohs(ftp->s_port);

	lip->init = 1;
	(void) STRNCPY(lip->magic, kLibraryMagic);

	/* We'll initialize the defaultAnonPassword field
	 * later when we try the first anon ftp connection.
	 */

#ifdef HAVE_LIBSOCKS
	SOCKSinit("libncftp");
	lip->socksInit = 1;
#endif
	return (kNoErr);
}	/* FTPInitLibrary */

/* Open.c */
