/* ncftpls.c
 *
 * Copyright (c) 1999-2000 Mike Gleason, NCEMRSoft.
 * All rights reserved.
 *
 * A non-interactive utility to list directories on a remote FTP server.
 * Very useful in shell scripts!
 */

#include "syshdrs.h"

#if defined(WIN32) || defined(_WINDOWS)
#	include "..\ncftp\getopt.h"
#	define getopt Getopt
#	define optarg gOptArg
#	define optind gOptInd
	WSADATA wsaData;
	int wsaInit = 0;

	__inline void DisposeWinsock(int aUNUSED) { if (wsaInit > 0) WSACleanup(); wsaInit--; }
#	include "..\ncftp\util.h"
#	include "..\ncftp\spool.h"
#	include "..\ncftp\pref.h"
#	include "..\ncftp\getline.h"
#else
#	include "../ncftp/util.h"
#	include "../ncftp/spool.h"
#	include "../ncftp/pref.h"
#	include "../ncftp/getline.h"
#endif

#include "gpshare.h"


FTPLibraryInfo gLib;
FTPConnectionInfo fi;

extern int gFirewallType;
extern char gFirewallHost[64];
extern char gFirewallUser[32];
extern char gFirewallPass[32];
extern unsigned int gFirewallPort;
extern char gFirewallExceptionList[256];
extern int gFwDataPortMode;
extern char gOS[], gVersion[];

extern char *optarg;
extern int optind;

static void
Usage(void)
{
	FILE *fp;

	fp = OpenPager();
	(void) fprintf(fp, "NcFTPLs %.5s\n\n", gVersion + 11);
	(void) fprintf(fp, "Usages:\n");
	(void) fprintf(fp, "  ncftpls [FTP flags] [-x \"ls flags\"] ftp://url.style.host/path/name/\n");
	(void) fprintf(fp, "\nls Flags:\n\
  -1     Most basic format, one item per line.\n\
  -l     Long list format.\n\
  -x XX  Other flags to pass on to the remote server.\n");
	(void) fprintf(fp, "\nFTP Flags:\n\
  -u XX  Use username XX instead of anonymous.\n\
  -p XX  Use password XX with the username.\n\
  -P XX  Use port number XX instead of the default FTP service port (21).\n\
  -j XX  Use account XX with the account (deprecated).\n\
  -d XX  Use the file XX for debug logging.\n");
	(void) fprintf(fp, "\
  -t XX  Timeout after XX seconds.\n\
  -f XX  Read the file XX for user and password information.\n\
  -E     Use regular (PORT) data connections.\n\
  -F     Use passive (PASV) data connections (default).\n\
  -K     Show disk usage by attempting SITE DF.\n");
	(void) fprintf(fp, "\
  -W XX  Send raw FTP command XX after logging in.\n\
  -X XX  Send raw FTP command XX after each listing.\n\
  -Y XX  Send raw FTP command XX before logging out.\n\
  -r XX  Redial XX times until connected.\n");
	(void) fprintf(fp, "\nExamples:\n\
  ncftpls ftp://ftp.wustl.edu/pub/\n\
  ncftpls -1 ftp://ftp.wustl.edu/pub/\n\
  ncftpls -x \"-lrt\" ftp://ftp.wustl.edu/pub/\n");

	(void) fprintf(fp, "\nLibrary version: %s.\n", gLibNcFTPVersion + 5);
	(void) fprintf(fp, "\nThis is a freeware program by Mike Gleason (mgleason@ncftp.com).\n");
	(void) fprintf(fp, "This was built using LibNcFTP (http://www.ncftp.com/libncftp).\n");

	ClosePager(fp);
	DisposeWinsock(0);
	exit(kExitUsage);
}	/* Usage */




static void
Abort(int UNUSED(sigNum))
{
	LIBNCFTP_USE_VAR(sigNum);
	signal(SIGINT, Abort);

	/* Hopefully the I/O operation in progress
	 * will complete, and we'll abort before
	 * it starts a new block.
	 */
	fi.cancelXfer++;

	/* If the user appears to be getting impatient,
	 * restore the default signal handler so the
	 * next ^C abends the program.
	 */
	if (fi.cancelXfer >= 2)
		signal(SIGINT, SIG_DFL);
}	/* Abort */




static void
SetLsFlags(char *dst, size_t dsize, int *longMode, const char *src)
{
	char *dlim = dst + dsize - 1;
	int i, c;

	for (i=0;;) {
		c = *src++;
		if (c == '\0')
			break;
		if (c == 'l') {
			*longMode = 1;
		} else if (c == '1') {
			*longMode = 0;
		} else if (c != '-') {
			if (c == 'C') {
				*longMode = 0;
			}
			if (i == 0) {
				if (dst < dlim)
					*dst++ = '-';
			} 
			i++;
			if (dst < dlim)
				*dst++ = (char) c;
		}
	}
	*dst = '\0';
}	/* SetLsFlags */




int
main(int argc, char **argv)
{
	int result, c;
	FTPConnectionInfo savedfi;
	FTPConnectionInfo startfi;
	const char * volatile errstr;
	volatile ExitStatus es;
	char url[256];
	char urlfile[128];
	char rootcwd[256];
	char curcwd[256];
	int longMode = 0;
	volatile int i;
	char lsflag[32] = "";
	LineList cdlist;
	LinePtr lp;
	int rc;
	volatile int ndirs;
	int dfmode = 0;
	ResponsePtr rp;
	FILE *ofp;
	char precmd[128], postcmd[128], perfilecmd[128];

	InitWinsock();
#ifdef SIGPOLL
	NcSignal(SIGPOLL, (FTPSigProc) SIG_IGN);
#endif
	result = FTPInitLibrary(&gLib);
	if (result < 0) {
		(void) fprintf(stderr, "ncftpls: init library error %d (%s).\n", result, FTPStrError(result));
		DisposeWinsock(0);
		exit(kExitInitLibraryFailed);
	}
	result = FTPInitConnectionInfo(&gLib, &fi, kDefaultFTPBufSize);
	if (result < 0) {
		(void) fprintf(stderr, "ncftpls: init connection info error %d (%s).\n", result, FTPStrError(result));
		DisposeWinsock(0);
		exit(kExitInitConnInfoFailed);
	}

	InitUserInfo();
	fi.dataPortMode = kFallBackToSendPortMode;
	LoadFirewallPrefs(0);
	if (gFwDataPortMode >= 0)
		fi.dataPortMode = gFwDataPortMode;
	fi.debugLog = NULL;
	fi.errLog = stderr;
	fi.xferTimeout = 60 * 60;
	fi.connTimeout = 30;
	fi.ctrlTimeout = 135;
	(void) STRNCPY(fi.user, "anonymous");
	fi.host[0] = '\0';
	urlfile[0] = '\0';
	InitLineList(&cdlist);
	SetLsFlags(lsflag, sizeof(lsflag), &longMode, "-CF");
	precmd[0] = '\0';
	postcmd[0] = '\0';
	perfilecmd[0] = '\0';
	es = kExitSuccess;

	while ((c = getopt(argc, argv, "1lx:P:u:j:p:e:d:t:r:f:EFKW:X:Y:")) > 0) switch(c) {
		case 'P':
			fi.port = atoi(optarg);	
			break;
		case 'u':
			(void) STRNCPY(fi.user, optarg);
			memset(optarg, '*', strlen(fi.user));
			break;
		case 'j':
			(void) STRNCPY(fi.acct, optarg);
			memset(optarg, '*', strlen(fi.acct));
			break;
		case 'p':
			(void) STRNCPY(fi.pass, optarg);	/* Don't recommend doing this! */
			memset(optarg, '*', strlen(fi.pass));
			break;
		case 'e':
			if (strcmp(optarg, "stdout") == 0)
				fi.errLog = stdout;
			else if (optarg[0] == '-')
				fi.errLog = stdout;
			else if (strcmp(optarg, "stderr") == 0)
				fi.errLog = stderr;
			else
				fi.errLog = fopen(optarg, "a");
			break;
		case 'd':
			if (strcmp(optarg, "stdout") == 0)
				fi.debugLog = stdout;
			else if (optarg[0] == '-')
				fi.debugLog = stdout;
			else if (strcmp(optarg, "stderr") == 0)
				fi.debugLog = stderr;
			else
				fi.debugLog = fopen(optarg, "a");
			break;
		case 't':
			SetTimeouts(&fi, optarg);
			break;
		case 'r':
			SetRedial(&fi, optarg);
			break;
		case 'f':
			ReadConfigFile(optarg, &fi);
			break;
		case 'E':
			fi.dataPortMode = kSendPortMode;
			break;
		case 'F':
			fi.dataPortMode = kPassiveMode;
			break;
		case 'l':
			SetLsFlags(lsflag, sizeof(lsflag), &longMode, "-l");
			break;
		case '1':
			SetLsFlags(lsflag, sizeof(lsflag), &longMode, "-1");
			break;
		case 'x':
			SetLsFlags(lsflag, sizeof(lsflag), &longMode, optarg);
			break;
		case 'K':
			dfmode++;
			break;
		case 'W':
			STRNCPY(precmd, optarg);
			break;
		case 'X':
			STRNCPY(perfilecmd, optarg);
			break;
		case 'Y':
			STRNCPY(postcmd, optarg);
			break;
		default:
			Usage();
	}
	if (optind > argc - 1)
		Usage();

	InitOurDirectory();

	startfi = fi;
	memset(&savedfi, 0, sizeof(savedfi));
	ndirs = argc - optind;
	for (i=optind; i<argc; i++) {
		fi = startfi;
		(void) STRNCPY(url, argv[i]);
		rc = FTPDecodeURL(&fi, url, &cdlist, urlfile, sizeof(urlfile), (int *) 0, NULL);
		(void) STRNCPY(url, argv[i]);
		if (rc == kMalformedURL) {
			(void) fprintf(stderr, "Malformed URL: %s\n", url);
			DisposeWinsock(0);
			exit(kExitMalformedURL);
		} else if (rc == kNotURL) {
			(void) fprintf(stderr, "Not a URL: %s\n", url);
			DisposeWinsock(0);
			exit(kExitMalformedURL);
		} else if (urlfile[0] != '\0') {
			/* It not obviously a directory, and they didn't say -R. */
			(void) fprintf(stderr, "Not a directory URL: %s\n", url);
			DisposeWinsock(0);
			exit(kExitMalformedURL);
		}
		
		if ((strcmp(fi.host, savedfi.host) == 0) && (strcmp(fi.user, savedfi.user) == 0)) {
			fi = savedfi;
			
			/* This host is currently open, so keep using it. */
			if (FTPChdir(&fi, rootcwd) < 0) {
				FTPPerror(&fi, fi.errNo, kErrCWDFailed, "ncftpls: Could not chdir to", rootcwd);
				es = kExitChdirFailed;
				DisposeWinsock(0);
				exit((int) es);
			}
		} else {
			if (savedfi.connected != 0) {
				errstr = "could not run post-command remote host";
				(void) AdditionalCmd(&fi, postcmd, NULL);

				errstr = "could not close remote host";
				(void) FTPCloseHost(&savedfi);
			}
			memset(&savedfi, 0, sizeof(savedfi));
			
			if (strcmp(fi.user, "anonymous") && strcmp(fi.user, "ftp")) {
				if (fi.pass[0] == '\0') {
					(void) gl_getpass("Password: ", fi.pass, sizeof(fi.pass));
				}
			}
			
			if (MayUseFirewall(fi.host, gFirewallType, gFirewallExceptionList) != 0) {
				fi.firewallType = gFirewallType; 
				(void) STRNCPY(fi.firewallHost, gFirewallHost);
				(void) STRNCPY(fi.firewallUser, gFirewallUser);
				(void) STRNCPY(fi.firewallPass, gFirewallPass);
				fi.firewallPort = gFirewallPort;
			}
			
			es = kExitOpenTimedOut;
			errstr = "could not open remote host";
			if ((result = FTPOpenHost(&fi)) < 0) {
				(void) fprintf(stderr, "ncftpls: cannot open %s: %s.\n", fi.host, FTPStrError(result));
				es = kExitOpenFailed;
				DisposeWinsock(0);
				exit((int) es);
			}

			if (fi.hasCLNT != kCommandNotAvailable)
				(void) FTPCmd(&fi, "CLNT NcFTPLs %.5s %s", gVersion + 11, gOS);

			errstr = "could not run pre-command remote host";
			(void) AdditionalCmd(&fi, precmd, NULL);
			
			errstr = "could not get current remote working directory from remote host";
			if (FTPGetCWD(&fi, rootcwd, sizeof(rootcwd)) < 0) {
				FTPPerror(&fi, fi.errNo, kErrPWDFailed, "ncftpls", errstr);
				es = kExitChdirFailed;
				DisposeWinsock(0);
				exit((int) es);
			}
		}
		
		errstr = "could not change directory on remote host";
		es = kExitChdirTimedOut;
		for (lp = cdlist.first; lp != NULL; lp = lp->next) {
			if (FTPChdir(&fi, lp->line) != 0) {
				FTPPerror(&fi, fi.errNo, kErrCWDFailed, "ncftpls: Could not chdir to", lp->line);
				es = kExitChdirFailed;
				DisposeWinsock(0);
				exit((int) es);
			}
		}
		
		if (ndirs > 1) {
			fprintf(stdout, "%s%s\n\n",
				(i > optind) ? "\n\n\n" : "", url);
		}
		fflush(stdout);
	
		if (dfmode != 0) {
			errstr = "could not get current remote working directory from remote host";
			if (FTPGetCWD(&fi, curcwd, sizeof(curcwd)) < 0) {
				FTPPerror(&fi, fi.errNo, kErrPWDFailed, "ncftpls", errstr);
				es = kExitChdirFailed;
				DisposeWinsock(0);
				exit((int) es);
			}

			errstr = "could not get disk usage from remote host";
			rp = InitResponse();
			if (rp != NULL) {
				result = RCmd(&fi, rp, "SITE DF %s", curcwd);
				ofp = fi.debugLog;
				fi.debugLog = stdout;
				PrintResponse(&fi, &rp->msg);
				fi.debugLog = ofp;
				DoneWithResponse(&fi, rp);
			}
			if (dfmode == 1)
				continue;	/* Don't bother with the listing unless -KK. */
		}

		errstr = "could not read file from remote host";
		es = kExitXferTimedOut;
		(void) signal(SIGINT, Abort);
		if (FTPList(&fi, STDOUT_FILENO, longMode, lsflag) < 0) {
			(void) fprintf(stderr, "ncftpls: directory listing error: %s.\n", FTPStrError(fi.errNo));
			es = kExitXferFailed;
		} else {
			es = kExitSuccess;
			(void) AdditionalCmd(&fi, perfilecmd, curcwd);
			savedfi = fi;
		}
		(void) signal(SIGINT, SIG_DFL);
	}

	errstr = "could not run post-command remote host";
	(void) AdditionalCmd(&fi, postcmd, NULL);
	
	errstr = "could not close remote host";
	(void) FTPCloseHost(&fi);

	DisposeWinsock(0);
	exit((int) es);
}	/* main */
