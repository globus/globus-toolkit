/* ncftpget.c
 *
 * Copyright (c) 1996-2001 Mike Gleason, NCEMRSoft.
 * All rights reserved.
 *
 * A non-interactive utility to grab files from a remote FTP server.
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
	(void) fprintf(fp, "NcFTPGet %.5s\n\n", gVersion + 11);
	(void) fprintf(fp, "Usages:\n");
	(void) fprintf(fp, "  ncftpget [flags] remote-host local-dir remote-path-names...   (mode 1)\n");
	(void) fprintf(fp, "  ncftpget -f login.cfg [flags] local-dir remote-path-names...  (mode 2)\n");
	(void) fprintf(fp, "  ncftpget [flags] ftp://url.style.host/path/name               (mode 3)\n");
	(void) fprintf(fp, "\nFlags:\n\
  -u XX  Use username XX instead of anonymous.\n\
  -p XX  Use password XX with the username.\n\
  -P XX  Use port number XX instead of the default FTP service port (21).\n\
  -d XX  Use the file XX for debug logging.\n\
  -a     Use ASCII transfer type instead of binary.\n");
	(void) fprintf(fp, "\
  -t XX  Timeout after XX seconds.\n\
  -v/-V  Do (do not) use progress meters.\n\
  -f XX  Read the file XX for host, user, and password information.\n\
  -A     Append to local files, instead of overwriting them.\n");
	(void) fprintf(fp, "\
  -z/-Z  Do (do not) not try to resume downloads (default: -z).\n\
  -E     Use regular (PORT) data connections.\n\
  -F     Use passive (PASV) data connections (default).\n\
  -DD    Delete remote file after successfully downloading it.\n\
  -b     Run in background (submit job to \"ncftpbatch\" and run).\n\
  -bb    Same as \"-b\" but queue only (do not run \"ncftpbatch\").\n");
	(void) fprintf(fp, "\
  -B XX  Try setting the SO_RCVBUF size to XX.\n\
  -r XX  Redial XX times until connected.\n\
  -W XX  Send raw FTP command XX after logging in.\n\
  -X XX  Send raw FTP command XX after each file transferred.\n\
  -Y XX  Send raw FTP command XX before logging out.\n\
  -R     Recursive mode; copy whole directory trees.\n\
  -T     Do not try to use TAR mode with Recursive mode.\n");
	(void) fprintf(fp, "\nExamples:\n\
  ncftpget ftp.wustl.edu . /pub/README /pub/README.too\n\
  ncftpget ftp.wustl.edu . '/pub/README*'\n\
  ncftpget -R ftp.probe.net /tmp /pub/ncftpd  (ncftpd is a directory)\n\
  ncftpget ftp://ftp.wustl.edu/pub/README\n\
  ncftpget -u gleason -p my.password Bozo.probe.net . '/home/mjg/.*rc'\n\
  ncftpget -u gleason Bozo.probe.net . /home/mjg/foo.txt  (prompt for password)\n\
  ncftpget -f Bozo.cfg '/home/mjg/.*rc'\n\
  ncftpget -a -d /tmp/debug.log -t 60 ftp.wustl.edu . '/pub/README*'\n");

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




static int 
Copy(FTPCIPtr cip, char *dstdir, const char ** volatile files, int rflag, int xtype, int resumeflag, int appendflag, int deleteflag, int tarflag, const char *const perfilecmd)
{
	int i;
	int result;
	const char *file;
	int rc = 0;

	for (i=0; ; i++) {
		file = files[i];
		if (file == NULL)
			break;
		result = FTPGetFiles3(cip, file, dstdir, rflag, kGlobYes, xtype, resumeflag, appendflag, deleteflag, tarflag, NoConfirmResumeDownloadProc, 0);
		if (result != 0) {
			FTPPerror(cip, result, kErrCouldNotStartDataTransfer, "ncftpget", file);
			if (result != kErrLocalSameAsRemote) {
				/* Display the warning, but don't consider it an error. */
				rc = result;
			}
		} else {
			(void) AdditionalCmd(cip, perfilecmd, file);
		}
	}
	return (rc);
}	/* Copy */




int
main(int argc, char **argv)
{
	int result, c;
	volatile int rflag = 0;
	volatile int xtype = kTypeBinary;
	volatile int appendflag = kAppendNo;
	volatile int resumeflag = kResumeYes;
	volatile int deleteflag = kDeleteNo;
	volatile int tarflag = kTarYes;
	int progmeters;
	char *dstdir = NULL;
	const char **flist;
	const char *errstr;
	volatile ExitStatus es;
	char url[512];
	char urlfile[256];
	char urldir[512];
	int urlxtype;
	LineList cdlist;
	LinePtr lp;
	int rc;
	int nD = 0;
	int batchmode = 0;
	int spooled = 0;
	int i;
	char *urlfilep;
	const char *urldirp;
	char precmd[128], postcmd[128], perfilecmd[128];

	InitWinsock();
#ifdef SIGPOLL
	NcSignal(SIGPOLL, (FTPSigProc) SIG_IGN);
#endif
	result = FTPInitLibrary(&gLib);
	if (result < 0) {
		(void) fprintf(stderr, "ncftpget: init library error %d (%s).\n", result, FTPStrError(result));
		exit(kExitInitLibraryFailed);
	}
	result = FTPInitConnectionInfo(&gLib, &fi, kDefaultFTPBufSize);
	if (result < 0) {
		(void) fprintf(stderr, "ncftpget: init connection info error %d (%s).\n", result, FTPStrError(result));
		exit(kExitInitConnInfoFailed);
	}

	InitUserInfo();
	fi.dataPortMode = kPassiveMode;
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
	progmeters = GetDefaultProgressMeterSetting();
	urlfile[0] = '\0';
	InitLineList(&cdlist);
	precmd[0] = '\0';
	postcmd[0] = '\0';
	perfilecmd[0] = '\0';

	while ((c = getopt(argc, argv, "P:u:j:p:e:d:t:aRTr:vVf:ADzZEFbB:W:X:Y:")) > 0) switch(c) {
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
				fi.errLog = fopen(optarg, FOPEN_APPEND_TEXT);
			break;
		case 'D':
			/* Require two -D's in case they typo. */
			nD++;
			break;
		case 'd':
			if (strcmp(optarg, "stdout") == 0)
				fi.debugLog = stdout;
			else if (optarg[0] == '-')
				fi.debugLog = stdout;
			else if (strcmp(optarg, "stderr") == 0)
				fi.debugLog = stderr;
			else
				fi.debugLog = fopen(optarg, FOPEN_APPEND_TEXT);
			break;
		case 't':
			SetTimeouts(&fi, optarg);
			break;
		case 'a':
			xtype = kTypeAscii;
			break;
		case 'r':
			SetRedial(&fi, optarg);
			break;
		case 'R':
			rflag = 1;
			break;
		case 'T':
			tarflag = 0;
			break;
		case 'v':
			progmeters = 1;
			break;
		case 'V':
			progmeters = 0;
			break;
		case 'f':
			ReadConfigFile(optarg, &fi);
			break;
		case 'A':
			appendflag = kAppendYes;
			break;
		case 'z':
			resumeflag = kResumeYes;
			break;
		case 'Z':
			resumeflag = kResumeNo;
			break;
		case 'E':
			fi.dataPortMode = kSendPortMode;
			break;
		case 'F':
			fi.dataPortMode = kPassiveMode;
			break;
		case 'b':
			batchmode++;
			break;
		case 'B':
			fi.dataSocketRBufSize = (size_t) atol(optarg);	
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

	if (progmeters != 0)
		fi.progress = PrStatBar;

	if (fi.host[0] == '\0') {
		(void) STRNCPY(url, argv[optind]);
		rc = FTPDecodeURL(&fi, url, &cdlist, urlfile, sizeof(urlfile), (int *) &urlxtype, NULL);
		if (rc == kMalformedURL) {
			(void) fprintf(stderr, "Malformed URL: %s\n", url);
			exit(kExitMalformedURL);
		} else if (rc == kNotURL) {
			/* This is what should happen most of the time. */
			if (optind > argc - 3)
				Usage();
			(void) STRNCPY(fi.host, argv[optind]);
			dstdir = StrDup(argv[optind + 1]);
			if (dstdir == NULL) {
				(void) fprintf(stderr, "Out of memory?\n");
				exit(kExitNoMemory);
			}
			StrRemoveTrailingLocalPathDelim(dstdir);
			flist = (const char **) argv + optind + 2;
		} else {
			/* URL okay */
			flist = NULL;
			if ((urlfile[0] == '\0') && (rflag == 0)) {
				/* It was obviously a directory, and they didn't say -R. */
				(void) fprintf(stderr, "ncftpget: Use -R if you want the whole directory tree.\n");
				es = kExitUsage;
				exit((int) es);
			}

			/* Allow "-a" flag to use ASCII mode
			 * with the URL, since most people
			 * don't know there is way to specify
			 * ASCII in the URL itself with ";a".
			 */
			if (xtype != kTypeAscii)
				xtype = urlxtype;
		}
	} else {
		if (optind > argc - 2)
			Usage();
		dstdir = StrDup(argv[optind + 0]);
		if (dstdir == NULL) {
			(void) fprintf(stderr, "Out of memory?\n");
			exit(kExitNoMemory);
		}
		StrRemoveTrailingLocalPathDelim(dstdir);
		flist = (const char **) argv + optind + 1;
	}

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

	if (nD >= 2)
		deleteflag = kDeleteYes;

	if (batchmode != 0) {
		if (flist == NULL) {
			/* URL mode */

			urldir[0] = '\0';
			for (lp = cdlist.first; lp != NULL; lp = lp->next) {
				if (urldir[0] != '\0')
					STRNCAT(urldir, "/");
				STRNCAT(urldir, lp->line);
			}

			rc = SpoolX(
				"get",
				urlfile, 	/* Remote file */
				urldir,		/* Remote CWD */
				urlfile, 	/* Local file */
				".",		/* Local CWD */
				fi.host,
				fi.ip,
				fi.port,
				fi.user,
				fi.pass,
				xtype,
				rflag,
				deleteflag,
				fi.dataPortMode,
				precmd,
				perfilecmd,
				postcmd,
				(time_t) 0	/* when: now */
			);
			if (rc == 0) {
				fprintf(stdout, "  + Spooled; writing locally as %s/%s.\n", ".", urlfile);
				spooled++;
			}
		} else {
			/* List of files specified */
			for (i=0; flist[i] != NULL; i++) {
				STRNCPY(urlfile, flist[i]);
				urlfilep = strrchr(urlfile, '/');
				if (urlfilep == NULL) {
					urldirp = ".";
					urlfilep = urlfile;
				} else {
					urldirp = urlfile;
					*urlfilep++ = '\0';
				}

				rc = SpoolX(
					"get",
					urlfilep, 	/* Remote file */
					urldirp,	/* Remote CWD */
					urlfilep, 	/* Local file */
					dstdir,		/* Local CWD */
					fi.host,
					fi.ip,
					fi.port,
					fi.user,
					fi.pass,
					xtype,
					rflag,
					deleteflag,
					fi.dataPortMode,
					precmd,
					perfilecmd,
					postcmd,
					(time_t) 0	/* when: now */
				);
				if (rc == 0) {
					fprintf(stdout, "  + Spooled; writing locally as %s/%s.\n", urldirp, urlfilep);
					spooled++;
				}
			}
		}
		if (spooled > 0) {
			if (batchmode == 1) {
				RunBatch(0, NULL);
			}
			DisposeWinsock(0);
			exit(kExitSuccess);
		}
		DisposeWinsock(0);
		exit(kExitSpoolFailed);
	}
	
	es = kExitOpenTimedOut;
	errstr = "could not open remote host";
	if ((result = FTPOpenHost(&fi)) < 0) {
		(void) fprintf(stderr, "ncftpget: cannot open %s: %s.\n", fi.host, FTPStrError(result));
		es = kExitOpenFailed;
		DisposeWinsock(0);
		exit((int) es);
	}
	if (fi.hasCLNT != kCommandNotAvailable)
		(void) FTPCmd(&fi, "CLNT NcFTPGet %.5s %s", gVersion + 11, gOS);

	errstr = "could not run pre-command remote host";
	(void) AdditionalCmd(&fi, precmd, NULL);

	if (flist == NULL) {
		/* URL mode */
		errstr = "could not change directory on remote host";
		es = kExitChdirTimedOut;
		for (lp = cdlist.first; lp != NULL; lp = lp->next) {
			if ((rc = FTPChdir(&fi, lp->line)) != 0) {
				FTPPerror(&fi, rc, kErrCWDFailed, "Could not chdir to", lp->line);
				(void) FTPCloseHost(&fi);
				es = kExitChdirFailed;
				DisposeWinsock(0);
				exit((int) es);
			}
		}
		
		errstr = "could not read file from remote host";
		es = kExitXferTimedOut;
		(void) signal(SIGINT, Abort);
		if ((rc = FTPGetFiles3(&fi, urlfile, ".", rflag, kGlobYes, xtype, resumeflag, appendflag, deleteflag, tarflag, NoConfirmResumeDownloadProc, 0)) < 0) {
			FTPPerror(&fi, rc, kErrCouldNotStartDataTransfer, "ncftpget", NULL);
			es = kExitXferFailed;
		} else {
			es = kExitSuccess;

			errstr = "could not run per-file-command remote host";
			(void) AdditionalCmd(&fi, perfilecmd, urlfile);
		}
	} else {
		errstr = "could not read file from remote host";
		es = kExitXferTimedOut;
		(void) signal(SIGINT, Abort);
		if (Copy(&fi, dstdir, flist, rflag, xtype, resumeflag, appendflag, deleteflag, tarflag, perfilecmd) < 0)
			es = kExitXferFailed;
		else
			es = kExitSuccess;
	}

	errstr = "could not run post-command remote host";
	(void) AdditionalCmd(&fi, postcmd, NULL);
	
	(void) FTPCloseHost(&fi);
	DisposeWinsock(0);
	
	exit((int) es);
}	/* main */
