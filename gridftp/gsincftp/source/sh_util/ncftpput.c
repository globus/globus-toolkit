/* ncftpput.c
 *
 * Copyright (c) 1996-2001 Mike Gleason, NCEMRSoft.
 * All rights reserved.
 *
 * A simple, non-interactive utility to send files to a remote FTP server.
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
	(void) fprintf(fp, "NcFTPPut %.5s\n\n", gVersion + 11);
	(void) fprintf(fp, "Usages:\n");
	(void) fprintf(fp, "  ncftpput [flags] remote-host remote-dir local-files...   (mode 1)\n");
	(void) fprintf(fp, "  ncftpput -f login.cfg [flags] remote-dir local-files...  (mode 2)\n");
	(void) fprintf(fp, "  ncftpput -c remote-host remote-path-name < stdin  (mode 3)\n");
	(void) fprintf(fp, "\nFlags:\n\
  -u XX  Use username XX instead of anonymous.\n\
  -p XX  Use password XX with the username.\n\
  -P XX  Use port number XX instead of the default FTP service port (21).\n\
  -j XX  Use account XX with the account (deprecated).\n\
  -d XX  Use the file XX for debug logging.\n\
  -e XX  Use the file XX for error logging.\n\
  -U XX  Use value XX for the umask.\n\
  -t XX  Timeout after XX seconds.\n");
	(void) fprintf(fp, "\
  -a     Use ASCII transfer type instead of binary.\n\
  -m     Attempt to mkdir the dstdir before copying.\n\
  -v/-V  Do (do not) use progress meters.\n\
  -f XX  Read the file XX for host, user, and password information.\n");
	(void) fprintf(fp, "\
  -c     Use stdin as input file to write on remote host.\n\
  -A     Append to remote files instead of overwriting them.\n\
  -z/-Z  Do (do not) try to resume uploads (default: -Z).\n\
  -T XX  Upload into temporary files prefixed by XX.\n");
	(void) fprintf(fp, "\
  -S XX  Upload into temporary files suffixed by XX.\n\
  -DD    Delete local file after successfully uploading it.\n\
  -b     Run in background (submit job to \"ncftpbatch\" and run).\n\
  -bb    Same as \"-b\" but queue only (do not run \"ncftpbatch\").\n\
  -E     Use regular (PORT) data connections.\n\
  -F     Use passive (PASV) data connections (default).\n\
  -y     Try using \"SITE UTIME\" to preserve timestamps on remote host.\n");
	(void) fprintf(fp, "\
  -B XX  Try setting the SO_SNDBUF size to XX.\n\
  -r XX  Redial XX times until connected.\n\
  -W XX  Send raw FTP command XX after logging in.\n\
  -X XX  Send raw FTP command XX after each file transferred.\n\
  -Y XX  Send raw FTP command XX before logging out.\n\
  -R     Recursive mode; copy whole directory trees.\n");
	(void) fprintf(fp, "\nExamples:\n\
  ncftpput -u gleason -p my.password Elwood.probe.net /home/gleason stuff.txt\n\
  ncftpput -u gleason Elwood.probe.net /home/gleason a.txt (prompt for pass)\n\
  ncftpput -a -u gleason -p my.password -m -U 007 Bozo.probe.net /tmp/tmpdir a.txt\n\
  tar cvf - /home | ncftpput -u operator -c Server.probe.net /backups/monday.tar\n");
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
Copy(FTPCIPtr cip, const char *const dstdir, char **const files, const int rflag, const int xtype, const int appendflag, const char *const tmppfx, const char *const tmpsfx, const int resumeflag, const int deleteflag, const char *const perfilecmd)
{
	int i;
	int result;
	const char *file;
	int rc = 0;

	for (i=0; ; i++) {
		file = files[i];
		if (file == NULL)
			break;
		result = FTPPutFiles3(cip, file, dstdir, rflag,
#if defined(WIN32) || defined(_WINDOWS)
			kGlobYes,
#else
			kGlobNo,	/* Shell does the glob for you */
#endif
			xtype, appendflag, tmppfx, tmpsfx, resumeflag, deleteflag, NoConfirmResumeUploadProc, 0);
		if (result != 0) {
			FTPPerror(cip, result, kErrCouldNotStartDataTransfer, "ncftpput", file);
			rc = result;
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
	int rflag = 0;
	int appendflag = kAppendNo;
	int deleteflag = kDeleteNo;
	int resumeflag = kResumeNo;
	const char *tmppfx = "";
	const char *tmpsfx = "";
	int xtype = kTypeBinary;
	ExitStatus es;
	int wantMkdir = 0;
	char *Umask = NULL;
	char *dstdir = NULL;
	const char *errstr;
	char **files = (char **) 0;
	int progmeters;
	int usingcfg = 0;
	int ftpcat = 0;
	int tryUtime = 0;
	int nD = 0;
	int batchmode = 0;
	int spooled = 0;
	int i;
	char *ufilep;
	const char *udirp;
	char ufile[256];
	char precmd[128], postcmd[128], perfilecmd[128];

	InitWinsock();
#ifdef SIGPOLL
	NcSignal(SIGPOLL, (FTPSigProc) SIG_IGN);
#endif
	result = FTPInitLibrary(&gLib);
	if (result < 0) {
		(void) fprintf(stderr, "ncftpput: init library error %d (%s).\n", result, FTPStrError(result));
		DisposeWinsock(0);
		exit(kExitInitLibraryFailed);
	}
	result = FTPInitConnectionInfo(&gLib, &fi, kDefaultFTPBufSize);
	if (result < 0) {
		(void) fprintf(stderr, "ncftpput: init connection info error %d (%s).\n", result, FTPStrError(result));
		DisposeWinsock(0);
		exit(kExitInitConnInfoFailed);
	}

	InitUserInfo();
	fi.dataPortMode = kFallBackToSendPortMode;
	LoadFirewallPrefs(0);
	if (gFwDataPortMode >= 0)
		fi.dataPortMode = gFwDataPortMode;
	fi.xferTimeout = 60 * 60;
	fi.connTimeout = 30;
	fi.ctrlTimeout = 135;
	fi.debugLog = NULL;
	fi.errLog = stderr;
	(void) STRNCPY(fi.user, "anonymous");
	progmeters = GetDefaultProgressMeterSetting();
	precmd[0] = '\0';
	postcmd[0] = '\0';
	perfilecmd[0] = '\0';

	while ((c = getopt(argc, argv, "P:u:j:p:e:d:U:t:mar:RvVf:AT:S:EFcyZzDbB:W:X:Y:")) > 0) switch(c) {
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
		case 'U':
			Umask = optarg;
			break;
		case 't':
			SetTimeouts(&fi, optarg);
			break;
		case 'm':
			wantMkdir = 1;
			break;
		case 'a':
			xtype = kTypeAscii;	/* Use ascii. */
			break;
		case 'r':
			SetRedial(&fi, optarg);
			break;
		case 'R':
			rflag = 1;
			break;
		case 'v':
			progmeters = 1;
			break;
		case 'V':
			progmeters = 0;
			break;
		case 'f':
			ReadConfigFile(optarg, &fi);
			usingcfg = 1;
			break;
		case 'A':
			appendflag = 1;
			break;
		case 'T':
			tmppfx = optarg;
			break;
		case 'S':
			tmpsfx = optarg;
			break;
		case 'E':
			fi.dataPortMode = kSendPortMode;
			break;
		case 'F':
			fi.dataPortMode = kPassiveMode;
			break;
		case 'c':
			ftpcat = 1;
			break;
		case 'y':
			tryUtime = 1;
			break;
		case 'z':
			resumeflag = kResumeYes;
			break;
		case 'Z':
			resumeflag = kResumeNo;
			break;
		case 'b':
			batchmode++;
			break;
		case 'B':
			fi.dataSocketSBufSize = (size_t) atol(optarg);	
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
	if (usingcfg != 0) {
		if (ftpcat == 0) {
			if (optind > argc - 2)
				Usage();
			dstdir = argv[optind + 0];
			files = argv + optind + 1;
		} else {
			if (optind > argc - 2)
				Usage();
			(void) STRNCPY(fi.host, argv[optind]);
		}
	} else {
		if (ftpcat == 0) {
			if (optind > argc - 3)
				Usage();
			(void) STRNCPY(fi.host, argv[optind]);
			dstdir = argv[optind + 1];
			files = argv + optind + 2;
		} else {
			if (optind > argc - 2)
				Usage();
			(void) STRNCPY(fi.host, argv[optind]);
		}
	}

	if (strcmp(fi.user, "anonymous") && strcmp(fi.user, "ftp")) {
		if (fi.pass[0] == '\0') {
			(void) gl_getpass("Password: ", fi.pass, sizeof(fi.pass));
		}
	}

	if (progmeters != 0)
		fi.progress = PrStatBar;
	if (tryUtime == 0)
		fi.hasUTIME = 0;
	if (nD >= 2)
		deleteflag = kDeleteYes;

	if (MayUseFirewall(fi.host, gFirewallType, gFirewallExceptionList) != 0) {
		fi.firewallType = gFirewallType; 
		(void) STRNCPY(fi.firewallHost, gFirewallHost);
		(void) STRNCPY(fi.firewallUser, gFirewallUser);
		(void) STRNCPY(fi.firewallPass, gFirewallPass);
		fi.firewallPort = gFirewallPort;
	}

	if (batchmode != 0) {
		/* List of files specified */
		for (i=0; files[i] != NULL; i++) {
			STRNCPY(ufile, files[i]);
			ufilep = strrchr(ufile, '/');
			if (ufilep == NULL) {
				udirp = ".";
				ufilep = ufile;
			} else {
				udirp = ufile;
				*ufilep++ = '\0';
			}

			result = SpoolX(
				"put",
				ufilep, 	/* Remote file */
				dstdir,		/* Remote CWD */
				ufilep, 	/* Local file */
				udirp,	/* Local CWD */
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
			if (result == 0) {
				fprintf(stdout, "  + Spooled; sending remotely as %s/%s.\n", dstdir, ufilep);
				spooled++;
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
	
	errstr = "could not open remote host";
	es = kExitOpenTimedOut;
	if ((result = FTPOpenHost(&fi)) < 0) {
		(void) fprintf(stderr, "ncftpput: cannot open %s: %s.\n", fi.host, FTPStrError(result));
		es = kExitOpenFailed;
		DisposeWinsock(0);
		exit((int) es);
	}

	if (fi.hasCLNT != kCommandNotAvailable)
		(void) FTPCmd(&fi, "CLNT NcFTPPut %.5s %s", gVersion + 11, gOS);

	if (Umask != NULL) {
		errstr = "could not set umask on remote host";
		result = FTPUmask(&fi, Umask);
		if (result != 0)
			FTPPerror(&fi, result, kErrUmaskFailed, "ncftpput", "could not set umask");
	}

	errstr = "could not run pre-command remote host";
	(void) AdditionalCmd(&fi, precmd, NULL);

	if (dstdir != NULL) {
		es = kExitChdirTimedOut;
		if (wantMkdir != 0) {
			errstr = "could not create and chdir on remote host";
			result = FTPChdir3(&fi, dstdir, NULL, 0, kChdirOneSubdirAtATime|kChdirAndMkdir);
		} else {
			errstr = "could not chdir on remote host";
			result = FTPChdir3(&fi, dstdir, NULL, 0, kChdirOneSubdirAtATime);
		}
	}

	if (result != 0) {
		FTPPerror(&fi, result, kErrCWDFailed, "ncftpput: Could not change to directory", dstdir);
		(void) FTPCloseHost(&fi);
		es = kExitChdirFailed;
		DisposeWinsock(0);
		exit((int) es);
	}

	if (result >= 0) {
		errstr = "could not write to file on remote host";
		es = kExitXferTimedOut;
		(void) signal(SIGINT, Abort);
		if (ftpcat == 0) {
			if (Copy(&fi, "", files, rflag, xtype, appendflag, (const char *) tmppfx, (const char *) tmpsfx, resumeflag, deleteflag, perfilecmd) < 0)
				es = kExitXferFailed;
			else
				es = kExitSuccess;
		} else {
			fi.progress = (FTPProgressMeterProc) 0;
			if (FTPPutOneFile2(&fi, NULL, argv[optind + 1], xtype, STDIN_FILENO, appendflag, tmppfx, tmpsfx) < 0)
				es = kExitXferFailed;
			else {
				es = kExitSuccess;
				(void) AdditionalCmd(&fi, perfilecmd, argv[optind + 1]);
			}
		}
	}

	errstr = "could not run post-command remote host";
	(void) AdditionalCmd(&fi, postcmd, NULL);
	
	(void) FTPCloseHost(&fi);
	DisposeWinsock(0);
	exit((int) es);
}	/* main */
