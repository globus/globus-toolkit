/* ncftpbatch.c
 * 
 * Copyright (c) 1999-2000 Mike Gleason, NCEMRSoft.
 * All rights reserved.
 * 
 */

#include "syshdrs.h"

#if defined(WIN32) || defined(_WINDOWS)
#	include "..\ncftp\getopt.h"
#	define getopt Getopt
#	define optarg gOptArg
#	define optind gOptInd
	WSADATA wsaData;
	int wsaInit = 0;
	INITCOMMONCONTROLSEX gComCtls;
	HINSTANCE ghInstance = 0;
	HWND gMainWnd = 0;
	HWND gStaticCtrl = 0;
	int gQuitRequested = 0;

	__inline void DisposeWinsock(int aUNUSED) { if (wsaInit > 0) WSACleanup(); wsaInit--; }
#	include "..\ncftp\util.h"
#	include "..\ncftp\pref.h"
#	include "resource.h"
#	include "gpshare.h"
#else
#	define YieldUI(a)
#	include "../ncftp/util.h"
#	include "../ncftp/pref.h"
#	include "gpshare.h"
#endif

#ifdef HAVE_LONG_FILE_NAMES

#define kSpoolDir "spool"
#if defined(WIN32) || defined(_WINDOWS)
#	define kSpoolLog "batchlog.txt"
#else
#	define kSpoolLog "batchlog"
#endif

int gGotSig = 0;
FTPLibraryInfo gLib;
FTPConnectionInfo gConn;
int gIsTTY;
int gSpoolSerial = 0;
int gSpooled = 0;
char gSpoolDir[256];
extern int gFirewallType;
extern char gFirewallHost[64];
extern char gFirewallUser[32];
extern char gFirewallPass[32];
extern char gFirewallExceptionList[256];
extern unsigned int gFirewallPort;
int gItemInUse = 0;
char gItemPath[256];
char gMyItemPath[256];
int gOperation;
char gHost[64];
char gHostIP[32];
unsigned int gPort;
char gRUser[32];
char gRPass[128];
char gPreCommand[128];
char gPerFileCommand[128];
char gPostCommand[128];
int gXtype;
int gRecursive;
int gDelete;
int gPassive;
char gRDir[256];
char gLDir[256];
char gRFile[256];
char gLFile[256];
char gRStartDir[256];

/* Writes logging data to a ~/.ncftp/batchlog file.
 * This is nice for me when I need to diagnose problems.
 */
time_t gLogTime;
FILE *gLogFile = NULL;
char gLogLBuf[256];
unsigned int gMyPID;
const char *gLogOpenMode = FOPEN_APPEND_TEXT;
int gUnused;
int gMayCancelJmp = 0;

#if defined(WIN32) || defined(_WINDOWS)
char gStatusText[512];
#else
#ifdef HAVE_SIGSETJMP
sigjmp_buf gCancelJmp;
#else	/* HAVE_SIGSETJMP */
jmp_buf gCancelJmp;
#endif	/* HAVE_SIGSETJMP */
#endif

extern char gOurDirectoryPath[256];
extern int FTPRebuildConnectionInfo(const FTPLIPtr lip, const FTPCIPtr cip);
extern char *optarg;
extern int optind;
extern char gFirewallExceptionList[256];
extern int gFwDataPortMode;
extern char gOS[], gVersion[];

#if defined(WIN32) || defined(_WINDOWS)
typedef struct dirent {
	char d_name[MAX_PATH];
} dirent;

typedef struct DIR {
	HANDLE searchHandle;
	char *dirpath;
	WIN32_FIND_DATA ffd;
	dirent dent;
} DIR;


DIR *opendir(const char *const path)
{
	DIR *p;
	char *dirpath;
	size_t len;

	p = (DIR *) malloc(sizeof(DIR));
	if (p == NULL)
		return NULL;
	memset(p, 0, sizeof(DIR));

	len = strlen(path);
	dirpath = (char *) malloc(len + 5);
	if (dirpath == NULL)
		return NULL;
	p->dirpath = dirpath;

	memcpy(dirpath, path, len + 1);
	if (IsLocalPathDelim(dirpath[len - 1])) {
		--len;
		dirpath[len] = '\0';
	}
	memcpy(dirpath + len, "\\*.*", (size_t) 5);

	p->searchHandle = FindFirstFile(dirpath, &p->ffd);
	if (p->searchHandle == INVALID_HANDLE_VALUE) {
		memset(&p->ffd, 0, sizeof(p->ffd));
	}
	return (p);
}	/* opendir */



struct dirent *readdir(DIR *dir)
{
	memcpy(dir->dent.d_name, dir->ffd.cFileName, (size_t) sizeof(dir->dent.d_name));
	if (dir->searchHandle != INVALID_HANDLE_VALUE) {
		if (!FindNextFile(dir->searchHandle, &dir->ffd)) {
			/* no more items, or an error we don't care about */
			FindClose(dir->searchHandle);
			dir->searchHandle = INVALID_HANDLE_VALUE;
			memset(&dir->ffd, 0, sizeof(dir->ffd));
		}
	}
	if (dir->dent.d_name[0] == '\0')
		return NULL;
	return (&dir->dent);
}	/* readdir */



void closedir(DIR *dir)
{
	/* The searchHandle is already closed, but we
	 * need to dealloc the structures.
	 */
	if ((dir != NULL) && (dir->dirpath != NULL)) {
		free(dir->dirpath);
		memset(dir, 0, sizeof(DIR));
		free(dir);
	}
}	/* closedir */

#endif



#if defined(WIN32) || defined(_WINDOWS)
static void YieldUI(int redraw)
{
	MSG msg;

	if (redraw)
		InvalidateRect(gMainWnd, NULL, (redraw > 1));

	while (PeekMessage (&msg, gMainWnd, 0, 0, PM_REMOVE)) {
		TranslateMessage (&msg);
		DispatchMessage (&msg);
	}
}	// YieldUI
#endif



static void ErrBox(const char *const fmt, ...)
{
#if defined(WIN32) || defined(_WINDOWS)
	char buf[512];
	va_list ap;

	ZeroMemory(buf, sizeof(buf));
	va_start(ap, fmt);
	wvsprintf(buf, fmt, ap);
	va_end(ap);

	MessageBox((gMainWnd != NULL) ? gMainWnd : GetDesktopWindow(),
		buf, "Error", MB_OK | MB_ICONINFORMATION);
#else
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
#endif
}	/* ErrBox */




static void PerrorBox(const char *const whatFailed)
{
#if defined(WIN32) || defined(_WINDOWS)
	char errMsg[256];

	(void) FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		errMsg,
		sizeof(errMsg),
		NULL
	);

	(void) ErrBox("%s: %s\n", whatFailed, errMsg);
#else
	perror(whatFailed);
#endif
}	/* PerrorBox */



/*VARARGS*/
static void
Log(
#if defined(WIN32) || defined(_WINDOWS)
		int uiShow,
#else
		int UNUSED(uiShow),
#endif
		const char *const fmt, ...)
{
	va_list ap;
	struct tm *ltp;

	if (gLogFile != NULL) {
		(void) time(&gLogTime);
		ltp = localtime(&gLogTime);
		if (ltp != NULL) {
			(void) fprintf(gLogFile,
#if defined(WIN32) || defined(_WINDOWS)
				"$%08x %04d-%02d-%02d %02d:%02d:%02d | ",
#else
				"%06u %04d-%02d-%02d %02d:%02d:%02d | ",
#endif
				gMyPID,
				ltp->tm_year + 1900,
				ltp->tm_mon + 1,
				ltp->tm_mday,
				ltp->tm_hour,
				ltp->tm_min,
				ltp->tm_sec
			);
		}
		va_start(ap, fmt);
		(void) vfprintf(gLogFile, fmt, ap);
		va_end(ap);
	}
	if (gIsTTY != 0) {
		va_start(ap, fmt);
		(void) vfprintf(stdout, fmt, ap);
		va_end(ap);
	}
#if defined(WIN32) || defined(_WINDOWS)
	if (uiShow) {
		char *cp;

		va_start(ap, fmt);
		(void) vsprintf(gStatusText, fmt, ap);
		va_end(ap);
		cp = gStatusText + strlen(gStatusText) - 1;
		while (iscntrl(*cp)) {
			*cp-- = '\0';
		}
		YieldUI(2);
	}
#else
	LIBNCFTP_USE_VAR(uiShow);
#endif
}	/* Log */



/*VARARGS*/
static void
LogPerror(const char *const fmt, ...)
{
	va_list ap;
	struct tm *ltp;
	int oerrno;
	
	oerrno = errno;
	if (gLogFile != NULL) {
		(void) time(&gLogTime);
		ltp = localtime(&gLogTime);
		if (ltp != NULL) {
			(void) fprintf(gLogFile,
#if defined(WIN32) || defined(_WINDOWS)
				"$%08x %04d-%02d-%02d %02d:%02d:%02d | ",
#else
				"%06u %04d-%02d-%02d %02d:%02d:%02d | ",
#endif
				gMyPID,
				ltp->tm_year + 1900,
				ltp->tm_mon + 1,
				ltp->tm_mday,
				ltp->tm_hour,
				ltp->tm_min,
				ltp->tm_sec
			);
		}
		va_start(ap, fmt);
		(void) vfprintf(gLogFile, fmt, ap);
		va_end(ap);
#ifdef HAVE_STRERROR
		(void) fprintf(gLogFile, ": %s\n", strerror(oerrno));
#else
		(void) fprintf(gLogFile, ": errno=%d\n", (oerrno));
#endif
	}
	if (gIsTTY != 0) {
		va_start(ap, fmt);
		(void) vfprintf(stdout, fmt, ap);
		va_end(ap);
#ifdef HAVE_STRERROR
		(void) fprintf(stdout, ": %s\n", strerror(oerrno));
#else
		(void) fprintf(stdout, ": errno=%d\n", (oerrno));
#endif
	}
}	/* LogPerror */



#if defined(WIN32) || defined(_WINDOWS)
void
PrWinStatBar(const FTPCIPtr cip, int mode)
{
	switch (mode) {
		case kPrInitMsg:
			YieldUI(2);
			break;

		case kPrUpdateMsg:
		case kPrEndMsg:
			YieldUI(1);
			break;
	}
}	/* PrWinStatBar */
#endif



static void
DebugHook(const FTPCIPtr cipUnused, char *msg)
{
	gUnused = (int) cipUnused;			/* shut up gcc */
	Log(0, "%s", msg);
}	/* DebugHook */




static void
CloseLog(void)
{
	if (gLogFile != NULL) {
		(void) fclose(gLogFile);
		gLogFile = NULL;
	}
}	/* CloseLog */




static void
OpenLog(void)
{
	FILE *fp;
	char pathName[256];
	struct Stat st;
	const char *openMode;

	CloseLog();
	(void) OurDirectoryPath(pathName, sizeof(pathName), kSpoolLog);

	openMode = gLogOpenMode;
	if ((Stat(pathName, &st) == 0) && (st.st_size > 200000L)) {
		/* Prevent the log file from growing forever. */
		openMode = FOPEN_WRITE_TEXT;
	}

	fp = fopen(pathName, openMode);
	if (fp != NULL) {
#ifdef HAVE_SETVBUF
		(void) setvbuf(fp, gLogLBuf, _IOLBF, sizeof(gLogLBuf));
#endif	/* HAVE_SETVBUF */
		(void) time(&gLogTime);
		gLogFile = fp;
		gMyPID = (unsigned int) getpid();
	}
}	/* OpenLog */




static void
ExitStuff(void)
{
	if (gItemInUse > 0) {
		gItemInUse = 0;
		(void) rename(gMyItemPath, gItemPath);
	}
}	/* ExitStuff */



#if defined(WIN32) || defined(_WINDOWS)
#elif 0
static void
SigAlrm(int sigNum)
{
	if (gMayCancelJmp != 0) {
		gUnused = sigNum;
		if (gItemInUse > 0) {
			gItemInUse = 0;
			(void) rename(gMyItemPath, gItemPath);
		}
#ifdef HAVE_SIGSETJMP
		siglongjmp(gCancelJmp, 1);
#else	/* HAVE_SIGSETJMP */
		longjmp(gCancelJmp, 1);
#endif	/* HAVE_SIGSETJMP */
	}
}	/* SigExit */
#endif




static void
SigExit(int sigNum)
{
	ExitStuff();
	Log(0, "-----caught signal %d, exiting-----\n", sigNum);
	DisposeWinsock(0);
	exit(0);
}	/* SigExit */





static void
FTPInit(void)
{
	int result;

	InitWinsock();
	result = FTPInitLibrary(&gLib);
	if (result < 0) {
		ErrBox("ncftpbatch: init library error %d (%s).\n", result, FTPStrError(result));
		DisposeWinsock(0);
		exit(1);
	}

	result = FTPInitConnectionInfo(&gLib, &gConn, kDefaultFTPBufSize);
	if (result < 0) {
		ErrBox("ncftpbatch: init connection info error %d (%s).\n", result, FTPStrError(result));
		DisposeWinsock(0);
		exit(1);
	}
}	/* FTPInit */




/* These things are done first, before we even parse the command-line
 * options.
 */
static void
PreInit(void)
{
#if defined(WIN32) || defined(_WINDOWS)
	gIsTTY = 0;
	ZeroMemory(gStatusText, sizeof(gStatusText));
#else
	gIsTTY = ((isatty(2) != 0) && (getppid() > 1)) ? 1 : 0;
#endif
#ifdef SIGPOLL
	NcSignal(SIGPOLL, (FTPSigProc) SIG_IGN);
#endif
	InitUserInfo();

	FTPInit();
	LoadFirewallPrefs(0);
	srand((unsigned int) getpid());

	(void) OurDirectoryPath(gSpoolDir, sizeof(gSpoolDir), kSpoolDir);
	(void) signal(SIGINT, SigExit);
	(void) signal(SIGTERM, SigExit);
#if defined(WIN32) || defined(_WINDOWS)
#else
	(void) signal(SIGSEGV, SigExit);
	(void) signal(SIGBUS, SigExit);
	(void) signal(SIGFPE, SigExit);
	(void) signal(SIGILL, SigExit);
#if SIGIOT != SIGABRT
	(void) signal(SIGIOT, SigExit);
#endif
#ifdef SIGEMT
	(void) signal(SIGEMT, SigExit);
#endif
#ifdef SIGSYS
	(void) signal(SIGSYS, SigExit);
#endif
#ifdef SIGSTKFLT
	(void) signal(SIGSTKFLT, SigExit);
#endif
#endif
}	/* PreInit */




/* These things are just before the program exits. */
static void
PostShell(void)
{
	CloseLog();
}	/* PostShell */




static int
PrePrintItem(void)
{
	FILE *fp;
	char line[256];
	char *tok1, *tok2;
	
	fp = fopen(gMyItemPath, FOPEN_READ_TEXT);
	if (fp == NULL) {
		/* Could have been renamed already. */
		return (-1);
	}

	gOperation = '?';
	gHost[0] = '\0';
	gHostIP[0] = '\0';
	gRUser[0] = '\0';
	gRPass[0] = '\0';
	gXtype = 'I';
	gRecursive = 0;
	gDelete = 0;
	gPassive = 2;
	if (gFwDataPortMode >= 0)
		gPassive = gFwDataPortMode;
	gRDir[0] = '\0';
	gLDir[0] = '\0';
	gRFile[0] = '\0';
	gLFile[0] = '\0';
	gPreCommand[0] = '\0';
	gPerFileCommand[0] = '\0';
	gPostCommand[0] = '\0';

	line[sizeof(line) - 1] = '\0';
	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		tok1 = strtok(line, " =\t\r\n");
		if ((tok1 == NULL) || (tok1[0] == '#'))
			continue;
		tok2 = strtok(NULL, "\r\n");
		if (tok2 == NULL)
			continue;

		if (strcmp(tok1, "op") == 0) {
			gOperation = tok2[0];
		} else if (strcmp(tok1, "hostname") == 0) {
			(void) STRNCPY(gHost, tok2);
		} else if (strcmp(tok1, "host-ip") == 0) {
			/* Don't really use this anymore, it is
			 * only used if the host is not set.
			 */
			(void) STRNCPY(gHostIP, tok2);
		} else if (strcmp(tok1, "user") == 0) {
			(void) STRNCPY(gRUser, tok2);
		} else if (strcmp(tok1, "pass") == 0) {
			(void) STRNCPY(gRPass, tok2);
		} else if (strcmp(tok1, "anon-pass") == 0) {
			(void) STRNCPY(gLib.defaultAnonPassword, tok2);
		} else if (strcmp(tok1, "xtype") == 0) {
			gXtype = tok2[0];
		} else if (strcmp(tok1, "recursive") == 0) {
			gRecursive = StrToBool(tok2);
		} else if (strcmp(tok1, "delete") == 0) {
			gDelete = StrToBool(tok2);
		} else if (strcmp(tok1, "passive") == 0) {
			if (isdigit((int) tok2[0]))
				gPassive = atoi(tok2);
			else
				gPassive = StrToBool(tok2);
		} else if (strcmp(tok1, "remote-dir") == 0) {
			(void) STRNCPY(gRDir, tok2);
		} else if (strcmp(tok1, "local-dir") == 0) {
			(void) STRNCPY(gLDir, tok2);
		} else if (strcmp(tok1, "remote-file") == 0) {
			(void) STRNCPY(gRFile, tok2);
		} else if (strcmp(tok1, "local-file") == 0) {
			(void) STRNCPY(gLFile, tok2);
		} else if (strcmp(tok1, "pre-command") == 0) {
			(void) STRNCPY(gPreCommand, tok2);
		} else if (strcmp(tok1, "per-file-command") == 0) {
			(void) STRNCPY(gPerFileCommand, tok2);
		} else if (strcmp(tok1, "post-command") == 0) {
			(void) STRNCPY(gPostCommand, tok2);
		}	/* else, unknown command. */
	}
	(void) fclose(fp);

	if (islower(gOperation))
		gOperation = toupper(gOperation);

	if (gHost[0] == '\0') {
		if (gHostIP[0] != '\0') {
			(void) STRNCPY(gHost, gHostIP);
		} else {
			return (-1);
		}
	}

	if (gOperation == 'G') {
		if (gRecursive != 0) {
			if (gRFile[0] == '\0') {
				return (-1);
			}
			if (gLDir[0] == '\0') {
				return (-1);
			}
		} else {
			if (gRFile[0] == '\0') {
				return (-1);
			}
			if (gLFile[0] == '\0') {
				return (-1);
			}
		}
	} else if (gOperation == 'P') {
		if (gRecursive != 0) {
			if (gLFile[0] == '\0') {
				return (-1);
			}
			if (gRDir[0] == '\0') {
				return (-1);
			}
		} else {
			if (gLFile[0] == '\0') {
				return (-1);
			}
			if (gRFile[0] == '\0') {
				return (-1);
			}
		}
	} else {
		return (-1);
	}

	if (gRUser[0] == '\0')
		(void) STRNCPY(gRUser, "anonymous");

	return (0);
}	/* PrePrintItem */




static int
DoItem(int iType)
{
	FILE *fp;
	char line[256];
	char *tok1, *tok2;
	int needOpen;
	int result;
	int n;
	int cdflags;
	
	fp = fopen(gMyItemPath, FOPEN_READ_TEXT);
	if (fp == NULL) {
		LogPerror(gMyItemPath);
		return (-1);
	}

	gOperation = iType;
	gHost[0] = '\0';
	gHostIP[0] = '\0';
	gPort = kDefaultFTPPort;
	gRUser[0] = '\0';
	gRPass[0] = '\0';
	gXtype = 'I';
	gRecursive = 0;
	gDelete = 0;
	gPassive = 2;
	gRDir[0] = '\0';
	gLDir[0] = '\0';
	gRFile[0] = '\0';
	gLFile[0] = '\0';
	gPreCommand[0] = '\0';
	gPerFileCommand[0] = '\0';
	gPostCommand[0] = '\0';

	line[sizeof(line) - 1] = '\0';
	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		tok1 = strtok(line, " =\t\r\n");
		if ((tok1 == NULL) || (tok1[0] == '#'))
			continue;
		tok2 = strtok(NULL, "\r\n");
		if (tok2 == NULL)
			continue;

		if (strcmp(tok1, "op") == 0) {
			gOperation = tok2[0];
		} else if (strcmp(tok1, "hostname") == 0) {
			(void) STRNCPY(gHost, tok2);
		} else if (strcmp(tok1, "host-ip") == 0) {
			(void) STRNCPY(gHostIP, tok2);
		} else if (strcmp(tok1, "port") == 0) {
			n = atoi(tok2);
			if (n > 0)
				gPort = (unsigned int) n;
		} else if (strcmp(tok1, "user") == 0) {
			(void) STRNCPY(gRUser, tok2);
		} else if (strcmp(tok1, "pass") == 0) {
			(void) STRNCPY(gRPass, tok2);
		} else if (strcmp(tok1, "anon-pass") == 0) {
			(void) STRNCPY(gLib.defaultAnonPassword, tok2);
		} else if (strcmp(tok1, "xtype") == 0) {
			gXtype = tok2[0];
		} else if (strcmp(tok1, "recursive") == 0) {
			gRecursive = StrToBool(tok2);
		} else if (strcmp(tok1, "delete") == 0) {
			gDelete = StrToBool(tok2);
		} else if (strcmp(tok1, "passive") == 0) {
			if (isdigit((int) tok2[0]))
				gPassive = atoi(tok2);
			else
				gPassive = StrToBool(tok2);
		} else if (strcmp(tok1, "remote-dir") == 0) {
			(void) STRNCPY(gRDir, tok2);
		} else if (strcmp(tok1, "local-dir") == 0) {
			(void) STRNCPY(gLDir, tok2);
		} else if (strcmp(tok1, "remote-file") == 0) {
			(void) STRNCPY(gRFile, tok2);
		} else if (strcmp(tok1, "local-file") == 0) {
			(void) STRNCPY(gLFile, tok2);
		} else if (strcmp(tok1, "pre-command") == 0) {
			(void) STRNCPY(gPreCommand, tok2);
		} else if (strcmp(tok1, "per-file-command") == 0) {
			(void) STRNCPY(gPerFileCommand, tok2);
		} else if (strcmp(tok1, "post-command") == 0) {
			(void) STRNCPY(gPostCommand, tok2);
		}	/* else, unknown command. */
	}
	(void) fclose(fp);

	if (islower(gOperation))
		gOperation = toupper(gOperation);

	/* First, check if the parameters from the batch file
	 * are valid.  If not, return successfully so the file
	 * gets removed.
	 */
	if (gHost[0] == '\0') {
		if (gHostIP[0] != '\0') {
			(void) STRNCPY(gHost, gHostIP);
		} else {
			Log(0, "batch file parameter missing: %s.\n", "host");
			return (0);
		}
	}

	cdflags = kChdirOneSubdirAtATime;
	if (gOperation == 'G') {
		if (gRecursive != 0) {
			if (gRFile[0] == '\0') {
				Log(0, "batch file parameter missing: %s.\n", "remote-file");
				return (0);
			}
			if (gLDir[0] == '\0') {
				Log(0, "batch file parameter missing: %s.\n", "local-dir");
				return (0);
			}
		} else {
			if (gRFile[0] == '\0') {
				Log(0, "batch file parameter missing: %s.\n", "remote-file");
				return (0);
			}
			if (gLFile[0] == '\0') {
				Log(0, "batch file parameter missing: %s.\n", "local-file");
				return (0);
			}
		}
	} else if (gOperation == 'P') {
		cdflags = kChdirOneSubdirAtATime|kChdirAndMkdir;
		if (gRecursive != 0) {
			if (gLFile[0] == '\0') {
				Log(0, "batch file parameter missing: %s.\n", "local-file");
				return (0);
			}
			if (gRDir[0] == '\0') {
				Log(0, "batch file parameter missing: %s.\n", "remote-dir");
				return (0);
			}
		} else {
			if (gLFile[0] == '\0') {
				Log(0, "batch file parameter missing: %s.\n", "local-file");
				return (0);
			}
			if (gRFile[0] == '\0') {
				Log(0, "batch file parameter missing: %s.\n", "remote-file");
				return (0);
			}
		}
	} else {
		Log(0, "Invalid batch operation: %c.\n", gOperation);
		return (0);
	}

	if (gLDir[0] != '\0') {
		if (chdir(gLDir) < 0) {
			LogPerror("Could not cd to local-dir=%s", gLDir);
			return (0);
#if defined(WIN32) || defined(_WINDOWS)
#else
		} else if ((gOperation == 'G') && (access(gLDir, W_OK) < 0)) {
			LogPerror("Could not write to local-dir=%s", gLDir);
			return (0);
#endif
		}
	}

	if (gRUser[0] == '\0')
		(void) STRNCPY(gRUser, "anonymous");

	/* Decode password, if it was base-64 encoded. */
	if (strncmp(gRPass, kPasswordMagic, kPasswordMagicLen) == 0) {
		FromBase64(line, gRPass + kPasswordMagicLen, strlen(gRPass + kPasswordMagicLen), 1);
		(void) STRNCPY(gRPass, line);
	}

	/* Now see if we need to open a new host.  We try to leave the
	 * host connected, so if they batch multiple files using the
	 * same remote host we don't need to re-open the remote host.
	 */
	needOpen = 0;
	if (gConn.connected == 0) {
		/* Not connected at all. */
		Log(0, "Was not connected originally.\n");
		needOpen = 1;
	} else if (ISTRCMP(gHost, gConn.host) != 0) {
		/* Host is different. */
		needOpen = 1;
		Log(0, "New host (%s), old host was (%s).\n", gHost, gConn.host);
	} else if (strcmp(gRUser, gConn.user) != 0) {
		/* Same host, but new user. */
		needOpen = 1;
		Log(0, "New user (%s), old user was (%s).\n", gRUser, gConn.user);
	}

	if (needOpen != 0) {
		(void) AdditionalCmd(&gConn, gPostCommand, NULL);
		(void) FTPCloseHost(&gConn);
		if (FTPInitConnectionInfo(&gLib, &gConn, kDefaultFTPBufSize) < 0) {
			/* Highly unlikely... */
			Log(0, "init connection info failed!\n");
			ExitStuff();
			DisposeWinsock(0);
			exit(1);
		}

		gConn.debugLogProc = DebugHook;
		gConn.debugLog = NULL;
		gConn.errLogProc = NULL;
		gConn.errLog = NULL;
		(void) STRNCPY(gConn.host, gHost);
		gConn.port = gPort;
		(void) STRNCPY(gConn.user, gRUser);
		(void) STRNCPY(gConn.pass, gRPass);
		gConn.maxDials = 1;
		gConn.dataPortMode = gPassive;
#if defined(WIN32) || defined(_WINDOWS)
		gConn.progress = PrWinStatBar;
#endif

		if (MayUseFirewall(gConn.host, gFirewallType, gFirewallExceptionList) != 0) {
			gConn.firewallType = gFirewallType; 
			(void) STRNCPY(gConn.firewallHost, gFirewallHost);
			(void) STRNCPY(gConn.firewallUser, gFirewallUser);
			(void) STRNCPY(gConn.firewallPass, gFirewallPass);
			gConn.firewallPort = gFirewallPort;
		}
		
		gConn.connTimeout = 30;
		gConn.ctrlTimeout = 135;
		gConn.xferTimeout = 300;
		Log(1, "Opening %s:%u as user %s...\n", gHost, gPort, gRUser);
		result = FTPOpenHost(&gConn);
		if (result < 0) {
			Log(1, "Couldn't open %s, will try again next time.\n", gHost);
			(void) FTPCloseHost(&gConn);
			return (-1);	/* Try again next time. */
		}
		if (FTPGetCWD(&gConn, gRStartDir, sizeof(gRStartDir)) < 0) {
			Log(1, "Couldn't get start directory on %s, will try again next time.\n", gHost);
			(void) AdditionalCmd(&gConn, gPostCommand, NULL);
			(void) FTPCloseHost(&gConn);
			return (-1);	/* Try again next time. */
		}
		if (gConn.hasCLNT != kCommandNotAvailable)
			(void) FTPCmd(&gConn, "CLNT NcFTPBatch %.5s %s", gVersion + 11, gOS);
		(void) AdditionalCmd(&gConn, gPreCommand, NULL);

		if (FTPChdir3(&gConn, gRDir, NULL, 0, cdflags) < 0) {
			Log(1, "Could not remote cd to %s.\n", gRDir);

			/* Leave open, but unspool.
			 *
			 * Odds are that the directory no longer exists,
			 * so it would be pointless to retry.
			 */
			return (0);
		}
	} else {
		/* Same host, but go back to root.
		 * The remote directory path is relative
		 * to root, so go back to it.
		 */
		if (FTPChdir(&gConn, gRStartDir) < 0) {
			Log(1, "Could not remote cd back to %s.\n", gRStartDir);
			return (-1);	/* Try again next time, in case conn dropped. */
		}

		if (FTPChdir3(&gConn, gRDir, NULL, 0, cdflags) < 0) {
			Log(1, "Could not remote cd to %s.\n", gRDir);
			return (-1);	/* Try again next time, in case conn dropped. */
		}
	}

	if (gOperation == 'G') {
		if (gRecursive != 0) {
#if defined(WIN32) || defined(_WINDOWS)
			sprintf(gStatusText, "Downloading %.200s", gRFile);
#endif
			result = FTPGetFiles3(&gConn, gRFile, gLDir, gRecursive, kGlobNo, gXtype, kResumeYes, kAppendNo, gDelete, kTarNo, NoConfirmResumeDownloadProc, 0);
		} else {
#if defined(WIN32) || defined(_WINDOWS)
			sprintf(gStatusText, "[0%%] - Downloading %.200s", gRFile);
#endif
			result = FTPGetOneFile3(&gConn, gRFile, gLFile, gXtype, (-1), kResumeYes, kAppendNo, gDelete, NoConfirmResumeDownloadProc, 0);
		}
		if (result == kErrCouldNotStartDataTransfer) {
			Log(1, "Remote item %s is no longer retrievable.\n", gRFile);
			result = 0;	/* file no longer on host */
		} else if (result == kErrLocalSameAsRemote) {
			Log(1, "Remote item %s is already present locally.\n", gRFile);
			result = 0;
		} else {
			(void) AdditionalCmd(&gConn, gPerFileCommand, gRFile);
			Log(1, "Done with %s.\n", gRFile);
		}
	} else /* if (gOperation == 'P') */ {
		if (gRecursive != 0) {
#if defined(WIN32) || defined(_WINDOWS)
			sprintf(gStatusText, "Uploading %.200s", gLFile);
#endif
			result = FTPPutFiles3(&gConn, gLFile, gRDir, gRecursive, kGlobNo, gXtype, kAppendNo, NULL, NULL, kResumeYes, gDelete, NoConfirmResumeUploadProc, 0);
		} else {
#if defined(WIN32) || defined(_WINDOWS)
			sprintf(gStatusText, "[0%%] - Uploading %.200s", gLFile);
#endif
			result = FTPPutOneFile3(&gConn, gLFile, gRFile, gXtype, (-1), kAppendNo, NULL, NULL, kResumeYes, gDelete, NoConfirmResumeUploadProc, 0);
		}
		if (result == kErrCouldNotStartDataTransfer) {
			Log(1, "Remote item %s is no longer sendable.  Perhaps permission denied on destination?\n", gRFile);
			result = 0;	/* file no longer on host */
		} else if (result == kErrLocalSameAsRemote) {
			Log(1, "Local item %s is already present on remote host.\n", gLFile);
			result = 0;
		} else {
			(void) AdditionalCmd(&gConn, gPerFileCommand, gRFile);
			Log(1, "Done with %s.\n", gLFile);
		}
	}
	return (result);
}	/* DoItem */




static int
DecodeName(const char *const src, int *yyyymmdd, int *hhmmss)
{
	char itemName[64];
	char *tok, *ps;
	int t;
	int valid = -1;

	(void) STRNCPY(itemName, src);
	for (t = 0, ps = itemName; ((tok = strtok(ps, "-")) != NULL); ps = NULL) {
		t++;
		switch (t) {
			case 4:
				*yyyymmdd = atoi(tok);
				break;
			case 5:
				*hhmmss = atoi(tok);
				valid = 0;
				break;
			case 6:
				valid = -1;
				break;
		}
	}
	if (valid < 0) {
		*yyyymmdd = 0;
		*hhmmss = 0;
	}
	return (valid);
}	/* DecodeName */




static void
Now(int *yyyymmdd, int *hhmmss)
{
	struct tm *ltp;
	time_t now;

	(void) time(&now);
	ltp = localtime(&now);
	if (ltp == NULL) {
		*yyyymmdd = 0;
		*hhmmss = 0;
	} else {
		*yyyymmdd = ((ltp->tm_year + 1900) * 10000)
			+ ((ltp->tm_mon + 1) * 100)
			+ (ltp->tm_mday);
		*hhmmss = (ltp->tm_hour * 10000)
			+ (ltp->tm_min * 100)
			+ (ltp->tm_sec);
	}
}	/* Now */





static void
EventShell(volatile unsigned int sleepval)
{
	int nItems;
	struct dirent *direntp;
	struct Stat st;
	char *cp;
	int iType;
	int iyyyymmdd, ihhmmss, nyyyymmdd, nhhmmss;
	DIR *volatile DIRp;
#if defined(WIN32) || defined(_WINDOWS)
	int passes;
#else
	int sj;
	volatile int passes;
#endif

	DIRp = NULL;
	OpenLog();
	Log(0, "-----started-----\n");

#if defined(WIN32) || defined(_WINDOWS)
#else
#ifdef HAVE_SIGSETJMP
	sj = sigsetjmp(gCancelJmp, 1);
#else	/* HAVE_SIGSETJMP */
	sj = setjmp(gCancelJmp);
#endif	/* HAVE_SIGSETJMP */

	if (sj != 0) {
		gMayCancelJmp = 0;
		if (DIRp != NULL) {
			(void) closedir(DIRp);
			DIRp = NULL;
		}
		FTPShutdownHost(&gConn);
		Log(0, "Timed-out, starting over.\n");
	}
	gMayCancelJmp = 1;
#endif

	for (passes = 0; ; ) {
		passes++;
		if ((passes > 1) || ((passes == 1) && (sleepval > 0))) {
			if (sleepval == 0) {
				sleepval = 3;
			} else if (sleepval > 900) {
				/* If sleep duration got so large it got past 15 minutes,
				 * start over again.
				 */
				sleepval = 60;
			} else {
				sleepval = (unsigned int) (((0.1 * (rand() % 15)) + 1.2) * sleepval); 
			}

			/* Re-open it, in case they deleted the log
			 * while this process was running.
			 */
			OpenLog();
			Log(0, "Sleeping %u seconds before starting pass %d.\n", sleepval, passes);
			YieldUI(1);
			(void) sleep(sleepval);
		}

		if ((DIRp = opendir(gSpoolDir)) == NULL) {
			PerrorBox(gSpoolDir);
			DisposeWinsock(0);
			exit(1);
		}

		Log(0, "Starting pass %d.\n", passes);
		for (nItems = 0; ; ) {
			direntp = readdir(DIRp);
			if (direntp == NULL)
				break;

			YieldUI(0);

			(void) STRNCPY(gItemPath, gSpoolDir);
			(void) STRNCAT(gItemPath, LOCAL_PATH_DELIM_STR);
			(void) STRNCAT(gItemPath, direntp->d_name);
			if ((Stat(gItemPath, &st) < 0) || (S_ISREG(st.st_mode) == 0)) {
				/* Item may have been
				 * deleted by another
				 * process.
				 */
				continue;
			}

			if (DecodeName(direntp->d_name, &iyyyymmdd, &ihhmmss) < 0) {
				/* Junk file in the spool directory. */
				continue;
			}

			cp = StrRFindLocalPathDelim(gItemPath);
			if (cp == NULL) {
				/* Impossible */
				continue;
			}
			cp++;

			iType = (int) *cp;
			if ((iType != 'g') && (iType != 'p')) {
				/* No more items waiting for processing. */
				continue;
			}

			/* Count items waiting for processing. */
			nItems++;

			Now(&nyyyymmdd, &nhhmmss);
			if ((nyyyymmdd < iyyyymmdd) || ((nyyyymmdd == iyyyymmdd) && (nhhmmss < ihhmmss))) {
				/* Process only if the specified start
				 * time has passed.
				 */
				continue;
			}

			(void) STRNCPY(gMyItemPath, gItemPath);
			gMyItemPath[(int) (cp - gItemPath)] = 'x';

			/* Race condition between other ncftpbatches,
			 * but only one of them will rename it
			 * successfully.
			 */
			if (rename(gItemPath, gMyItemPath) == 0) {
				Log(0, "Processing path: %s\n", gMyItemPath);
				gItemInUse = 1;
				if (DoItem(iType) < 0) {
					/* rename it back, so it will
					 * get reprocessed.
					 */
					if (rename(gMyItemPath, gItemPath) != 0) {
						/* quit now */
						Log(0, "Could not rename job %s!\n", gMyItemPath);
						return;
					}
					Log(0, "Re-queueing %s.\n", gItemPath);
				} else {
					Log(0, "Done with %s.\n", gItemPath);
					if (unlink(gMyItemPath) != 0) {
						/* quit now */
						Log(0, "Could not delete finished job %s!\n", gMyItemPath);
						return;
					}
				}
				(void) chdir(LOCAL_PATH_DELIM_STR);
#if defined(WIN32) || defined(_WINDOWS)
				/* Allow time for message to be seen */
				sleep(1);
#endif
			}
#if defined(WIN32) || defined(_WINDOWS)
			if (gQuitRequested != 0) {
				(void) closedir(DIRp);
				Log(0, "User requested close.\n");
				(void) AdditionalCmd(&gConn, gPostCommand, NULL);
				(void) FTPCloseHost(&gConn);
				gMayCancelJmp = 0;
				Log(0, "-----done-----\n");
				return;
			}
#endif
		}
		(void) closedir(DIRp);
		if (nItems == 0) {
			/* Spool directory is empty, done. */
			Log(0, "The spool directory is now empty.\n");
			break;
		}
	}
	(void) AdditionalCmd(&gConn, gPostCommand, NULL);
	(void) FTPCloseHost(&gConn);
	gMayCancelJmp = 0;
	Log(0, "-----done-----\n");
}	/* EventShell */




#if defined(WIN32) || defined(_WINDOWS)
#else

static void
ListQueue(void)
{
	int nItems;
	struct dirent *direntp;
	struct Stat st;
	DIR *DIRp;
	char *cp;
	int iyyyymmdd, ihhmmss;
	char dstr[64];
	char yyyy[8], mm[4], dd[4];
	char HH[4], MM[4];

	if ((DIRp = opendir(gSpoolDir)) == NULL) {
		PerrorBox(gSpoolDir);
		(void) fprintf(stderr, "This directory is created automatically the first time you do a background\noperation from NcFTP.\n");
		DisposeWinsock(0);
		exit(1);
	}
	for (nItems = 0; ; ) {
		direntp = readdir(DIRp);
		if (direntp == NULL)
			break;

		(void) STRNCPY(gItemPath, gSpoolDir);
		(void) STRNCAT(gItemPath, LOCAL_PATH_DELIM_STR);
		(void) STRNCAT(gItemPath, direntp->d_name);
		if ((Stat(gItemPath, &st) < 0) || (S_ISREG(st.st_mode) == 0)) {
			/* Item may have been
			 * deleted by another
			 * process.
			 */
			continue;
		}

		if (DecodeName(direntp->d_name, &iyyyymmdd, &ihhmmss) < 0) {
			/* Junk file in the spool directory. */
			continue;
		}

		cp = StrRFindLocalPathDelim(gItemPath);
		if (cp == NULL) {
			/* Impossible */
			continue;
		}
		cp++;

		(void) STRNCPY(gMyItemPath, gItemPath);
		if (PrePrintItem() == 0) {
			nItems++;
			if (nItems == 1) {
				(void) printf("---Scheduled-For-----Host----------------------------Command--------------------\n");
			}
			(void) sprintf(dstr, "%08d", iyyyymmdd);
			(void) memcpy(yyyy, dstr, 4); yyyy[4] = '\0';
			(void) memcpy(mm, dstr + 4, 2); mm[2] = '\0';
			(void) memcpy(dd, dstr + 6, 2); dd[2] = '\0';
			(void) sprintf(dstr, "%06d", ihhmmss);
			(void) memcpy(HH, dstr + 0, 2); HH[2] = '\0';
			(void) memcpy(MM, dstr + 2, 2); MM[2] = '\0';
			(void) printf("%c  %s-%s-%s %s:%s  %-30s  ",
				(gItemPath[0] == 'x') ? '*' : ' ',
				yyyy, mm, dd, HH, MM,
				gHost
			);
			if (gOperation != 'P') {
				(void) printf("GET");
				if (gRecursive != 0) {
					(void) printf(" -R %s", gRFile);
				} else {
					(void) printf(" %s", gRFile);
				}
			} else {
				(void) printf("PUT");
				if (gRecursive != 0) {
					(void) printf(" -R %s", gLFile);
				} else {
					(void) printf(" %s", gLFile);
				}
			}
			(void) printf("\n");
		}
	}
	(void) closedir(DIRp);
	if (nItems == 0) {
		/* Spool directory is empty, done. */
		(void) printf("Your \"%s\" directory is empty.\n", gSpoolDir);
	}
}	/* ListQueue */

#endif





#if defined(WIN32) || defined(_WINDOWS)

static void OnDraw(HWND hwnd, HDC hdc)
{
	RECT clientRect, rect, r;
	char str[128];
	time_t now;
	BOOL sizeIsUnknown, inProgress;
	int secLeft, minLeft;
	double rate, per;
	const char *rStr;
	int oldBkMode;
	int iper;
	HBRUSH redBrush;
	TEXTMETRIC textMetrics;
	static int lineHeight = 0;
	static int lastUpdate = 0;
	COLORREF oldBkColor;
	static HFONT statusTextFont;
	LOGFONT lf;
	char *cp;

	time(&now);
	strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S", localtime(&now));

	sizeIsUnknown = (gConn.expectedSize == kSizeUnknown);
	inProgress = (gConn.bytesTransferred > 0);

	GetClientRect(hwnd, &clientRect);

	if (lineHeight == 0) {
		// First time through.
		//
		ZeroMemory(&lf, (DWORD) sizeof(lf));
		lf.lfHeight = -MulDiv(8, GetDeviceCaps(hdc, LOGPIXELSY), 72);
		strcpy(lf.lfFaceName, "MS Sans Serif");
		statusTextFont = CreateFontIndirect(&lf);
		if (statusTextFont != NULL)
			SendMessage(gStaticCtrl, WM_SETFONT, (WPARAM) statusTextFont, (LPARAM) 1);

		GetTextMetrics(hdc, &textMetrics);
		lineHeight = textMetrics.tmAscent + textMetrics.tmDescent + textMetrics.tmExternalLeading;

		GetWindowRect(gMainWnd, &r);
		r.bottom = r.top + 30 + lineHeight + lineHeight + lineHeight + 20 - 4;
		MoveWindow(gMainWnd, r.left, r.top, r.right - r.left, r.bottom - r.top, TRUE);
	}

	if (gConn.dataSocket < 0) {
		// Transfer not in progress, show the status text.
		//
		SetWindowText(gStaticCtrl, gStatusText);
		if (lastUpdate == 0) {
			ShowWindow(gStaticCtrl, SW_SHOW);
			SetWindowText(gMainWnd, "NcFTPBatch");
		}
		lastUpdate = 1;
	} else {
		if (lastUpdate == 1)
			ShowWindow(gStaticCtrl, SW_HIDE);
		lastUpdate = 0;

		rect.left = 10;
		rect.top = 10;
		rect.right = clientRect.right - 10;
		rect.bottom = rect.top + lineHeight + 10;
		
		if (!sizeIsUnknown) {
			FrameRect(hdc, &rect, GetStockObject(BLACK_BRUSH));
			
			r.left = rect.left + 1;
			per = gConn.percentCompleted / 100.0;
			if (per < 0.0)
				per = 0.0;
			r.right = r.left + (int) ((double) (rect.right - 1 - r.left) * per);
			r.top = rect.top + 1;
			r.bottom = rect.bottom - 1;
			
			redBrush = CreateSolidBrush(RGB(255,0,0));
			FillRect(hdc, &r, redBrush);
			DeleteObject(redBrush);
			
			r.left = r.right;
			r.right = rect.right - 1;
			if ((r.left + 2) < r.right)
				FillRect(hdc, &r, GetStockObject(WHITE_BRUSH));

			r.left = rect.left + 10;
			r.right = rect.right - 10;
			r.top = rect.top + 2;
			r.bottom = rect.bottom - 2;
			
			oldBkMode = SetBkMode(hdc, TRANSPARENT);
			if (gConn.lname != NULL)
				DrawText(hdc, gConn.lname, -1, &r, DT_SINGLELINE | DT_WORD_ELLIPSIS | DT_VCENTER | DT_CENTER);
			(void) SetBkMode(hdc, oldBkMode);

			cp = strchr(gStatusText, '[');
			if (cp != NULL) {
				iper = (int) (per * 100.0 + 0.5);

				if ((iper > 99) && (cp[2] == '%')) {
					memmove(cp + 2, cp, strlen(cp) + 2);
				} else if ((iper > 99) && (cp[3] == '%')) {
					memmove(cp + 1, cp, strlen(cp) + 1);
				} else if ((iper > 9) && (cp[2] == '%')) {
					memmove(cp + 1, cp, strlen(cp) + 1);
				}
				sprintf(cp, "[%d", iper);
				if (iper > 99)
					cp[4] = '%';
				else if (iper > 9)
					cp[3] = '%';
				else
					cp[2] = '%';
			}
		} else {
			FillRect(hdc, &rect, GetStockObject(WHITE_BRUSH));
			FrameRect(hdc, &rect, GetStockObject(BLACK_BRUSH));
			if (gConn.lname != NULL)
				DrawText(hdc, gConn.lname, -1, &r, DT_SINGLELINE | DT_WORD_ELLIPSIS | DT_VCENTER | DT_CENTER);

			cp = strchr(gStatusText, '[');
			if (cp != NULL) {
				// Get rid of the prefix from [0%] - Down...
				//
				memmove(gStatusText, gStatusText + 7, strlen(gStatusText) + 7);
			}
		}
		SetWindowText(gMainWnd, gStatusText);

		oldBkColor = SetBkColor(hdc, RGB(192,192,192));

		rect.left = 10;
		rect.top = 30 + lineHeight;
		rect.right = (clientRect.right / 2) - 10;
		rect.bottom = rect.top + lineHeight;

		if (sizeIsUnknown) {
			sprintf(str, "%ld bytes", gConn.bytesTransferred);
		} else {
			sprintf(str, "%ld of %ld bytes",
				inProgress ? gConn.bytesTransferred : 0,
				gConn.expectedSize
				);
		}
		DrawText(hdc, str, -1, &rect, DT_SINGLELINE | DT_NOCLIP);
		
		if ((!sizeIsUnknown) && (inProgress)) {
			rect.left = (clientRect.right / 2);
			rect.right = (3 * clientRect.right / 4);
			secLeft = (int) (gConn.secLeft + 0.5);
			minLeft = secLeft / 60;
			secLeft = secLeft - (minLeft * 60);
			if (minLeft > 999) {
				minLeft = 999;
				secLeft = 59;
			}
			sprintf(str, "ETA: %d:%02d", minLeft, secLeft);
			DrawText(hdc, str, -1, &rect, DT_SINGLELINE | DT_CENTER);
		}
		
		if (inProgress) {
			rate = FileSize(gConn.kBytesPerSec * 1024.0, &rStr, NULL);
			rect.left = (3 * clientRect.right / 4);
			rect.right = clientRect.right - 10;
			sprintf(str, "%.1f %s/sec", rate, rStr);
			DrawText(hdc, str, -1, &rect, DT_SINGLELINE | DT_RIGHT);
		}

		SetBkColor(hdc, oldBkColor);
	}
}	/* OnDraw */





LRESULT CALLBACK WndProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	HDC hdc;
	PAINTSTRUCT ps;

	switch (iMsg) {
	case WM_USER:
		return 0;

	case WM_PAINT:
		hdc = BeginPaint(hwnd, &ps);
		OnDraw(hwnd, hdc);
		EndPaint(hwnd, &ps);
		return 0;

	case WM_DESTROY:
		gQuitRequested = 1;
		gConn.cancelXfer = 1;
		return 0;
	}
	
	return DefWindowProc(hwnd, iMsg, wParam, lParam);
}	// WndProc




#pragma warning(disable : 4100)		// warning C4100: unreferenced formal parameter
int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance_unused, PSTR szCmdLine_unused, int iCmdShow)
{
	WNDCLASSEX wndclass;
	HWND hWnd;
	RECT r;

	ghInstance = hInstance;

	ZeroMemory(&gComCtls, sizeof(gComCtls));
	gComCtls.dwSize = sizeof(gComCtls);
	gComCtls.dwICC = ICC_PROGRESS_CLASS;
	if (! InitCommonControlsEx(&gComCtls)) {
		PerrorBox("InitCommonControlsEx");
		return 0;
	}

	ZeroMemory(&wndclass, sizeof(wndclass));
	wndclass.cbSize        = sizeof (wndclass) ;
	wndclass.style         = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc   = WndProc;
	wndclass.cbClsExtra    = 0;
	wndclass.cbWndExtra    = 0;
	wndclass.hInstance     = hInstance;
	wndclass.hCursor       = LoadCursor(NULL, IDC_ARROW) ;
	wndclass.hbrBackground = (HBRUSH) GetStockObject(LTGRAY_BRUSH);
	wndclass.lpszMenuName  = NULL;
	wndclass.lpszClassName = _T("ncftpbatch");
	wndclass.hIcon         = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MAINFRAME));

	if (RegisterClassEx(&wndclass) == (ATOM) 0) {
		PerrorBox("RegisterClassEx");
		return 0;
	}

	// Create the main window, which is
	// never intended to be seen.
	//
	hWnd = CreateWindow (
		wndclass.lpszClassName,		// window class name
		_T("NcFTPBatch"),			// window caption
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,		// window style
		100,						// initial x position
		100,						// initial y position
		450,						// initial x size
		100,						// initial y size
		NULL,						// parent window handle
		NULL,						// window menu handle
		hInstance,					// program instance handle
		NULL);						// creation parameters

	if (hWnd == NULL) {
		PerrorBox("CreateWindow(main window)");
		return 0;
	}
	gMainWnd = hWnd;

	GetClientRect(gMainWnd, &r);
	r.top = r.left = 10;
	r.right -= 10;
	r.bottom -= 10;

	ZeroMemory(gStatusText, (DWORD) sizeof(gStatusText));
	hWnd = CreateWindow (
		"STATIC",					// window class name
		gStatusText,				// window caption
		SS_LEFT | WS_CHILD | WS_VISIBLE,			// window style
		r.left,						// initial x position
		r.top,						// initial y position
		r.right - r.left,			// initial x size
		r.bottom - r.top,			// initial y size
		gMainWnd,					// parent window handle
		NULL,						// window menu handle
		hInstance,					// program instance handle
		NULL);						// creation parameters

	if (hWnd == NULL) {
		PerrorBox("CreateWindow(static control)");
		return 0;
	}
	gStaticCtrl = hWnd;

	SendMessage(gMainWnd, WM_USER, (WPARAM) 0, (LPARAM) 0);
	ShowWindow(gMainWnd, SW_SHOWNORMAL);
	// Here we go!
	//
	PreInit();
	EventShell(0);
	PostShell();

	return 0;
}	// WinMain
#pragma warning(default : 4100)		// warning C4100: unreferenced formal parameter


#else

static int
PRead(int sfd, char *const buf0, size_t size, int retry)
{
	int nread;
	int nleft;
	char *buf = buf0;

	errno = 0;
	nleft = (int) size;
	for (;;) {
		nread = (int) read(sfd, buf, nleft);
		if (nread <= 0) {
			if (nread == 0) {
				/* EOF */
				nread = (int) size - nleft;
				return (nread);
			} else if (errno != EINTR) {
				nread = (int) size - nleft;
				if (nread == 0)
					nread = -1;
				return (nread);
			} else {
				errno = 0;
				nread = 0;
				/* Try again. */
			}
		}
		nleft -= nread;
		if ((nleft <= 0) || (retry == 0))
			break;
		buf += nread;
	}
	nread = (int) size - nleft;
	return (nread);
}	/* PRead */




static void
ReadCore(int fd)
{
	FTPLibraryInfo tLib;
	FTPConnectionInfo tConn;
	int rc;

	if ((PRead(fd, (char *) &tLib, sizeof(tLib), 1) == sizeof(tLib))
		&& (PRead(fd, (char *) &tConn, sizeof(tConn), 1) == sizeof(tConn))
		&& (strncmp(tConn.magic, gConn.magic, sizeof(tConn.magic)) == 0)
	) {
		(void) memcpy(&gConn, &tConn, sizeof(gConn));
		(void) memcpy(&gLib, &tLib, sizeof(gLib));
		rc = FTPRebuildConnectionInfo(&gLib, &gConn);
		if (rc < 0) {
			FTPInit();
		} else {
			gConn.debugLogProc = DebugHook;
		}
	}
}	/* ReadCore */




static void
Daemon(void)
{
#if defined(WIN32) || defined(_WINDOWS)
	/* Change to root directory so filesystems
	 * can be unmounted, if they could in fact
	 * be unmounted.
	 */
	(void) chdir("\\");
#else
	int i, fd;
	int devnull;
	int pid;

	/* Redirect standard in, out, and err, if they were terminals. */
	devnull = open("/dev/null", O_RDWR, 00666);

	for (i=0; i<3; i++) {
		if (gConn.ctrlSocketR == i)
			continue;
		if (gConn.ctrlSocketW == i)
			continue;

		/* Close standard descriptors and replace
		 * with /dev/null.
		 */
		(void) close(i);
		if (devnull >= 0)
			(void) dup2(devnull, i);
	}

	if (devnull >= 0)
		(void) close(devnull);

	/* Close all unneeded descriptors. */
	for (fd = 3; fd < 256; fd++) {
		if (gConn.ctrlSocketR == fd)
			continue;
		if (gConn.ctrlSocketW == fd)
			continue;
		(void) close(fd);
	}

	pid = fork();
	if (pid < 0)
		exit(1);
	else if (pid > 0)
		exit(0);	/* parent. */

#ifdef HAVE_SETSID
	/* Become session leader for this "group." */
	(void) setsid();
#endif

	/* Run as "nohup."  Don't want to get hangup signals. */
	(void) NcSignal(SIGHUP, (FTPSigProc) SIG_IGN);

	/* Turn off TTY control signals, just to be sure. */
	(void) NcSignal(SIGINT, (FTPSigProc) SIG_IGN);
	(void) NcSignal(SIGQUIT, (FTPSigProc) SIG_IGN);
#ifdef SIGTSTP
	(void) NcSignal(SIGTSTP, (FTPSigProc) SIG_IGN);
#endif
	
	/* Become our own process group. */
#ifdef HAVE_SETPGID
	(void) setpgid(0, 0);
#elif defined(HAVE_SETPGRP) && defined(SETPGRP_VOID)
	(void) setpgrp();
#elif defined(HAVE_SETPGRP) && !defined(SETPGRP_VOID)
	(void) setpgrp(0, getpid());
#endif

#ifdef TIOCNOTTY
	/* Detach from controlling terminal, so this
	 * process is not associated with any particular
	 * tty.
	 */
	fd = open("/dev/tty", O_RDWR, 0);
	if (fd >= 0) {
		(void) ioctl(fd, TIOCNOTTY, 0);
		(void) close(fd);
	}
#endif

	/* Change to root directory so filesystems
	 * can be unmounted.
	 */
	(void) chdir("/");
#endif
}	/* Daemon */




static void
Usage(void)
{
	(void) fprintf(stderr, "Usages:\n");
	(void) fprintf(stderr, "\tncftpbatch -d | -D\t\t\t(start NcFTP batch processing)\n");
	(void) fprintf(stderr, "\tncftpbatch -l\t\t\t\t(list spooled jobs)\n");
	(void) fprintf(stderr, "\nLibrary version: %s.\n", gLibNcFTPVersion + 5);
	(void) fprintf(stderr, "This is a freeware program by Mike Gleason (mgleason@probe.net).\n");
	DisposeWinsock(0);
	exit(2);
}	/* Usage */




int
main(int argc, const char **const argv)
{
	int c;
	int runAsDaemon = -1;
	unsigned int sleepval = 0;
	int listonly = -1;
	int readcore = -1;

	PreInit();
	while ((c = getopt(argc, (char **) argv, "|:XDdlSs:w")) > 0) switch(c) {
		case 'd':
			runAsDaemon = 1;
			break;
		case 'D':
			runAsDaemon = 0;
			break;
		case 'l':
			listonly = 1;
			break;
		case 'S':
			sleep(15);
			break;
		case 's':
			sleepval = (unsigned int) atoi(optarg);
			break;
		case 'w':
			gLogOpenMode = FOPEN_WRITE_TEXT;
			break;
		case '|':
			readcore = atoi(optarg);
			break;
		case 'X':
			/* Yes, I do exist. */
			DisposeWinsock(0);
			exit(0);
		default:
			Usage();
	}

	if ((listonly < 0) && (runAsDaemon < 0)) {
		/* Must specify either -l or -d/-D */
		Usage();
	}

	if (listonly > 0) {
		ListQueue();
	} else {
		if (readcore >= 0) {
			/* Inherit current live FTP session
			 * from ncftp!
			 */
			ReadCore(readcore);
		}
		if (runAsDaemon > 0) {
			Daemon();
			gIsTTY = 0;
		}

		EventShell(sleepval);
		PostShell();
	}
	DisposeWinsock(0);
	exit(0);
}	/* main */

#endif


#else	/* HAVE_LONG_FILE_NAMES */
main()
{
	fprintf(stderr, "this program needs long filenames, sorry.\n");
	exit(1);
}	/* main */
#endif	/* HAVE_LONG_FILE_NAMES */
