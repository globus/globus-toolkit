/* util.c
 *
 * Copyright (c) 1992-1999 by Mike Gleason.
 * All rights reserved.
 * 
 */

// This is a subset of NcFTP's util.c.

#include "syshdrs.h"
#include "util.h"

uid_t gUid;
char gUser[32];
char gHome[256];
char gShell[256];
char gOurDirectoryPath[260];
char gOurInstallationPath[260];

static const unsigned char B64EncodeTable[64] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};

static const unsigned char B64DecodeTable[256] =
{
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 000-007 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 010-017 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 020-027 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 030-037 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 040-047 */
	'\177', '\177', '\177', '\76', '\177', '\177', '\177', '\77',	/* 050-057 */
	'\64', '\65', '\66', '\67', '\70', '\71', '\72', '\73',		/* 060-067 */
	'\74', '\75', '\177', '\177', '\177', '\100', '\177', '\177',	/* 070-077 */
	'\177', '\0', '\1', '\2', '\3', '\4', '\5', '\6',	/* 100-107 */
	'\7', '\10', '\11', '\12', '\13', '\14', '\15', '\16',	/* 110-117 */
	'\17', '\20', '\21', '\22', '\23', '\24', '\25', '\26',		/* 120-127 */
	'\27', '\30', '\31', '\177', '\177', '\177', '\177', '\177',	/* 130-137 */
	'\177', '\32', '\33', '\34', '\35', '\36', '\37', '\40',	/* 140-147 */
	'\41', '\42', '\43', '\44', '\45', '\46', '\47', '\50',		/* 150-157 */
	'\51', '\52', '\53', '\54', '\55', '\56', '\57', '\60',		/* 160-167 */
	'\61', '\62', '\63', '\177', '\177', '\177', '\177', '\177',	/* 170-177 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 200-207 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 210-217 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 220-227 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 230-237 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 240-247 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 250-257 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 260-267 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 270-277 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 300-307 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 310-317 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 320-327 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 330-337 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 340-347 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 350-357 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 360-367 */
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177',		/* 370-377 */
};

void
ToBase64(void *dst0, const void *src0, size_t n, int terminate)
{
	unsigned char *dst;
	const unsigned char *src, *srclim;
	unsigned int c0, c1, c2;
	unsigned int ch;

	src = src0;
	srclim = src + n;
	dst = dst0;

	while (src < srclim) {
		c0 = *src++;
		if (src < srclim) {
			c1 = *src++;
		} else {
			c1 = 0;
		}
		if (src < srclim) {
			c2 = *src++;
		} else {
			c2 = 0;
		}

		ch = c0 >> 2;
		dst[0] = B64EncodeTable[ch & 077];

		ch = ((c0 << 4) & 060) | ((c1 >> 4) & 017);
		dst[1] = B64EncodeTable[ch & 077];

		ch = ((c1 << 2) & 074) | ((c2 >> 6) & 03);
		dst[2] = B64EncodeTable[ch & 077];

		ch = (c2 & 077);
		dst[3] = B64EncodeTable[ch & 077];

		dst += 4;
	}
	if (terminate != 0)
		*dst = '\0';
}						       /* ToBase64 */



void
FromBase64(void *dst0, const void *src0, size_t n, int terminate)
{
	unsigned char *dst;
	const unsigned char *src, *srclim;
	unsigned int c0, c1, c2, c3;
	unsigned int ch;

	src = src0;
	srclim = src + n;
	dst = dst0;

	while (src < srclim) {
		c0 = *src++;
		if (src < srclim) {
			c1 = *src++;
		} else {
			c1 = 0;
		}
		if (src < srclim) {
			c2 = *src++;
		} else {
			c2 = 0;
		}
		if (src < srclim) {
			c3 = *src++;
		} else {
			c3 = 0;
		}

		ch = (((unsigned int) B64DecodeTable[c0]) << 2) | (((unsigned int) B64DecodeTable[c1]) >> 4);
		dst[0] = (unsigned char) ch;

		ch = (((unsigned int) B64DecodeTable[c1]) << 4) | (((unsigned int) B64DecodeTable[c2]) >> 2);
		dst[1] = (unsigned char) ch;

		ch = (((unsigned int) B64DecodeTable[c2]) << 6) | (((unsigned int) B64DecodeTable[c3]));
		dst[2] = (unsigned char) ch;

		dst += 3;
	}
	if (terminate != 0)
		*dst = '\0';
}						       /* FromBase64 */



/* This will abbreviate a string so that it fits into max characters.
 * It will use ellipses as appropriate.  Make sure the string has
 * at least max + 1 characters allocated for it.
 */
void
AbbrevStr(char *dst, const char *src, size_t max, int mode)
{
	int len;

	len = (int) strlen(src);
	if (len > (int) max) {
		if (mode == 0) {
			/* ...Put ellipses at left */
			(void) strcpy(dst, "...");
			(void) Strncat(dst, (char *) src + len - (int) max + 3, max + 1);
		} else {
			/* Put ellipses at right... */
			(void) Strncpy(dst, (char *) src, max + 1);
			(void) strcpy(dst + max - 3, "...");
		}
	} else {
		(void) Strncpy(dst, (char *) src, max + 1);
	}
}	/* AbbrevStr */




char *
Path(char *const dst, const size_t siz, const char *const parent, const char *const fname)
{
	(void) Strncpy(dst, parent, siz);
	(void) Strncat(dst, LOCAL_PATH_DELIM_STR, siz);
	return (Strncat(dst, fname, siz));
}	/* Path */




char *
OurDirectoryPath(char *const dst, const size_t siz, const char *const fname)
{
	return (Path(dst, siz, gOurDirectoryPath, fname));
}	/* OurDirectoryPath */



char *
OurInstallationPath(char *const dst, const size_t siz, const char *const fname)
{
	return (Path(dst, siz, gOurInstallationPath, fname));
}	/* OurInstallationPath */




/* Create, if necessary, a directory in the user's home directory to
 * put our incredibly important stuff in.
 */
void
InitOurDirectory(void)
{
#if defined(WIN32) || defined(_WINDOWS)
	DWORD dwType, dwSize;
	HKEY hkey;
	char *cp;
	int rc;

	ZeroMemory(gOurDirectoryPath, (DWORD) sizeof(gOurDirectoryPath));
	ZeroMemory(gOurInstallationPath, (DWORD) sizeof(gOurInstallationPath));

	if (RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ncftp.exe",
		(DWORD) 0,
		KEY_QUERY_VALUE,
		&hkey) == ERROR_SUCCESS)
	{
		dwSize = (DWORD) (sizeof(gOurInstallationPath) - 1);
		dwType = 0;
		if (RegQueryValueEx(
			hkey, 
			NULL, 
			(DWORD *) 0, 
			&dwType, 
			(LPBYTE) gOurInstallationPath, 
			&dwSize) == ERROR_SUCCESS)
		{
			// This gave us the path to ncftp.exe;
			// But we use a subdirectory in that directory.
			//
			cp = StrRFindLocalPathDelim(gOurInstallationPath);
			if (cp == NULL)
				ZeroMemory(gOurInstallationPath, (DWORD) sizeof(gOurInstallationPath));
			else
				ZeroMemory(cp, (DWORD) (cp - gOurInstallationPath));
		}
		RegCloseKey(hkey);
	}
	
	if (gOurInstallationPath[0] == '\0') {
		if (GetModuleFileName(NULL, gOurInstallationPath, (DWORD) sizeof(gOurInstallationPath) - 1) <= 0) {
			ZeroMemory(gOurInstallationPath, (DWORD) sizeof(gOurInstallationPath));
		} else {
			// This gave us the path to the current .exe;
			// But we use a subdirectory in that directory.
			//
			cp = StrRFindLocalPathDelim(gOurInstallationPath);
			if (cp == NULL)
				ZeroMemory(gOurInstallationPath, (DWORD) sizeof(gOurInstallationPath));
			else
				ZeroMemory(cp, (DWORD) (cp - gOurInstallationPath));
		}
	}

	if (gOurInstallationPath[0] != '\0') {
		if ((cp = getenv("NCFTPDIR")) != NULL) {
			(void) STRNCPY(gOurDirectoryPath, cp);
		} else if ((cp = getenv("HOME")) != NULL) {
			(void) STRNCPY(gOurDirectoryPath, cp);
		} else {
			STRNCPY(gOurDirectoryPath, gOurInstallationPath);
			if (gUser[0] == '\0') {
				STRNCAT(gOurDirectoryPath, "\\Users\\default");
			} else {
				STRNCAT(gOurDirectoryPath, "\\Users\\");
				STRNCAT(gOurDirectoryPath, gUser);
			}
		}
		rc = MkDirs(gOurDirectoryPath, 00755);
	}

#else
	struct stat st;
	char *cp;

#ifdef BINDIR
	(void) STRNCPY(gOurInstallationPath, BINDIR);
#else
	memset(gOurInstallationPath, 0, sizeof(gOurInstallationPath));
#endif

	cp = getenv("NCFTPDIR");
	if (cp != NULL) {
		(void) STRNCPY(gOurDirectoryPath, cp);
	} else if (STREQ(gHome, "/")) {
		/* Don't create it if you're root and your home directory
		 * is the root directory.
		 *
		 * If you are root and you want to store your ncftp
		 * config files, move your home directory somewhere else,
		 * such as /root or /home/root.
		 */
		gOurDirectoryPath[0] = '\0';
		return;
	} else {
		(void) Path(gOurDirectoryPath,
			sizeof(gOurDirectoryPath),
			gHome,
			kOurDirectoryName
		);
	}

	if (stat(gOurDirectoryPath, &st) < 0) {
		if (mkdir(gOurDirectoryPath, 00755) < 0) {
			gOurDirectoryPath[0] = '\0';
		}
	}
#endif
}	/* InitOurDirectory */



void
InitUserInfo(void)
{
#if defined(WIN32) || defined(_WINDOWS)
	DWORD nSize;
	char *cp;

	memset(gUser, 0, sizeof(gUser));
	nSize = sizeof(gUser) - 1;
	if (! GetUserName(gUser, &nSize))
		STRNCPY(gUser, "default");

	memset(gHome, 0, sizeof(gHome));
	(void) GetTempPath((DWORD) sizeof(gHome) - 1, gHome);
	cp = strrchr(gHome, '\\');
	if ((cp != NULL) && (cp[1] == '\0'))
		*cp = '\0';

	memset(gShell, 0, sizeof(gShell));
#else
	struct passwd *pwptr;
	char *envp;

	gUid = geteuid();
	pwptr = getpwuid(gUid);

	if (pwptr == NULL) {
		envp = getenv("LOGNAME");
		if (envp == NULL) {
			(void) fprintf(stderr, "Who are you?\n");
			(void) fprintf(stderr, "You have a user id number of %d, but no username associated with it.\n", (int) gUid);
			(void) STRNCPY(gUser, "unknown");
		} else {
			(void) STRNCPY(gUser, envp);
		}

		envp = getenv("HOME");
		if (envp == NULL)
			(void) STRNCPY(gHome, "/");
		(void) STRNCPY(gHome, envp);

		envp = getenv("SHELL");
		if (envp == NULL)
			(void) STRNCPY(gShell, "/bin/sh");
		(void) STRNCPY(gShell, envp);
	} else {
		/* Copy home directory. */
		(void) STRNCPY(gHome, pwptr->pw_dir);

		/* Copy user name. */
		(void) STRNCPY(gUser, pwptr->pw_name);

		/* Copy shell. */
		(void) STRNCPY(gShell, pwptr->pw_shell);
	}
#endif

	InitOurDirectory();
}	/* InitUserInfo */



int 
StrToBool(const char *const s)
{
	int c;
	int result;
	
	c = *s;
	if (isupper(c))
		c = tolower(c);
	result = 0;
	switch (c) {
		case 'f':			       /* false */
		case 'n':			       /* no */
			break;
		case 'o':			       /* test for "off" and "on" */
			c = (int) s[1];
			if (isupper(c))
				c = tolower(c);
			if (c == 'f')
				break;
			/* fall through */
		case 't':			       /* true */
		case 'y':			       /* yes */
			result = 1;
			break;
		default:			       /* 1, 0, -1, other number? */
			if (atoi(s) != 0)
				result = 1;
	}
	return result;
}						       /* StrToBool */



/* Read a line, and axe the end-of-line. */
char *
FGets(char *str, size_t size, FILE *fp)
{
	char *cp, *nlptr;
	
	cp = fgets(str, ((int) size) - 1, fp);
	if (cp != NULL) {
		cp[((int) size) - 1] = '\0';	/* ensure terminator */
		nlptr = cp + strlen(cp) - 1;
		if (*nlptr == '\n')
			*nlptr = '\0';
	} else {
		memset(str, 0, size);
	}
	return cp;
}	/* FGets */




char *
StrFindLocalPathDelim(const char *src) /* TODO: optimize */
{
	const char *first;
	int c;

	first = NULL;
	for (;;) {
		c = *src++;
		if (c == '\0')
			break;
		if (IsLocalPathDelim(c)) {
			first = src - 1;
			break;
		}
	}

	return ((char *) first);
}	/* StrFindLocalPathDelim */



char *
StrRFindLocalPathDelim(const char *src)	/* TODO: optimize */
{
	const char *last;
	int c;

	last = NULL;
	for (;;) {
		c = *src++;
		if (c == '\0')
			break;
		if (IsLocalPathDelim(c))
			last = src - 1;
	}

	return ((char *) last);
}	/* StrRFindLocalPathDelim */





int
MkDirs(const char *const newdir, int mode1)
{
	char s[512];
	int rc;
	char *cp, *sl;
#if defined(WIN32) || defined(_WINDOWS)
	struct _stat st;
	char *share;
#else
	struct stat st;
	mode_t mode = (mode_t) mode1;
#endif

#if defined(WIN32) || defined(_WINDOWS)
	if ((isalpha(newdir[0])) && (newdir[1] == ':')) {
		if (! IsLocalPathDelim(newdir[2])) {
			/* Special case "c:blah", and errout.
			 * "c:\blah" must be used or _access GPFs.
			 */
			errno = EINVAL;
			return (-1);
		} else if (newdir[3] == '\0') {
			/* Special case root directory, which cannot be made. */
			return (0);
		}
	} else if (IsUNCPrefixed(newdir)) {
		share = StrFindLocalPathDelim(newdir + 2);
		if ((share == NULL) || (StrFindLocalPathDelim(share + 1) == NULL))
			return (-1);
	}

	if (_access(newdir, 00) == 0) {
		if (_stat(newdir, &st) < 0)
			return (-1);
		if (! S_ISDIR(st.st_mode)) {
			errno = ENOTDIR;
			return (-1);
		}
		return 0;
	}
#else
	if (access(newdir, F_OK) == 0) {
		if (stat(newdir, &st) < 0)
			return (-1);
		if (! S_ISDIR(st.st_mode)) {
			errno = ENOTDIR;
			return (-1);
		}
		return 0;
	}
#endif

	(void) strncpy(s, newdir, sizeof(s));
	if (s[sizeof(s) - 1] != '\0') {
#ifdef ENAMETOOLONG
		errno = ENAMETOOLONG;
#else
		errno = EINVAL;
		return (-1);
#endif
	}

	cp = StrRFindLocalPathDelim(s);
	if (cp == NULL) {
#if defined(WIN32) || defined(_WINDOWS)
		if (! CreateDirectory(newdir, (LPSECURITY_ATTRIBUTES) 0))
			return (-1);
		return (0);
#else
		rc = mkdir(newdir, mode);
		return (rc);
#endif
	} else if (cp[1] == '\0') {
		/* Remove trailing slashes from path. */
		--cp;
		while (cp > s) {
			if (! IsLocalPathDelim(*cp))
				break;
			--cp;
		}
		cp[1] = '\0';
		cp = StrRFindLocalPathDelim(s);
		if (cp == NULL) {
#if defined(WIN32) || defined(_WINDOWS)
			if (! CreateDirectory(s, (LPSECURITY_ATTRIBUTES) 0))
				return (-1);
#else
			rc = mkdir(s, mode);
			return (rc);
#endif
		}
	}

	/* Find the deepest directory in this
	 * path that already exists.  When
	 * we do, we want to have the 's'
	 * string as it was originally, but
	 * with 'cp' pointing to the first
	 * slash in the path that starts the
	 * part that does not exist.
	 */
	sl = NULL;
	for (;;) {
		*cp = '\0';
#if defined(WIN32) || defined(_WINDOWS)
		rc = _access(s, 00);
#else
		rc = access(s, F_OK);
#endif
		if (sl != NULL)
			*sl = LOCAL_PATH_DELIM;
		if (rc == 0) {
			*cp = LOCAL_PATH_DELIM;
			break;
		}
		sl = cp;
		cp = StrRFindLocalPathDelim(s);
		if (cp == NULL) {
			/* We do not have any more
			 * slashes, so none of the
			 * new directory's components
			 * existed before, so we will
			 * have to make everything
			 * starting at the first node.
			 */
			if (sl != NULL)
				*sl = LOCAL_PATH_DELIM;
			cp = s - 1;
			break;
		}
	}

	for (;;) {
		/* Extend the path we have to
		 * include the next component
		 * to make.
		 */
		sl = StrFindLocalPathDelim(cp + 1);
		if (sl == s) {
			/* If the next slash is pointing
			 * to the start of the string, then
			 * the path is an absolute path and
			 * we don't need to make the root node,
			 * and besides the next mkdir would
			 * try an empty string.
			 */
			++cp;
			sl = StrFindLocalPathDelim(cp + 1);
		}
		if (sl != NULL) {
			*sl = '\0';
		}
#if defined(WIN32) || defined(_WINDOWS)
		if (! CreateDirectory(s, (LPSECURITY_ATTRIBUTES) 0))
			return (-1);
#else
		rc = mkdir(s, mode);
		if (rc < 0)
			return rc;
#endif
		if (sl == NULL)
			break;
		*sl = LOCAL_PATH_DELIM;
		cp = sl;
	}
	return (0);
}	/* MkDirs */