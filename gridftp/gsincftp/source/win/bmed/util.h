/* util.h
 *
 * Copyright (c) 1992-1999 by Mike Gleason.
 * All rights reserved.
 * 
 */

typedef int (*qsort_proc_t)(const void *, const void *);
typedef int (*bsearch_proc_t)(const void *, const void *);
typedef void (*sigproc_t)(int);
typedef volatile sigproc_t vsigproc_t;

#define STREQ(a,b) (strcmp(a,b) == 0)
#define STRNEQ(a,b,s) (strncmp(a,b,(size_t)(s)) == 0)

#ifndef ISTRCMP
#	ifdef HAVE_STRCASECMP
#		define ISTRCMP strcasecmp
#		define ISTRNCMP strncasecmp
#	else
#		define ISTRCMP strcmp
#		define ISTRNCMP strncmp
#	endif
#endif

#define ISTREQ(a,b) (ISTRCMP(a,b) == 0)
#define ISTRNEQ(a,b,s) (ISTRNCMP(a,b,(size_t)(s)) == 0)
#define YESNO(i) ((i == 0) ? "no" : "yes")
#define ONOFF(i) ((i == 0) ? "off" : "on")
#define TRUEFALSE(i) ((i == 0) ? "false" : "true")

#ifndef HAVE_STRCOLL
#	ifndef strcoll
#		define strcoll strcmp
#	endif
#	ifndef strncoll
#		define strncoll strncmp
#	endif
#endif

#ifndef F_OK
#	define F_OK 0
#endif

#define kOurDirectoryName	".ncftp"

#define kPasswordMagic "*encoded*"
#define kPasswordMagicLen 9

#define kCommandAvailabilityUnknown	(-1)
#define kCommandAvailable		1
#define kCommandNotAvailable		0

#define kDefaultFTPPort			21

#	define LOCAL_PATH_DELIM '\\'
#	define LOCAL_PATH_DELIM_STR "\\"
#	define LOCAL_PATH_ALTDELIM '/'
#	define IsLocalPathDelim(c) ((c == LOCAL_PATH_DELIM) || (c == LOCAL_PATH_ALTDELIM))
#	define UNC_PATH_PREFIX "\\\\"
#	define IsUNCPrefixed(s) (IsLocalPathDelim(s[0]) && IsLocalPathDelim(s[1]))

#ifdef __cplusplus
extern "C" {
#endif

/* util.c */
void ToBase64(void *, const void *, size_t, int);
void FromBase64(void *, const void *, size_t, int);
char *FileToURL(char *url, size_t urlsize, const char *const fn, const char *const rcwd, const char *const startdir, const char *const user, const char *const pass, const char *const hname, const unsigned int port);
void AbbrevStr(char *, const char *, size_t, int);
char *Path(char *const dst, const size_t siz, const char *const parent, const char *const fname);
char *OurDirectoryPath(char *const dst, const size_t siz, const char *const fname);
void InitOurDirectory(void);
void InitUserInfo(void);
int StrToBool(const char *const);
char *OurInstallationPath(char *const dst, const size_t siz, const char *const fname);

char *FGets(char *str, size_t size, FILE *fp);
int MkDirs(const char *const, int mode1);
char *StrFindLocalPathDelim(const char *src);
char *StrRFindLocalPathDelim(const char *src);

#ifdef __cplusplus
}
#endif
