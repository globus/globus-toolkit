/* gpshare.c
 *
 * Copyright (c) 1996-2000 Mike Gleason, NCEMRSoft.
 * All rights reserved.
 *
 * Shared routines for ncftpget and ncftpput.
 */

#include "syshdrs.h"
#include "gpshare.h"

#if defined(WIN32) || defined(_WINDOWS)
	extern WSADATA wsaData;
	extern int wsaInit;
#endif

double
FileSize(double size, const char **uStr0, double *uMult0)
{
	double uMult, uTotal;
	const char *uStr;

	/* The comparisons below may look odd, but the reason
	 * for them is that we only want a maximum of 3 digits
	 * before the decimal point.  (I.e., we don't want to
	 * see "1017.2 kB", instead we want "0.99 MB".
	 */
	if (size > (999.5 * kGigabyte)) {
		uStr = "TB";
		uMult = kTerabyte;
	} else if (size > (999.5 * kMegabyte)) {
		uStr = "GB";
		uMult = kGigabyte;
	} else if (size > (999.5 * kKilobyte)) {
		uStr = "MB";
		uMult = kMegabyte;
	} else if (size > 999.5) {
		uStr = "kB";
		uMult = 1024;
	} else {
		uStr = "B";
		uMult = 1;
	}
	if (uStr0 != NULL)
		*uStr0 = uStr;
	if (uMult0 != NULL)
		*uMult0 = uMult;
	uTotal = size / ((double) uMult);
	if (uTotal < 0.0)
		uTotal = 0.0;
	return (uTotal);
}	/* FileSize */




void
PrSizeAndRateMeter(const FTPCIPtr cip, int mode)
{
	double rate;
	const char *rStr;
	static const char *uStr;
	static double uMult;
	char localName[32];
	char line[128];
	int i;

	switch (mode) {
		case kPrInitMsg:
			if (cip->expectedSize != kSizeUnknown) {
				cip->progress = PrStatBar;
				PrStatBar(cip, mode);
				return;
			}
			(void) FileSize((double) cip->expectedSize, &uStr, &uMult);

			if (cip->lname == NULL) {
				localName[0] = '\0';
			} else {
				AbbrevStr(localName, cip->lname, sizeof(localName) - 2, 0);
				(void) STRNCAT(localName, ":");
			}

			(void) fprintf(stderr, "%-32s", localName);
			break;

		case kPrUpdateMsg:
			rate = FileSize(cip->kBytesPerSec * 1024.0, &rStr, NULL);

			if (cip->lname == NULL) {
				localName[0] = '\0';
			} else {
				AbbrevStr(localName, cip->lname, sizeof(localName) - 2, 0);
				(void) STRNCAT(localName, ":");
			}

#ifdef PRINTF_LONG_LONG_LLD
			(void) sprintf(line, "%-32s  %10lld bytes  %6.2f %s/s",
				localName,
				(longest_int) (cip->bytesTransferred + cip->startPoint),
				rate,
				rStr
			);
#elif defined(PRINTF_LONG_LONG_QD)
			(void) sprintf(line, "%-32s  %10qd bytes  %6.2f %s/s",
				localName,
				(longest_int) (cip->bytesTransferred + cip->startPoint),
				rate,
				rStr
			);
#elif defined(PRINTF_LONG_LONG_I64D)
			(void) sprintf(line, "%-32s  %10I64d bytes  %6.2f %s/s",
				localName,
				(longest_int) (cip->bytesTransferred + cip->startPoint),
				rate,
				rStr
			);
#else
			(void) sprintf(line, "%-32s  %10ld bytes  %6.2f %s/s",
				localName,
				(long) (cip->bytesTransferred + cip->startPoint),
				rate,
				rStr
			);
#endif

			/* Pad the rest of the line with spaces, to erase any
			 * stuff that might have been left over from the last
			 * update.
			 */
			for (i = (int) strlen(line); i < 80 - 2; i++)
				line[i] = ' ';
			line[i] = '\0';

			/* Print the updated information. */
			(void) fprintf(stderr, "\r%s", line);
			break;

		case kPrEndMsg:
			(void) fprintf(stderr, "\n\r");
			break;
	}
}	/* PrSizeAndRateMeter */




void
PrStatBar(const FTPCIPtr cip, int mode)
{
	double rate, done;
	int secLeft, minLeft;
	const char *rStr;
	static const char *uStr;
	static double uTotal, uMult;
	const char *stall;
	char localName[80];
	char line[128];
	int i;

	switch (mode) {
		case kPrInitMsg:
			fflush(stdout);
			if (cip->expectedSize == kSizeUnknown) {
				cip->progress = PrSizeAndRateMeter;
				PrSizeAndRateMeter(cip, mode);
				return;
			}
			uTotal = FileSize((double) cip->expectedSize, &uStr, &uMult);

			if (cip->lname == NULL) {
				localName[0] = '\0';
			} else {
				/* Leave room for a ':' and '\0'. */
				AbbrevStr(localName, cip->lname, sizeof(localName) - 2, 0);
				(void) STRNCAT(localName, ":");
			}
			(void) fprintf(stderr, "%-32s", localName);
			break;

		case kPrUpdateMsg:
			secLeft = (int) (cip->secLeft + 0.5);
			minLeft = secLeft / 60;
			secLeft = secLeft - (minLeft * 60);
			if (minLeft > 999) {
				minLeft = 999;
				secLeft = 59;
			}

			rate = FileSize(cip->kBytesPerSec * 1024.0, &rStr, NULL);
			done = (double) (cip->bytesTransferred + cip->startPoint) / uMult;

			if (cip->lname == NULL) {
				localName[0] = '\0';
			} else {
				AbbrevStr(localName, cip->lname, 31, 0);
				(void) STRNCAT(localName, ":");
			}

			if (cip->stalled < 2)
				stall = " ";
			else if (cip->stalled < 15)
				stall = "-";
			else
				stall = "=";

			(void) sprintf(line, "%-32s   ETA: %3d:%02d  %6.2f/%6.2f %-2.2s  %6.2f %.2s/s %.1s",
				localName,
				minLeft,
				secLeft,
				done,
				uTotal,
				uStr,
				rate,
				rStr,
				stall
			);

			/* Print the updated information. */
			(void) fprintf(stderr, "\r%s", line);
			break;

		case kPrEndMsg:

			rate = FileSize(cip->kBytesPerSec * 1024.0, &rStr, NULL);
			done = (double) (cip->bytesTransferred + cip->startPoint) / uMult;

			if (cip->expectedSize >= (cip->bytesTransferred + cip->startPoint)) {
				if (cip->lname == NULL) {
					localName[0] = '\0';
				} else {
					AbbrevStr(localName, cip->lname, 52, 0);
					(void) STRNCAT(localName, ":");
				}

				(void) sprintf(line, "%-53s  %6.2f %-2.2s  %6.2f %.2s/s  ",
					localName,
					uTotal,
					uStr,
					rate,
					rStr
				);
			} else {
				if (cip->lname == NULL) {
					localName[0] = '\0';
				} else {
					AbbrevStr(localName, cip->lname, 45, 0);
					(void) STRNCAT(localName, ":");
				}

				(void) sprintf(line, "%-46s  %6.2f/%6.2f %-2.2s  %6.2f %.2s/s  ",
					localName,
					done,
					uTotal,
					uStr,
					rate,
					rStr
				);
			}

			/* Pad the rest of the line with spaces, to erase any
			 * stuff that might have been left over from the last
			 * update.
			 */
			for (i = (int) strlen(line); i < 80 - 2; i++)
				line[i] = ' ';
			line[i] = '\0';

			/* Print the updated information. */
			(void) fprintf(stderr, "\r%s\n\r", line);
			break;
	}
}	/* PrStatBar */




void
ReadConfigFile(const char *fn, FTPCIPtr cip)
{
	FILE *fp;
	char line[128];
	char *cp;
	int goodfile = 0;

	fp = fopen(fn, FOPEN_READ_TEXT);
	if (fp == NULL) {
		perror(fn);
		exit(kExitBadConfigFile);
	}

	line[sizeof(line) - 1] = '\0';
	while (fgets(line, sizeof(line) - 1, fp) != NULL) {
		if ((line[0] == '#') || (isspace((int) line[0])))
			continue;
		cp = line + strlen(line) - 1;
		if (*cp == '\n')
			*cp = '\0';
		if (strncmp(line, "user", 4) == 0) {
			(void) STRNCPY(cip->user, line + 5);
			goodfile = 1;
		} else if (strncmp(line, "password", 8) == 0) {
			(void) STRNCPY(cip->pass, line + 9);
			goodfile = 1;
		} else if ((strncmp(line, "pass", 4) == 0) && (isspace((int) line[4]))) {
			(void) STRNCPY(cip->pass, line + 5);
			goodfile = 1;
		} else if (strncmp(line, "host", 4) == 0) {
			(void) STRNCPY(cip->host, line + 5);
			goodfile = 1;
		} else if ((strncmp(line, "acct", 4) == 0) && (isspace((int) line[4]))) {
			(void) STRNCPY(cip->acct, line + 5);
		} else if (strncmp(line, "account", 7) == 0) {
			(void) STRNCPY(cip->acct, line + 8);
		}
	}
	(void) fclose(fp);

	if (goodfile == 0) {
		(void) fprintf(stderr, "%s doesn't contain anything useful.\n", fn);
		(void) fprintf(stderr, "%s should look something like this:\n", fn);
		(void) fprintf(stderr, "# Comment lines starting with a hash character\n# and blank lines are ignored.\n\n");
		(void) fprintf(stderr, "host Bozo.probe.net\n");
		(void) fprintf(stderr, "user gleason\n");
		(void) fprintf(stderr, "pass mypasswd\n");
		exit(kExitBadConfigFile);
	}
}	/* ReadConfigFile */




void
SetRedial(const FTPCIPtr cip, const char *const argstr)
{
	char buf[256];
	char *tok;
	char *parse;
	int nt = 0;
	int i;

	(void) STRNCPY(buf, argstr);
	for (parse = buf; (tok = strtok(parse, ", \n\t\r")) != NULL; parse = NULL) {
		nt++;
		if (nt == 1) {
			if (strcmp(tok, "forever") == 0)
				cip->maxDials = -1;
			else {
				i = atoi(tok);
				if (i == 0)
					cip->maxDials = 1;
				else
					cip->maxDials = i;
			}
		} else if (nt == 2) {
			i = atoi(tok);
			if (i < 2)
				i = 2;
			cip->redialDelay = i;
		}
	}
}	/* SetRedial */



void
SetTimeouts(const FTPCIPtr cip, const char *const argstr)
{
	char buf[256];
	char *tok;
	char *parse;
	int nt = 0;

	(void) STRNCPY(buf, argstr);
	for (parse = buf; (tok = strtok(parse, ", \n\t\r")) != NULL; parse = NULL) {
		nt++;
		if (nt == 1) {
			cip->xferTimeout = atoi(tok);
			cip->connTimeout = atoi(tok);
			cip->ctrlTimeout = atoi(tok);
		} else if (nt == 2) {
			cip->connTimeout = atoi(tok);
		} else if (nt == 3) {
			cip->ctrlTimeout = atoi(tok);
		}
	}
}	/* SetTimeouts */



void
InitWinsock(void)
{
#if defined(WIN32) || defined(_WINDOWS)
	if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
		fprintf(stderr, "could not initialize winsock\n");
		exit(1);
	}
	wsaInit++;
#endif
}	/* InitWinsock */



int
GetDefaultProgressMeterSetting(void)
{
	int progmeters;

#if defined(WIN32) || defined(_WINDOWS)
	progmeters = _isatty(_fileno(stderr));
#else
	progmeters = ((isatty(2) != 0) && (getppid() > 1)) ? 1 : 0;
#endif
	return (progmeters);
}	/* GetDefaultProgressMeterSetting */



FILE *
OpenPager(void)
{
	FILE *fp;

#if defined(WIN32) || defined(_WINDOWS)
	fp = stderr;
#else
	const char *cp;

	cp = (const char *) getenv("PAGER");
	if (cp == NULL)
		cp = "more";
	fp = popen(cp, "w");
	if (fp == NULL)
		fp = stderr;
#endif
	return (fp);
}	/* OpenPager */



void ClosePager(FILE *fp)
{
	if (fp == stderr)
		return;
#if defined(WIN32) || defined(_WINDOWS)
#else
	(void) pclose(fp);
#endif
}	/* ClosePager */




int
AdditionalCmd(FTPCIPtr const cip, const char *const spec, const char *const arg)
{
	int rc;
	char cmd[500], *dst, *dlim;
	const char *src, *s2;

	rc = kNoErr;
	if ((spec != NULL) && (spec[0] != '\0')) {
		src = spec;
		while (*src) {
			dst = cmd;
			dlim = cmd + sizeof(cmd) - 1;
			for ( ; *src != '\0'; src++) {
				if ((*src == '%') && (src[1] == 's')) {
					for (s2 = arg; *s2 != '\0'; s2++) {
						if (dst < dlim)
							*dst++ = *s2;
					}
					src++;
				} else if (*src == '\n') {
					src++;
					break;
				} else if (*src != '\r') {
					if (dst < dlim)
						*dst++ = *src;
				}
			}
			*dst = '\0';
			
			if (cmd[0] != '\0') {
				rc = FTPCmd(cip, "%s", cmd);
				if (rc != 2)
					rc = kErrGeneric;
			}
		}
	}
	return (rc);
}	/* AdditionalCmd */

/* eof */
