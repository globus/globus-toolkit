/* bookmark editor */

#include "syshdrs.h"

#include "../ncftp/util.h"
#include "../ncftp/trace.h"
#include "../ncftp/pref.h"
#include "../ncftp/bookmark.h"
#include "wutil.h"
#include "wgets.h"
#include "bmed.h"

/* Are we being run as a regular process, or a
 * subprocess of ncftp?
 */
int gStandAlone;

/* This is the full-screen window that pops up when you run the
 * host editor.  Not much is done with it, except display directions
 * and getting host editor commands.
 */
WINDOW *gHostWin = NULL;

/* This is a window devoted solely to serve as a scrolling list
 * of bookmarks.
 */
WINDOW *gHostListWin = NULL;

int gHostListWinWide;

/* This is another full-screen window that opens when a user wants
 * to edit the parameters for a site.
 */
WINDOW *gEditHostWin = NULL;

/* This is an index into the host list.  This indicates the position
 * in the host list where we draw the current "page" of the host list.
 */
int gHostListWinStart;

/* This index is the currently selected host.  This index must be >=
 * to gHostListWinStart and less than gHostListWinStart + pageLen - 1,
 * so that this host will show up in the current page of the host list.
 */
int gHilitedHost;

/* This is a pointer to the actual information of the currently
 * selected host.
 */
BookmarkPtr gCurHostListItem;

/* How many lines compose a "page" in the host list's scrolling window. */
int gHostListPageSize;

/* A flag saying if we need to erase a message after the next input key. */
int gNeedToClearMsg = 0;

/* When we edit gCurHostListItem's stuff, we actually edit a copy of it.
 * This is so we could restore the information if the user wanted to
 * abort the changes.
 */
Bookmark gEditRsi;

#ifdef HAVE_SIGSETJMP
sigjmp_buf gHostWinJmp;
#else	/* HAVE_SIGSETJMP */
jmp_buf gHostWinJmp;
#endif	/* HAVE_SIGSETJMP */

/* If set to a valid pathname, hitting enter at the host selection
 * screen will write the name of the bookmark into this file.
 * This is a cheap form of IPC with a parent NcFTP process.
 */
const char *gBookmarkSelectionFile = NULL;

/* Needed by prefs. */
FTPLibraryInfo gLib;
FTPConnectionInfo gConn;

extern int gWinInit;
extern int gScreenWidth;
extern int gScreenHeight;
extern int gNumBookmarks;
extern BookmarkPtr gBookmarkTable;
extern int gDebug;




void AtoIMaybe(int *dst, char *str)
{
	char *cp;
	
	/* Don't change the value if the user just hit return. */
	for (cp = str; *cp != '\0'; cp++)
		if (isdigit((int) *cp))
			break;
	if (isdigit((int) *cp))
		*dst = atoi(str);
}	/* AtoIMaybe */





/* Draws the screen when we're using the host editor's main screen.
 * You can can specify whether to draw each character whether it needs
 * it or not if you like.
 */
void UpdateHostWindows(int uptAll)
{
	if (uptAll) {
		DrawHostList();
		touchwin(gHostListWin);
		touchwin(gHostWin);
	}
	wnoutrefresh(gHostListWin);
	wnoutrefresh(gHostWin);
	DOUPDATE(1);
}	/* UpdateHostWindows */



/* This draws the scrolling list of bookmarks, and hilites the currently
 * selected host.
 */
void DrawHostList(void)
{
	int lastLine, i;
	BookmarkPtr rsip;
	char str[256];
	char url[256];
	int maxy, maxx;
	int lmaxy, lmaxx;
	int begy, begx;
	char spec[32];

	getmaxyx(gHostListWin, lmaxy, lmaxx);
	getbegyx(gHostListWin, begy, begx);
	getmaxyx(gHostWin, maxy, maxx);
	/* We have a status line saying how many bookmarks there are in
	 * the list.  That way the user knows something is supposed to
	 * be there when the host list is totally empty, and also that
	 * there are more bookmarks to look at when the entire host list
	 * doesn't fit in the scroll window.
	 */
	WAttr(gHostWin, kUnderline, 1);
	mvwprintw(
		gHostWin,
		begy - 1,
		begx,
		"%s",
		"Number of bookmarks"
	);
	WAttr(gHostWin, kUnderline, 0);
	wprintw(
		gHostWin,
		": %3d",
		gNumBookmarks
	);

	if (gHostListWinWide == 0) {
		sprintf(spec, "%%-16.16s %%-%ds", lmaxx - 17);
		lastLine = lmaxy + gHostListWinStart;
		for (i=gHostListWinStart; (i<lastLine) && (i<gNumBookmarks); i++) {
			rsip = &gBookmarkTable[i];
			if (rsip == gCurHostListItem)
				WAttr(gHostListWin, kReverse, 1);
			sprintf(str, spec, rsip->bookmarkName, rsip->name);
			str[lmaxx] = '\0';
			mvwaddstr(gHostListWin, i - gHostListWinStart, 0, str);
			swclrtoeol(gHostListWin);
			if (rsip == gCurHostListItem) {
				WAttr(gHostListWin, kReverse, 0);
			}
		}
	} else {
		lastLine = lmaxy + gHostListWinStart;
		for (i=gHostListWinStart; (i<lastLine) && (i<gNumBookmarks); i++) {
			rsip = &gBookmarkTable[i];
			if (rsip == gCurHostListItem)
				WAttr(gHostListWin, kReverse, 1);
			BookmarkToURL(rsip, url, sizeof(url));
			sprintf(str, "%-16.16s  ", rsip->bookmarkName);
			STRNCAT(str, url);
			memset(url, 0, sizeof(url));
			AbbrevStr(url, str, (size_t) lmaxx, 1);
			mvwaddstr(gHostListWin, i - gHostListWinStart, 0, url);
			swclrtoeol(gHostListWin);
			if (rsip == gCurHostListItem) {
				WAttr(gHostListWin, kReverse, 0);
			}
		}
	}


	/* Add 'vi' style empty-lines. */
	for ( ; i<lastLine; ++i) {
		mvwaddstr(gHostListWin, i - gHostListWinStart, 0, "~");
		swclrtoeol(gHostListWin);
	}
	wmove(gHostWin, maxy - 3, 2);
	sprintf(spec, "%%-%ds", maxx - 4);
	if (gCurHostListItem == NULL) {
		str[0] = '\0';
	} else if (gCurHostListItem->comment[0] == '\0') {
		memset(str, 0, sizeof(str));
		if (gHostListWinWide == 0) {
			BookmarkToURL(gCurHostListItem, url, sizeof(url));
			AbbrevStr(str, url, (size_t) maxx - 2, 1);
		}
	} else {
		STRNCPY(str, "``");
		STRNCAT(str, gCurHostListItem->comment);
		AbbrevStr(str + 2, gCurHostListItem->comment, (size_t) maxx - 8, 1);
		STRNCAT(str, "''");
	}
	wprintw(gHostWin, spec, str);
	wmove(gHostWin, maxy - 1, 0);
	UpdateHostWindows(0);
}	/* DrawHostList */




/* This prompts for a key of input when in the main host editor window. */
int HostWinGetKey(void)
{
	int c;
	int uc;
	int maxy, maxx;
	int escmode;

	getmaxyx(gHostWin, maxy, maxx);
	wmove(gHostWin, maxy - 1, 0);
	for (escmode = 0; ; escmode++) {
		uc = (unsigned int) wgetch(gHostWin);
		c = (int) uc;
		if (uc > 255) {
			Trace(1, "[0x%04X]\n", c);
		} else if (isprint(c) && !iscntrl(c)) {
			Trace(1, "[0x%04X, %c]\n", c, c);
		} else if (iscntrl(c)) {
			Trace(1, "[0x%04X, ^%c]\n", c, (c & 31) | ('A' - 1));
		} else {
			Trace(1, "[0x%04X]\n", c);
		}

		/* Some implementations of curses (i.e. Mac OS X)
		 * don't seem to detect the arrow keys on
		 * typical terminal types like "vt100" or "ansi",
		 * so we try and detect them the hard way.
		 */
		switch (escmode) {
			case 0:
				if (uc != 0x001B) {
					goto gotch;
				}
				/* else ESC key (^[) */
				break;
			case 1:
				if ((c != '[') && (c != 'O')) {
					goto gotch;
				}
				/* else ANSI ESC sequence continues */
				break;
			case 2:
				switch (c) {
					case 'A':
					case 'a':
#ifdef KEY_UP
						c = KEY_UP;
						Trace(1, "  --> [0x%04X, %s]\n", c, "UP");
#else
						c = 'k';	/* vi UP */
						Trace(1, "  --> [0x%04X, %s]\n", c, "k");
#endif
						break;
					case 'B':
					case 'b':
#ifdef KEY_DOWN
						c = KEY_DOWN;
						Trace(1, "  --> [0x%04X, %s]\n", c, "DOWN");
#else
						c = 'j';	/* vi DOWN */
						Trace(1, "  --> [0x%04X, %s]\n", c, "j");
#endif
						break;
					case 'D':
					case 'd':
#ifdef KEY_LEFT
						c = KEY_LEFT;
						Trace(1, "  --> [0x%04X, %s]\n", c, "LEFT");
#else
						c = 'h';	/* vi LEFT */
						Trace(1, "  --> [0x%04X, %s]\n", c, "h");
#endif
						break;
					case 'C':
					case 'c':
#ifdef KEY_RIGHT
						c = KEY_RIGHT;
						Trace(1, "  --> [0x%04X, %s]\n", c, "RIGHT");
#else
						c = 'l';	/* vi RIGHT */
						Trace(1, "  --> [0x%04X, %s]\n", c, "l");
#endif
						break;
				}
				goto gotch;
		}
	}
gotch:
	return (c);
}	/* HostWinGetKey */



static
void NewHilitedHostIndex(int newIdx)
{
	int oldIdx, lastLine;

	if (gNumBookmarks <= 0) {
		HostWinMsg(
"No bookmarks in the list.  Try a /new, or open a site manually to add one.");
	} else {
		oldIdx = gHilitedHost;
		if (gNumBookmarks < gHostListPageSize)
			lastLine = gHostListWinStart + gNumBookmarks - 1;
		else
			lastLine = gHostListWinStart + gHostListPageSize - 1;
		if (newIdx < gHostListWinStart) {
			/* Will need to scroll the window up. */
			if (newIdx < 0) {
				newIdx = 0;
				if (oldIdx == newIdx)
					HostWinMsg("You are at the top of the list.");
			}
			gHilitedHost = gHostListWinStart = newIdx;
		} else if (newIdx > lastLine) {
			/* Will need to scroll the window down. */
			if (newIdx > (gNumBookmarks - 1)) {
				newIdx = gNumBookmarks - 1;
				if (oldIdx == newIdx)
					HostWinMsg("You are at the bottom of the list.");
			}
			gHilitedHost = newIdx;
			gHostListWinStart = newIdx - (gHostListPageSize - 1);
			if (gHostListWinStart < 0)
				gHostListWinStart = 0;
		} else {
			/* Don't need to scroll window, just move pointer. */
			gHilitedHost = newIdx;
		}
		gCurHostListItem = &gBookmarkTable[gHilitedHost];
		if (oldIdx != newIdx) {
			DrawHostList();
		}
	}
}	/* NewHilitedHostIndex */




/* You can zip to a different area of the list without using the arrow
 * or page scrolling keys.  Just type a letter, and the list will scroll
 * to the first host starting with that letter.
 */
void HostWinZoomTo(int c)
{	
	int i, j;

	if (gNumBookmarks > 0) {
		if (islower(c))
			c = toupper(c);
		for (i=0; i<gNumBookmarks - 1; i++) {
			j = gBookmarkTable[i].bookmarkName[0];
			if (islower(j))
				j = toupper(j);
			if (j >= c)
				break;
		}
		NewHilitedHostIndex(i);
	} else {
		HostWinMsg("No bookmarks to select.  Try a /new.");
	}
	DrawHostList();
}	/* HostWinZoomTo */





void HostListLineUp(void)
{
	NewHilitedHostIndex(gHilitedHost - 1);
}	/* HostListLineUp */





void HostListLineDown(void)
{
	NewHilitedHostIndex(gHilitedHost + 1);
}	/* HostListLineDown */




void HostListPageUp(void)
{
	NewHilitedHostIndex(gHilitedHost - gHostListPageSize);
}	/* HostListPageUp */




void HostListPageDown(void)
{
	NewHilitedHostIndex(gHilitedHost + gHostListPageSize);
}	/* HostListPageDown */



/* This marks the start of a section that belongs to the Bookmark Options
 * window.  This window pops up on top of the host editor's main window
 * when you wish to edit a site's settings.  When the user finishes,
 * we close it and the host editor resumes.
 */

/* This displays a message in the Bookmark Options window. */
void EditHostWinMsg(const char *msg)
{
	int maxy, maxx;

	getmaxyx(gEditHostWin, maxy, maxx);
	mvwaddstr(gEditHostWin, maxy - 2, 0, msg);
	wclrtoeol(gEditHostWin);
	wmove(gEditHostWin, maxy - 1, 0);
	wrefresh(gEditHostWin);
}	/* EditHostWinMsg */




/* Prompts for a line of input. */
void EditHostWinGetStr(char *dst, size_t size, int canBeEmpty, int canEcho)
{
	char str[256];
	WGetsParams wgp;
	int maxy, maxx;

	WAttr(gEditHostWin, kBold, 1);
	getmaxyx(gEditHostWin, maxy, maxx);
	mvwaddstr(gEditHostWin, maxy - 1, 0, "> ");
	WAttr(gEditHostWin, kBold, 0);
	wclrtoeol(gEditHostWin);
	wrefresh(gEditHostWin);
	curs_set(1);

	wgp.w = gEditHostWin;
	wgp.sy = maxy - 1;
	wgp.sx = 2;
	wgp.fieldLen = maxx - 3;
	wgp.dst = str;
	wgp.dstSize = size;
	wgp.useCurrentContents = 0;
	wgp.echoMode = canEcho ? wg_RegularEcho : wg_BulletEcho;
	wgp.history = wg_NoHistory;
	(void) wg_Gets(&wgp);
	cbreak();						/* wg_Gets turns off cbreak and delay. */

	/* See if the user just hit return.  We may not want to overwrite
	 * the dst here, which would make it an empty string.
	 */
	if ((wgp.changed) || (canBeEmpty == kOkayIfEmpty))
		strcpy(dst, str);

	wmove(gEditHostWin, maxy - 1, 0);
	wclrtoeol(gEditHostWin);
	wrefresh(gEditHostWin);
	curs_set(0);
}	/* EditHostWinGetStr */





/* Prompts for an integer of input. */
void EditHostWinGetNum(int *dst)
{
	WGetsParams wgp;
	char str[256];
	int maxy, maxx;

	getmaxyx(gEditHostWin, maxy, maxx);
	WAttr(gEditHostWin, kBold, 1);
	mvwaddstr(gEditHostWin, maxy - 1, 0, "> ");
	WAttr(gEditHostWin, kBold, 0);
	wclrtoeol(gEditHostWin);
	wrefresh(gEditHostWin);
	curs_set(1);

	wgp.w = gEditHostWin;
	wgp.sy = maxy - 1;
	wgp.sx = 2;
	wgp.fieldLen = maxx - 3;
	wgp.dst = str;
	wgp.dstSize = sizeof(str);
	wgp.useCurrentContents = 0;
	wgp.echoMode = wg_RegularEcho;
	wgp.history = wg_NoHistory;
	(void) wg_Gets(&wgp);
	cbreak();						/* wg_Gets turns off cbreak and delay. */

	AtoIMaybe(dst, str);
	wmove(gEditHostWin, maxy - 1, 0);
	wclrtoeol(gEditHostWin);
	wrefresh(gEditHostWin);
	curs_set(0);
}	/* EditHostWinGetNum */




/* This is the meat of the site options window.  We can selectively update
 * portions of the window by using a bitmask with bits set for items
 * we want to update.
 */
void EditHostWinDraw(int flags, int hilite)
{
	int maxy, maxx;
	int i, f;
	char str[256];
	char spec[32];
	const char *cp;

	/* Draw the keys the user can type in reverse text. */
	WAttr(gEditHostWin, kReverse, 1);
	f = 5;
	for (i = kFirstEditWindowItem; i <= kLastEditWindowItem; i++) {
		if (TESTBIT(flags, i))
			mvwaddch(gEditHostWin, f + i, 2, 'A' + i);
	}
	
	/* The "quit" item is a special item that is offset a line, and
	 * always has the "X" key assigned to it.
	 */
	i = kQuitEditWindowItem;
	if (TESTBIT(flags, i))
		mvwaddch(gEditHostWin, 1 + f + i, 2, 'X');
	WAttr(gEditHostWin, kReverse, 0);
	
	/* We can use this to hilite a whole line, to indicate to the
	 * user that a certain item is being edited.
	 */
	if (hilite)
		WAttr(gEditHostWin, kReverse, 1);
	getmaxyx(gEditHostWin, maxy, maxx);
	sprintf(spec, " %%-26s%%-%ds",
		maxx - 32);

	/* Now draw the items on a case-by-case basis. */
	if (TESTBIT(flags, kNicknameEditWindowItem)) {
		mvwprintw(gEditHostWin, kNicknameEditWindowItem + f, 3, spec,
			"Bookmark name:",
			gEditRsi.bookmarkName
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kHostnameEditWindowItem)) {
		mvwprintw(gEditHostWin, kHostnameEditWindowItem + f, 3, spec,
			"Hostname:",
			gEditRsi.name
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kUserEditWindowItem)) {
		mvwprintw(gEditHostWin, kUserEditWindowItem + f, 3, spec,
			"User:",
			gEditRsi.user[0] == '\0' ? "anonymous" : gEditRsi.user
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kPassEditWindowItem)) {
		if (gEditRsi.pass[0] == '\0' && gEditRsi.user[0] == '\0')
			STRNCPY(str, gLib.defaultAnonPassword);
		mvwprintw(gEditHostWin, kPassEditWindowItem + f, 3, spec,
			"Password:",
			strcmp(str, gLib.defaultAnonPassword) ? "********" : str
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kAcctEditWindowItem)) {
		mvwprintw(gEditHostWin, kAcctEditWindowItem + f, 3, spec,
			"Account:",
			gEditRsi.acct[0] == '\0' ? "none" : gEditRsi.acct
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kDirEditWindowItem)) {
		if (gEditRsi.dir[0] == '\0')
			STRNCPY(str, "/");
		else
			AbbrevStr(str, gEditRsi.dir, (size_t) maxx - 32, 0);
		mvwprintw(gEditHostWin, kDirEditWindowItem + f, 3, spec,
			"Remote Directory:",
			str
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kLDirEditWindowItem)) {
		if (gEditRsi.ldir[0] == '\0')
			STRNCPY(str, "(current)");
		else
			AbbrevStr(str, gEditRsi.ldir, (size_t) maxx - 32, 0);
		mvwprintw(gEditHostWin, kLDirEditWindowItem + f, 3, spec,
			"Local Directory:",
			str
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kXferTypeEditWindowItem)) {
		if ((gEditRsi.xferType == 'I') || (gEditRsi.xferType == 'B'))
			cp = "Binary";
		else if (gEditRsi.xferType == 'A')
			cp = "ASCII Text";
		else
			cp = "Tenex";
		mvwprintw(gEditHostWin, kXferTypeEditWindowItem + f, 3, spec,
			"Transfer type:",
			cp
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kPortEditWindowItem)) {
		sprintf(str, "%u", (gEditRsi.port == 0) ? 21 : (unsigned int) gEditRsi.port);
		mvwprintw(gEditHostWin, kPortEditWindowItem + f, 3, spec,
			"Port:",
			str
		);
		wclrtoeol(gEditHostWin);
	}
#if 0
	if (TESTBIT(flags, kSizeEditWindowItem)) {
		mvwprintw(gEditHostWin, kSizeEditWindowItem + f, 3, spec,
			"Has SIZE command:",
			gEditRsi.hasSIZE ? "Yes" : "No"
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kMdtmEditWindowItem)) {
		mvwprintw(gEditHostWin, kMdtmEditWindowItem + f, 3, spec,
			"Has MDTM command:",
			gEditRsi.hasMDTM ? "Yes" : "No"
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kPasvEditWindowItem)) {
		mvwprintw(gEditHostWin, kPasvEditWindowItem + f, 3, spec,
			"Can use passive FTP:",
			gEditRsi.hasPASV ? "Yes" : "No"
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kOSEditWindowItem)) {
		mvwprintw(gEditHostWin, kOSEditWindowItem + f, 3, spec,
			"Operating System:",
			(gEditRsi.isUnix == 1) ? "UNIX" : "Non-UNIX"
		);
		wclrtoeol(gEditHostWin);
	} 
#endif
	if (TESTBIT(flags, kCommentEditWindowItem)) {
		if (gEditRsi.comment[0] == '\0')
			STRNCPY(str, "(none)");
		else
			AbbrevStr(str, gEditRsi.comment, (size_t) maxx - 32, 0);
		mvwprintw(gEditHostWin, kCommentEditWindowItem + f, 3, spec,
			"Comment:",
			str
		);
		wclrtoeol(gEditHostWin);
	}
	if (TESTBIT(flags, kQuitEditWindowItem)) {
		mvwprintw(gEditHostWin, kQuitEditWindowItem + f + 1, 3, spec,
			"(Done editing)",
			""
		);
		wclrtoeol(gEditHostWin);
	}

	if (hilite)
		WAttr(gEditHostWin, kReverse, 0);

	wmove(gEditHostWin, maxy - 1, 0);
	wrefresh(gEditHostWin);
}	/* EditHostWinDraw */



/* The user can hit space to change the transfer type.  For these toggle
 * functions we do an update each time so the user can see the change
 * immediately.
 */
void ToggleXferType(void)
{
	int c;

	for (;;) {
		c = wgetch(gEditHostWin);
		if ((c == 'x') || (c == 10) || (c == 13)
#ifdef KEY_ENTER
			|| (c == KEY_ENTER)
#endif
			)
			break;
		else if (isspace(c)) {
			if (gEditRsi.xferType == 'A')
				gEditRsi.xferType = 'I';
			else if ((gEditRsi.xferType == 'B') || (gEditRsi.xferType == 'I'))
				gEditRsi.xferType = 'T';
			else
				gEditRsi.xferType = 'A';
			EditHostWinDraw(BIT(kXferTypeEditWindowItem), kHilite);
		}
	}
}	/* ToggleXferType */




void EditWinToggle(int *val, int bitNum, int min, int max)
{
	int c;

	for (;;) {
		c = wgetch(gEditHostWin);
		if ((c == 'x') || (c == 10) || (c == 13)
#ifdef KEY_ENTER
			|| (c == KEY_ENTER)
#endif
			)
			break;
		else if (isspace(c)) {
			*val = *val + 1;
			if (*val > max)
				*val = min;
			EditHostWinDraw(BIT(bitNum), kHilite);
		}
	}
}	/* EditWinToggle */




static void
SaveAndReload(void)
{
	SaveBookmarkTable();
	if (LoadBookmarkTable() < 0) {
		fprintf(stderr, "Suddenly unable to re-load bookmarks.");
		Exit(1);
	}
}	/* SaveAndReload */



/* This opens and handles the site options window. */
void HostWinEdit(void)
{
	int c, field;
	int needUpdate;
	char bmname[128];
	BookmarkPtr rsip;

	if (gCurHostListItem != NULL) {
		gEditHostWin = newwin(LINES, COLS, 0, 0);
		if (gEditHostWin == NULL)
			return;
	
		STRNCPY(bmname, gCurHostListItem->bookmarkName);
		
		/* Set the clear flag for the first update. */
		wclear(gEditHostWin);

		/* leaveok(gEditHostWin, TRUE);	* Not sure if I like this... */
		WAttr(gEditHostWin, kBold, 1);
		WAddCenteredStr(gEditHostWin, 0, "Bookmark Options");
		WAttr(gEditHostWin, kBold, 0);
		
		/* We'll be editing a copy of the current host's settings. */
		gEditRsi = *gCurHostListItem;

		EditHostWinDraw(kAllWindowItems, kNoHilite);
		field = 1;
		for (;;) {
			EditHostWinMsg("Select an item to edit by typing its corresponding letter.");
			c = wgetch(gEditHostWin);
			if (islower(c))
				c = toupper(c);
			if (!isupper(c))
				continue;
			if (c == 'X')
				break;
			field = c - 'A';
			needUpdate = 1;
			
			/* Hilite the current item to edit. */
			EditHostWinDraw(BIT(field), kHilite);
			switch(field) {
				case kNicknameEditWindowItem:
					EditHostWinMsg("Type a new bookmark name, or hit <RETURN> to continue.");
					EditHostWinGetStr(gEditRsi.bookmarkName, sizeof(gEditRsi.bookmarkName), kNotOkayIfEmpty, kGetAndEcho);
					break;
					
				case kHostnameEditWindowItem:
					EditHostWinMsg("Type a new hostname, or hit <RETURN> to continue.");
					EditHostWinGetStr(gEditRsi.name, sizeof(gEditRsi.name), kNotOkayIfEmpty, kGetAndEcho);
					gEditRsi.lastIP[0] = '\0';	/* In case it changed. */
					break;

				case kUserEditWindowItem:
					EditHostWinMsg("Type a username, or hit <RETURN> to signify anonymous.");
					EditHostWinGetStr(gEditRsi.user, sizeof(gEditRsi.user), kOkayIfEmpty, kGetAndEcho);
					break;

				case kPassEditWindowItem:
					EditHostWinMsg("Type a password, or hit <RETURN> if no password is required.");
					EditHostWinGetStr(gEditRsi.pass, sizeof(gEditRsi.pass), kOkayIfEmpty, kGetNoEcho);
					break;

				case kAcctEditWindowItem:
					EditHostWinMsg("Type an account name, or hit <RETURN> if no account is required.");
					EditHostWinGetStr(gEditRsi.acct, sizeof(gEditRsi.acct), kOkayIfEmpty, kGetAndEcho);
					break;

				case kDirEditWindowItem:
					EditHostWinMsg("Type a remote directory path to start in after a connection is established.");
					EditHostWinGetStr(gEditRsi.dir, sizeof(gEditRsi.dir), kOkayIfEmpty, kGetAndEcho);
					break;

				case kLDirEditWindowItem:
					EditHostWinMsg("Type a local directory path to start in after a connection is established.");
					EditHostWinGetStr(gEditRsi.ldir, sizeof(gEditRsi.ldir), kOkayIfEmpty, kGetAndEcho);
					break;

				case kXferTypeEditWindowItem:
					EditHostWinMsg(kToggleMsg);
					ToggleXferType();
					break;

				case kPortEditWindowItem:
					EditHostWinMsg("Type a port number to use for FTP.");
					EditHostWinGetNum((int *) &gEditRsi.port);
					break;

#if 0
				case kSizeEditWindowItem:
					EditHostWinMsg(kToggleMsg);
					EditWinToggle(&gEditRsi.hasSIZE, field, 0, 1);
					break;

				case kMdtmEditWindowItem:
					EditHostWinMsg(kToggleMsg);
					EditWinToggle(&gEditRsi.hasMDTM, field, 0, 1);
					break;

				case kPasvEditWindowItem:
					EditHostWinMsg(kToggleMsg);
					EditWinToggle(&gEditRsi.hasPASV, field, 0, 1);
					break;

				case kOSEditWindowItem:
					EditHostWinMsg(kToggleMsg);
					EditWinToggle(&gEditRsi.isUnix, field, 0, 1);
					break;
#endif

				case kCommentEditWindowItem:
					EditHostWinMsg("Enter a line of information to store about this site.");
					EditHostWinGetStr(gEditRsi.comment, sizeof(gEditRsi.comment), kOkayIfEmpty, kGetAndEcho);
					break;
				
				default:
					needUpdate = 0;
					break;
			}
			if (needUpdate)
				EditHostWinDraw(BIT(field), kNoHilite);
		}
		delwin(gEditHostWin);
		gEditHostWin = NULL;
		*gCurHostListItem = gEditRsi;

		SaveAndReload();
		/* Note:  newly reallocated array, modified gNumBookmarks */

		rsip = SearchBookmarkTable(bmname);
		if (rsip == NULL)
			rsip = &gBookmarkTable[0];
		gCurHostListItem = rsip;
		gHilitedHost = BMTINDEX(rsip);
		gHostListWinStart = BMTINDEX(rsip) - gHostListPageSize + 1;
		if (gHostListWinStart < 0)
			gHostListWinStart = 0;
		UpdateHostWindows(1);
	}
}	/* HostWinEdit */



/* Clones an existing site in the host list. */
void HostWinDup(void)
{
	BookmarkPtr rsip;
	char bmname[128];

	if (gCurHostListItem != NULL) {
		/* Use the extra slot in the array for the new one. */
		rsip = &gBookmarkTable[gNumBookmarks];
		*rsip = *gCurHostListItem;
		STRNCAT(rsip->bookmarkName, "-copy");
		STRNCPY(bmname, rsip->bookmarkName);
		gNumBookmarks++;
		SaveAndReload();
		/* Note:  newly reallocated array, modified gNumBookmarks */

		rsip = SearchBookmarkTable(bmname);
		if (rsip == NULL)
			rsip = &gBookmarkTable[0];
		gCurHostListItem = rsip;
		gHilitedHost = BMTINDEX(rsip);
		gHostListWinStart = BMTINDEX(rsip) - gHostListPageSize + 1;
		if (gHostListWinStart < 0)
			gHostListWinStart = 0;
		DrawHostList();
	} else {
		HostWinMsg("Nothing to duplicate.");
	}
	DrawHostList();
}	/* HostWinDup */




static void
DeleteBookmark(BookmarkPtr bmp)
{
	bmp->deleted = 1;
	SaveAndReload();
}	/* DeleteBookmark */




/* Removes a site from the host list. */
void HostWinDelete(void)
{
	BookmarkPtr toDelete;
	int newi;
	
	if (gCurHostListItem != NULL) {
		toDelete = gCurHostListItem;

		/* Need to choose a new active host after deletion. */
		if (gHilitedHost == gNumBookmarks - 1) {
			if (gNumBookmarks == 1) {
				newi = -1;	/* None left. */
			} else {
				/* At last one before delete. */
				newi = gHilitedHost - 1;
			}
		} else {
			/* Won't need to increment gHilitedHost here, since after deletion,
			 * the next one will move up into this slot.
			 */
			newi = gHilitedHost;
		}
		DeleteBookmark(toDelete);
		if (newi < 0) {
			gCurHostListItem = NULL;
		} else if (newi < gNumBookmarks) {
			gCurHostListItem = &gBookmarkTable[newi];
			gHilitedHost = newi;
		} else {
			newi = 0;
			gCurHostListItem = &gBookmarkTable[newi];
			gHilitedHost = newi;
		}
	} else
		HostWinMsg("Nothing to delete.");
	DrawHostList();
}	/* HostWinDelete */




/* Adds a new site to the host list, with default settings in place. */
void HostWinNew(void)
{
	BookmarkPtr rsip;

	/* Use the extra slot in the array for the new one. */
	rsip = &gBookmarkTable[gNumBookmarks];
	SetBookmarkDefaults(rsip);
	STRNCPY(rsip->bookmarkName, "(untitled)");
	STRNCPY(rsip->name, "(Use /ed to edit)");
	gNumBookmarks++;
	SaveAndReload();
	/* Note:  newly reallocated array, modified gNumBookmarks */

	rsip = &gBookmarkTable[0];
	gCurHostListItem = rsip;
	gHilitedHost = BMTINDEX(rsip);
	gHostListWinStart = BMTINDEX(rsip) - gHostListPageSize + 1;
	if (gHostListWinStart < 0)
		gHostListWinStart = 0;
	DrawHostList();
}	/* HostWinNew */




/* This displays a message in the host editor's main window.
 * Used mostly for error messages.
 */
void HostWinMsg(const char *msg)
{
	int maxy, maxx;

	getmaxyx(gHostWin, maxy, maxx);
	mvwaddstr(gHostWin, maxy - 2, 0, msg);
	wclrtoeol(gHostWin);
	wmove(gHostWin, maxy - 1, 0);
	wrefresh(gHostWin);
	BEEP(1);
	gNeedToClearMsg = 1;
}	/* HostWinMsg */




/* Prompts for a line of input. */
void HostWinGetStr(char *str, size_t size)
{
	WGetsParams wgp;
	int maxy, maxx;

	getmaxyx(gHostWin, maxy, maxx);
	mvwaddstr(gHostWin, maxy - 1, 0, "/");
	wclrtoeol(gHostWin);
	wrefresh(gHostWin);
	curs_set(1);
	wgp.w = gHostWin;
	wgp.sy = maxy - 1;
	wgp.sx = 1;
	wgp.fieldLen = maxx - 1;
	wgp.dst = str;
	wgp.dstSize = size;
	wgp.useCurrentContents = 0;
	wgp.echoMode = wg_RegularEcho;
	wgp.history = wg_NoHistory;
	(void) wg_Gets(&wgp);
	cbreak();						/* wg_Gets turns off cbreak and delay. */

	wmove(gHostWin, maxy - 1, 0);
	wclrtoeol(gHostWin);
	wrefresh(gHostWin);
	curs_set(0);
}	/* HostWinGetStr */




/*ARGSUSED*/
static void
SigIntHostWin(int UNUSED(sig))
{
	LIBNCFTP_USE_VAR(sig);
	alarm(0);
#ifdef HAVE_SIGSETJMP
	siglongjmp(gHostWinJmp, 1);
#else	/* HAVE_SIGSETJMP */
	longjmp(gHostWinJmp, 1);
#endif	/* HAVE_SIGSETJMP */
}	/* SigIntHostWin */



static void
WriteSelectedBMToFile(char *bookmarkName)
{
	FILE *fp;

	fp = fopen(gBookmarkSelectionFile, "w");
	if (fp == NULL)
		return;
	(void) fprintf(fp, "%s\n", bookmarkName);
	(void) fclose(fp);
}	/* WriteSelectedBMToFile */



static void
LaunchNcFTP(char *bookmarkName)
{
	char *av[8];

	EndWin();

	av[0] = (char *) "ncftp";
	av[1] = bookmarkName;
	av[2] = NULL;

#ifdef NCFTPPATH
	execv(NCFTPPATH, av);
#else
	execvp("ncftp", av);
#endif
}	/* LaunchNcFTP */





/* Runs the host editor.  Another big use for this is to open sites
 * that are in your host list.
 */
int HostWindow(void)
{
	int c;
	char cmd[256];
	volatile BookmarkPtr toOpen;
	vsigproc_t si;
	int maxy, maxx;
	int lmaxy, lmaxx;

	si = (sigproc_t) (-1);
	if (gWinInit) {
		gHostListWin = NULL;
		gHostWin = NULL;

		gHostWin = newwin(LINES, COLS, 0, 0);
		if (gHostWin == NULL)
			return (-1);

		curs_set(0);
		cbreak();
		
		/* Set the clear flag for the first update. */
		wclear(gHostWin);
		keypad(gHostWin, TRUE);		/* For arrow keys. */
#ifdef HAVE_NOTIMEOUT
		notimeout(gHostWin, TRUE);
#endif

#ifdef HAVE_SIGSETJMP
		if (sigsetjmp(gHostWinJmp, 1) == 0) {
#else	/* HAVE_SIGSETJMP */
		if (setjmp(gHostWinJmp) == 0) {
#endif	/* HAVE_SIGSETJMP */
			/* Gracefully cleanup the screen if the user ^C's. */
			si = NcSignal(SIGINT, SigIntHostWin);
			
			/* Initialize the page start and select a host to be
			 * the current one.
			 */
			gHostListWinStart = 0;
			gHilitedHost = 0;
			if (gNumBookmarks == 0)
				gCurHostListItem = NULL;
			else
				gCurHostListItem = &gBookmarkTable[gHilitedHost];
			
			/* Initially, we don't want to connect to any site in
			 * the host list.
			 */
			toOpen = NULL;
	
			getmaxyx(gHostWin, maxy, maxx);
			WAttr(gHostWin, kBold, 1);
			WAddCenteredStr(gHostWin, 0, "NcFTP Bookmark Editor");
			WAttr(gHostWin, kBold, 0);
			
			mvwaddstr(gHostWin, 3, 2, "Open selected site:       <enter>");
			mvwaddstr(gHostWin, 4, 2, "Edit selected site:       /ed");
			mvwaddstr(gHostWin, 5, 2, "Delete selected site:     /del");
			mvwaddstr(gHostWin, 6, 2, "Duplicate selected site:  /dup");
			mvwaddstr(gHostWin, 7, 2, "Add a new site:           /new");
			mvwaddstr(gHostWin, 9, 2, "Up one:                   <u>");
			mvwaddstr(gHostWin, 10, 2, "Down one:                 <d>");
			mvwaddstr(gHostWin, 11, 2, "Previous page:            <p>");
			mvwaddstr(gHostWin, 12, 2, "Next page:                <n>");
			mvwaddstr(gHostWin, 14, 2, "Capital letters selects first");
			mvwaddstr(gHostWin, 15, 2, "  site starting with the letter.");
			mvwaddstr(gHostWin, 17, 2, "Exit the bookmark editor: <x>");
		
			/* Initialize the scrolling host list window. */
			if (maxx < 110) {
				gHostListWinWide = 0;
				gHostListWin = subwin(
					gHostWin,
					LINES - 7,
					40,
					3,
					COLS - 40 - 2
				);
			} else {
				gHostListWinWide = COLS - 42;
				gHostListWin = subwin(
					gHostWin,
					LINES - 7,
					gHostListWinWide,
					3,
					38	
				);
			}

			if (gHostListWin == NULL)
				return (-1);
			getmaxyx(gHostListWin, lmaxy, lmaxx);
			gHostListPageSize = lmaxy;
			DrawHostList();
			wmove(gHostWin, maxy - 1, 0);
			UpdateHostWindows(1);

			for (;;) {
				c = HostWinGetKey();
				if (gNeedToClearMsg) {
					wmove(gHostWin, maxy - 2, 0);
					wclrtoeol(gHostWin);
					wrefresh(gHostWin);
				}
				if ((c >= 'A') && (c <= 'Z')) {
					/* isupper can coredump if wgetch returns a meta key. */
					HostWinZoomTo(c);
				} else if (c == '/') {
					/* Get an "extended" command.  Sort of like vi's
					 * :colon commands.
					 */
					HostWinGetStr(cmd, sizeof(cmd));
	
					if (ISTREQ(cmd, "ed"))
						HostWinEdit();
					else if (ISTREQ(cmd, "dup"))
						HostWinDup();
					else if (ISTREQ(cmd, "del"))
						HostWinDelete();
					else if (ISTREQ(cmd, "new"))
						HostWinNew();
					else
						HostWinMsg("Invalid bookmark editor command.");
				} else switch(c) {
					case 10:	/* ^J == newline */
						goto enter;
					case 13:	/* ^M == carriage return */
						goto enter;
#ifdef KEY_ENTER
					case KEY_ENTER:
						Trace(1, "  [0x%04X, %s]\n", c, "ENTER");
#endif
enter:
						if (gCurHostListItem == NULL)
							HostWinMsg("Nothing to open.  Try 'open sitename' from the main screen.");
						else {
							toOpen = (BookmarkPtr) gCurHostListItem;
							goto done;
						}
						break;
	
					case kControl_L:
						UpdateHostWindows(1);
						break;
	
					case 'u':
					case 'k':	/* vi up key */
					case 'h':	/* vi left key */
						HostListLineUp();
						break;
#ifdef KEY_UP
					case KEY_UP:
						Trace(1, "  [0x%04X, %s]\n", c, "UP");
						HostListLineUp();
						break;
#endif

#ifdef KEY_LEFT
					case KEY_LEFT:
						Trace(1, "  [0x%04X, %s]\n", c, "LEFT");
						HostListLineUp();
						break;
#endif
					
					case 'd':
					case 'j':	/* vi down key */
					case 'l':	/* vi right key */
						HostListLineDown();
						break;

#ifdef KEY_DOWN
					case KEY_DOWN:
						Trace(1, "  [0x%04X, %s]\n", c, "DOWN");
						HostListLineDown();
						break;
#endif

#ifdef KEY_RIGHT
					case KEY_RIGHT:
						Trace(1, "  [0x%04X, %s]\n", c, "RIGHT");
						HostListLineDown();
						break;
#endif
						
					case 'p':
						HostListPageUp();
						break;

#ifdef KEY_PPAGE
					case KEY_PPAGE:
						Trace(1, "  [0x%04X, %s]\n", c, "PPAGE");
						HostListPageUp();
						break;
#endif

					case 'n':
						HostListPageDown();
						break;

#ifdef KEY_NPAGE
					case KEY_NPAGE:
						Trace(1, "  [0x%04X, %s]\n", c, "NPAGE");
						HostListPageDown();
						break;
#endif

					case 'x':
					case 'q':
						goto done;
	
					default:
						HostWinMsg("Invalid key.");
						Trace(1, "  [0x%04X, %s]\n", c, "<invalid>");
						break;
				}
			}
		}
		NcSignal(SIGINT, (FTPSigProc) SIG_IGN);
done:
		if (gHostListWin != NULL)
			delwin(gHostListWin);
		if (gHostWin != NULL)
			delwin(gHostWin);
		gHostListWin = gHostWin = NULL;
		if (si != (sigproc_t) (-1))
			NcSignal(SIGINT, si);
		if (toOpen != (BookmarkPtr) 0) {
			/* If the user selected a site to open, connect to it now. */
			if (gStandAlone != 0) {
				LaunchNcFTP(toOpen->bookmarkName);
				/*NOTREACHED*/
				Exit(0);
			} else if (gBookmarkSelectionFile != NULL) {
				WriteSelectedBMToFile(toOpen->bookmarkName);
			}
			return (kNoErr);
		}
	}
	return (kNoErr);
}	/* HostWindow */




int
main(int argc, const char **argv)
{
	int result;
	int argi;

	gStandAlone = 1;
	gBookmarkSelectionFile = NULL;

	InitUserInfo();
	if (LoadBookmarkTable() < 0) {
		exit(7);
	}
	if (argc > 1) {
		/* The following hack is used by NcFTP
		 * to get the number of columns without
		 * having to link with curses/termcap.
		 * This simplifies things since the
		 * system may or may not have a good
		 * curses implementation, and we don't
		 * want to complicate NcFTP itself with
		 * that.
		 */
		argi = 1;
		if (strcmp(argv[1], "--dimensions") == 0) {
			result = PrintDimensions(0);
			exit((result == 0) ? 0 : 1);
		} else if (strcmp(argv[1], "--dimensions-terse") == 0) {
			result = PrintDimensions(1);
			exit((result == 0) ? 0 : 1);
		} else if (strcmp(argv[1], "--debug") == 0) {
			SetDebug(1);
			argi++;
		}
		/* Requested that we were run from ncftp. */
		gStandAlone = 0;
		if ((argc > argi) && (argv[argi][0] == '/'))
			gBookmarkSelectionFile = (const char *) argv[argi];
		if (gNumBookmarks < 1)
			exit(7);
	}

	result = FTPInitLibrary(&gLib);
	if (result < 0) {
		(void) fprintf(stderr, "ncftp: init library error %d (%s).\n", result, FTPStrError(result));
		exit(1);
	}

	result = FTPInitConnectionInfo(&gLib, &gConn, kDefaultFTPBufSize);
	if (result < 0) {
		(void) fprintf(stderr, "ncftp: init connection info error %d (%s).\n", result, FTPStrError(result));
		exit(1);
	}

	if (gDebug > 0)
		OpenTrace();
	InitPrefs();
	LoadFirewallPrefs(0);
	LoadPrefs();

	InitWindows();
	Trace(1, "Terminal size is %d columns by %d rows.\n", gScreenWidth, gScreenHeight);
	HostWindow();
	if (gDebug > 0)
		CloseTrace();
	Exit(0);
	/*NOTREACHED*/
	return 0;
}
