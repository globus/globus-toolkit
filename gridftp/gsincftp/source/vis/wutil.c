/* wutil.c */

#include "syshdrs.h"

#include "wutil.h"

int gWinInit = 0;
int gScreenWidth = 0;
int gScreenHeight = 0;

void
EndWin(void)
{
	if (gWinInit) {
		gWinInit = 0;

		/* Ideally we would save the whole screen of data before
		 * starting, and restore it here.
		 */
		clear();
		refresh();

		endwin();
	}
}	/* EndWin */




void
Exit(int exitStatus)
{
	EndWin();
	exit(exitStatus);
}	/* Exit */




#ifdef NOT_USED_YET

void
SaveScreen(void)
{
	if (gWinInit) {
		/* Clearing the screen is necessary
		 * because ncurses doesn't move the
		 * cursor to the bottom left.
		 *
		 * This also causes the restore
		 * operation to require that we paint
		 * all our windows by hand, because we
		 * have just left the screen blank so
		 * when refresh gets called in the
		 * restore it just returns the screen
		 * to blank.
		 *
		 * If it weren't for this screen clear,
		 * we would be able to get away with
		 * just doing an endwin(), the shell,
		 * and then a refresh() without us
		 * re-drawing any windows manually.
		 */
		clear();
		refresh();
 		endwin();
		fflush(stdout);
		fflush(stderr);
	}
}	/* SaveScreen */



void
TTYWaitForReturn(void)
{
	int tty;
	int junk;

	tty = open("/dev/tty", O_RDWR);
	if (tty != -1) {
		write(tty, "[Hit return]", 12);
		read(tty, &junk, 1);
		close(tty);
	}
}	/* TTYWaitForReturn */



void
RestoreScreen(int pressKey)
{
	if (gWinInit) {
		if (pressKey) {
#	if !defined(CURSES_SHELL_BUG) || (CURSES_SHELL_BUG == 0)
			TTYWaitForReturn();
#	else
			sleep(2);
#	endif
		}
		refresh();
/*		UpdateScreen(1); */
	}
}	/* RestoreScreen */



void
Beep(int on)
{
	static time_t lastBeepTime = 0;
	time_t now;

	time(&now);

	/* Don't flood the user with beeps. Once per two seconds is reasonable. */
	if ((on > 0) && ((int) (now - lastBeepTime) > 1)) {
		if (gWinInit)
			BEEP(1);
		else
		{
			fprintf(stderr, "\007");	/* ^G */
			fflush(stderr);
		}
	}
	lastBeepTime = now;
}	/* Beep */

#endif	/* NOT_USED_YET */



/* Sometimes ncurses' wclrtoeol() gets confused when reverse text was on.
 * This forces is to use space characters to blank out the line instead
 * of the tty's clear-to-end-of-line built-in, if present.
 */
void
swclrtoeol(WINDOW *w)
{
	int maxy, maxx;
	int cury, curx;

	getmaxyx(w, maxy, maxx);
	getyx(w, cury, curx);
	for ( ; curx < maxx; curx++)
		waddch(w, ' ');
}	/* swclrtoeol */




/* Many old curses libraries don't support wattron() and its attributes.
 * They should support wstandout() though.  This routine is an attempt
 * to use the best substitute available, depending on what the curses
 * library has.
 */
void
WAttr(WINDOW *w, int attr, int on)
{
	/* Define PLAIN_TEXT_ONLY if you have the attributes, but don't want
	 * to use them.
	 */
#ifndef PLAIN_TEXT_ONLY
#ifdef A_REVERSE
	if (attr & kReverse) {
		if (on)
			wattron(w, A_REVERSE);
		else
			wattroff(w, A_REVERSE);
	}
#else
	if (attr & kReverse) {
		if (on)
			wstandout(w);
		else
			wstandend(w);

		/* Nothing else will be done anyway, so just return now. */
		return;
	}
#endif	/* A_REVERSE */

#ifdef A_BOLD
	if (attr & kBold) {
		if (on)
			wattron(w, A_BOLD);
		else
			wattroff(w, A_BOLD);
	}
#else
	/* Do nothing.  Plain is best substitute. */
#endif	/* A_BOLD */

#ifdef A_UNDERLINE
	if (attr & kUnderline) {
		if (on)
			wattron(w, A_UNDERLINE);
		else
			wattroff(w, A_UNDERLINE);
	}
#else
	/* Try using standout mode in place of underline. */
	if (attr & kUnderline) {
		if (on)
			wstandout(w);
		else
			wstandend(w);

		/* Nothing else will be done anyway, so just return now. */
		return;
	}
#endif	/* A_UNDERLINE */

#ifdef A_DIM
	if (attr & kDim) {
		if (on)
			wattron(w, A_DIM);
		else
			wattroff(w, A_DIM);
	}
#else
	/* Do nothing.  Plain is best substitute. */
#endif	/* A_DIM */

#ifdef A_NORMAL
	if (attr == kNormal) {
		wattrset(w, A_NORMAL);
		return;
	}
#else
	/* At least make sure standout mode is off. */
	if (attr == kNormal) {
		wstandend(w);
		return;
	}
#endif	/* A_NORMAL */
#endif	/* PLAIN_TEXT_ONLY */
}	/* WAttr */




/* Draws a string centered in a window. */
void WAddCenteredStr(WINDOW *w, int y, const char *str)
{
	int x;
	int maxy, maxx;

	getmaxyx(w, maxy, maxx);
	x = (maxx - (int) strlen(str)) / 2;
	if (x < 0)
		x = 0;
	wmove(w, y, x);
	waddstr(w, str);
}	/* WAddCenteredStr */




static void
SigTerm(int UNUSED(sig))
{
	LIBNCFTP_USE_VAR(sig);
	Exit(1);
}	/* SigTerm */




#ifndef NCURSES_VERSION
#ifdef SIGTSTP
static void
SigTstp(int UNUSED(sig))
{
	LIBNCFTP_USE_VAR(sig);
	/* TO-DO */

	/* Ncurses is smart enough to handle this for us,
	 * but for those other curses libs, we should really
	 * suspend gracefully instead of exiting.
	 */
	Exit(1);
}	/* SigTstp */
#endif
#endif




int
InitWindows(void)
{
	int maxx = 0, maxy = 0;

	gWinInit = 0;
	initscr();
	if (stdscr == NULL)
		return (-1);
	gWinInit = 1;
	NcSignal(SIGTERM, SigTerm);

	nl();
	noecho();	/* Leave this off until we need it. */

	getmaxyx(stdscr, maxy, maxx);
	gScreenWidth = maxx;
	gScreenHeight = maxy;

#ifndef NCURSES_VERSION
#ifdef SIGTSTP
	if (NcSignal(SIGTSTP, (FTPSigProc) SIG_IGN) != (FTPSigProc) SIG_IGN) {
		NcSignal(SIGTSTP, SigTstp);
		NcSignal(SIGCONT, SigTstp);
	}
#endif
#endif

	return (0);
}	/* InitWindows */



int
PrintDimensions(int shortMode)
{
	int maxy = 0, maxx = 0;
	char buf[128];

	initscr();
	if (stdscr == NULL)
		return (-1);
	getmaxyx(stdscr, maxy, maxx);
	endwin();
	if ((maxx > 0) && (maxy > 0)) {
		memset(buf, 0, sizeof(buf));
#ifdef HAVE_SNPRINTF
		(void) snprintf(
			buf,
			sizeof(buf) - 1,
#else
		(void) sprintf(
			buf,
#endif
			(shortMode != 0) ? "%d %d\n" : "COLUMNS=%d\nLINES=%d\nexport COLUMNS\nexport LINES\n",
			maxx,
			maxy
		);
		(void) write(1, buf, strlen(buf));
		return (0);
	}
	return (-1);
}	/* PrintDimensions */
