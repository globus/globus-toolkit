/* wgets.c */

#include "syshdrs.h"

/* The only reason we need to include this junk, is because on some systems
 * the function killchar() is actually a macro that uses definitions in
 * termios.h.  Example:  #define killchar()      (__baset.c_cc[VKILL])
 */

#ifdef HAVE_TERMIOS_H
#		include <termios.h>
#else
#	ifdef HAVE_TERMIO_H
#		include <termio.h>
#	else
#		ifdef HAVE_SYS_IOCTL_H
#			include <sys/ioctl.h>	/* For TIOxxxx constants. */
#		endif
#		include <sgtty.h>
#	endif
#endif /* !HAVE_TERMIOS_H */

#include "wgets.h"
#define MEMMOVE memmove

/* Pointer to current position in the buffer. */
static char *gBufPtr;

/* When we draw the display window in the buffer, this is the first
 * character to draw, at the far left.
 *
 * The "display window" is the current area being edited by the user.
 * For example, you specify that you can only use 10 screen columns to
 * input a string that can have a maximum size of 30 characters.
 *
 * Let's say the current buffer has "abcdefghijklmnopqrstuvw" in it.
 *     abcdefghijklmnopqrstuvw
 *          ^  ^     ^
 *          s  c     e
 *
 * The "display window" for this example would be "fghijklmno"
 * <s> (gWinStartPtr) points to "f" and <e> (gWinEndPtr) points to "o".
 * <c> (gBufPtr) points to the current character under the cursor, so
 * the letter "i" would be the hilited/blinking cursor.
 *
 * This display window allows you to set aside a certain amount of screen
 * area for editing, but allowing for longer input strings.  The display
 * window will scroll as needed.
 */
static char *gWinStartPtr = 0;

/* This would be the last character drawn in the display window. */
static char *gWinEndPtr = 0;

/* Number of characters in the buffer. */
static size_t gBufLen = 0;

/* If true, the display window needs to be redrawn. */
static int gNeedUpdate = 0;

/* The curses library window we are doing the editing in.  This window
 * is different from what I call the "display window."   The display
 * window is a subregion of the curses window, and does not have to have
 * a separate WINDOW pointer just for the editing.
 */
static WINDOW *gW = 0;

/* The column and row where the display window starts. */
static int gSy = 0, gSx = 0;

/* This is the buffer for the characters typed. */
static char *gDst = 0;

/* This is the length of the display window on screen.  It should <=
 * the size of the buffer itself.
 */
static int gWindowWidth = 0;

/* This is the size of the buffer. */
static size_t gDstSize = 0;

/* This flag tells whether we are allowed to use the contents of the buffer
 * passed by the caller, and whether the contents had length 1 or more.
 */
static int gHadStartingString = 0;

/* This is a flag to tell if the user did any editing.  If any characters
 * are added or deleted, this flag will be set.  If the user just used the
 * arrow keys to move around and/or just hit return, it will be false.
 */
static int gChanged = 0;

/* This is a flag to tell if we have moved at all on the line before
 * hitting return.  This is mostly used for ^D handling.  We want ^D to
 * return EOF if they hit right it away on a new line.
 */
static int gMoved = 0;

/* We have the flexibility with respect to echoing characters. We can just
 * echo the same character we read back to the screen like normal, always
 * echo "bullets," or not echo at all.
 */
static int gEchoMode = 0;

/* You can specify that the routine maintain a history buffer. If so, then
 * the user can use the arrow keys to move up and down through the history
 * to edit previous lines.
 */
static LineListPtr gHistory = 0;

/* This is a pointer to the line in the history that is being used as a copy
 * for editing.
 */
static LinePtr gCurHistLine = 0;

static void
wg_SetCursorPos(char *newPos)
{
	if (newPos > gWinEndPtr) {
		/* Shift window right.
		 * (Text will appear to shift to the left.)
		 */
		gWinStartPtr = newPos;
		if (gWindowWidth > 7)
			gWinStartPtr -= gWindowWidth * 2 / 10;
		else if (gWindowWidth > 1)
			gWinStartPtr -= 1;
		gBufPtr = newPos;
		gWinEndPtr = gWinStartPtr + gWindowWidth - 1;
	} else if (newPos < gWinStartPtr) {
		/* Shift window left.
		 * (Text will appear to shift to the right.)
		 */
		gWinStartPtr = newPos;
		if (gWindowWidth > 7)
			gWinStartPtr -= gWindowWidth * 2 / 10;
		else if (gWindowWidth > 1)
			gWinStartPtr -= 1;
		if (gWinStartPtr < gDst)
			gWinStartPtr = gDst;
		gBufPtr = newPos;
		gWinEndPtr = gWinStartPtr + gWindowWidth - 1;
	} else {
		/* Can just move cursor without shifting window. */
		gBufPtr = newPos;
	}
}	/* wg_SetCursorPos */




static void
wg_AddCh(int c)
{
	size_t n;
	char *limit;

	if (gBufLen < gDstSize) {
		limit = gDst + gBufLen;
		if (gBufPtr == limit) {
			/* Just add a character to the end.  No need to do
			 * a memory move for this.
			 */
			*gBufPtr = c;
			gBufLen++;
			wg_SetCursorPos(gBufPtr + 1);
		} else {
			/* Have to move characters after the cursor over one
			 * position so we can insert a character.
			 */
			n = limit - gBufPtr;
			MEMMOVE(gBufPtr + 1, gBufPtr, n);
			*gBufPtr = c;
			gBufLen++;
			wg_SetCursorPos(gBufPtr + 1);
		}
		gNeedUpdate = 1;
		gChanged = 1;
	} else {
		BEEP(1);
	}
}	/* wg_AddCh */




static void
wg_KillCh(int count)
{
	size_t n;
	char *limit;

	if (count > gBufPtr - gDst)
		count = (int) (gBufPtr - gDst);
	if (count) {
		limit = gDst + gBufLen;
		if (gBufPtr != limit) {
			/* Delete the characters before the character under the
			 * cursor, and move everything after it back one.
			 */
			n = limit - gBufPtr;
			memcpy(gBufPtr - count, gBufPtr, n);
		}
		gBufLen -= count;
		wg_SetCursorPos(gBufPtr - count);	/* Does a --gBufPtr. */
		gNeedUpdate = 1;
		gChanged = 1;
	} else {
		BEEP(1);
	}
}	/* wg_KillCh */

static int
IsWordChar(char c)
{
	return ((!isspace((int) c)) && (c != '/'));
}

static void
wg_KillWord(void)
{
	int count;
	int off = (int) (gBufPtr - gDst) - 1;
	count = off;

	/* Find the end of the previous word */
	while (off >= 0 && !IsWordChar(gDst[off]))
		off--;
	/* Find the start of the word */
	while (off >= 0 && IsWordChar(gDst[off]))
		off--;
	count = count - off;
	wg_KillCh(count);
}	/* wg_KillWord */


static void
wg_ForwardKillCh(void)
{
	size_t n;
	char *limit;

	if (gBufLen > 0) {
		limit = gDst + gBufLen;
		if (gBufPtr == limit) {
			/* Nothing in front to delete. */
			BEEP(1);
		} else {
			n = limit - gBufPtr - 1;
			memcpy(gBufPtr, gBufPtr + 1, n);
			--gBufLen;
			gNeedUpdate = 1;
			gChanged = 1;
		}
	} else {
		BEEP(1);
	}
}	/* wg_ForwardKillCh */



static void
wg_GoLeft(void)
{
	if (gBufPtr > gDst) {
		wg_SetCursorPos(gBufPtr - 1);	/* Does a --gBufPtr. */
		gNeedUpdate = 1;
		gMoved = 1;
	} else {
		BEEP(1);
	}
}	/* wg_GoLeft */




static void
wg_GoRight(void)
{
	if (gBufPtr < (gDst + gBufLen)) {
		wg_SetCursorPos(gBufPtr + 1);	/* Does a ++gBufPtr. */
		gNeedUpdate = 1;
		gMoved = 1;
	} else {
		BEEP(1);
	}
}	/* wg_GoRight */



static void
wg_GoLineStart(void)
{
	wg_SetCursorPos(gDst);
	gNeedUpdate = 1;
	gMoved = 1;
}	/* wg_GoLineStart */




static void
wg_GoLineEnd(void)
{
	wg_SetCursorPos(gDst + gBufLen);
	gNeedUpdate = 1;
	gMoved = 1;
}	/* wg_GoLineEnd */




static void
wg_LineKill(void)
{
	gBufPtr = gDst;
	gWinStartPtr = gBufPtr;
	gWinEndPtr = gWinStartPtr + gWindowWidth - 1;
	gBufPtr[gDstSize] = '\0';
	gBufLen = 0;
	gNeedUpdate = 1;

	/* Reset this so it acts as a new line.  We want them to be able to
	 * hit ^D until they do something with this line.
	 */
	gMoved = 0;

	/* We now have an empty string.  If we originally had something in the
	 * buffer, then mark it as changed since we just erased that.
	 */
	gChanged = gHadStartingString;
}	/* wg_LineKill */



static void
wg_HistoryUp(void)
{
	if (gHistory == wg_NoHistory) {
		/* Not using history. */
		BEEP(1);
		return;
	}

	if (gCurHistLine != NULL) {
		/* If not null, then the user had already scrolled up and was
		 * editing a line in the history.
		 */
		gCurHistLine = gCurHistLine->prev;
	} else {
		/* Was on original line to edit, but wants to go back one. */
		gCurHistLine = gHistory->last;
		if (gCurHistLine == NULL) {
			/* No lines at all in the history. */
			BEEP(1);
			return;
		}
	}

	wg_LineKill();
	if (gCurHistLine != NULL) {
		Strncpy(gDst, gCurHistLine->line, gDstSize);
		gBufLen = strlen(gDst);
		wg_GoLineEnd();
	}
	/* Otherwise, was on the first line in the history, but went "up" from here
	 * which wraps around to the bottom.  This last line is the new line
	 * to edit.
	 */
}	/* wg_HistoryUp */



static void
wg_HistoryDown(void)
{
	if (gHistory == wg_NoHistory) {
		/* Not using history. */
		BEEP(1);
		return;
	}

	if (gCurHistLine != NULL) {
		/* If not null, then the user had already scrolled up and was
		 * editing a line in the history.
		 */
		gCurHistLine = gCurHistLine->next;
	} else {
		/* Was on original line to edit, but wants to go down one.
		 * We'll wrap around and go to the very first line.
		 */
		gCurHistLine = gHistory->first;
		if (gCurHistLine == NULL) {
			/* No lines at all in the history. */
			BEEP(1);
			return;
		}
	}
	
	wg_LineKill();
	if (gCurHistLine != NULL) {
		Strncpy(gDst, gCurHistLine->line, gDstSize);
		gBufLen = strlen(gDst);
		wg_GoLineEnd();
	}
	/* Otherwise, was on the last line in the history, but went down from here
	 * which means we should resume editing a fresh line.
	 */
}	/* wg_HistoryDown */




static void
wg_Update(void)
{
	char *lastCharPtr;
	char *cp;

	wmove(gW, gSy, gSx);
	lastCharPtr = gDst + gBufLen;
	*lastCharPtr = '\0';
	if (gEchoMode == wg_RegularEcho) {
		for (cp = gWinStartPtr; cp < lastCharPtr; cp++) {
			if (cp > gWinEndPtr)
				goto xx;
			waddch(gW, (unsigned char) *cp);
		}
	} else if (gEchoMode == wg_BulletEcho) {
		for (cp = gWinStartPtr; cp < lastCharPtr; cp++) {
			if (cp > gWinEndPtr)
				goto xx;
			waddch(gW, wg_Bullet);
		}
	} else /* if (gEchoMode == wg_NoEcho) */ {
		for (cp = gWinStartPtr; cp < lastCharPtr; cp++) {
			if (cp > gWinEndPtr)
				goto xx;
			waddch(gW, ' ');
		}
	}

	/* Rest of display window is empty, so write out spaces. */
	for ( ; cp <= gWinEndPtr; cp++)
		waddch(gW, ' ');
xx:
	wmove(gW, gSy, gSx + (int) (gBufPtr - gWinStartPtr));
	wrefresh(gW);
	gNeedUpdate = 0;
} /* wg_Update */




int
wg_Gets(WGetsParamPtr wgpp)
{
	int c, result;
	int lineKill;
	int maxx, maxy;
#ifdef WG_DEBUG
	FILE *trace;
#endif

	/* Sanity checks. */
	if (wgpp == NULL)
		return (wg_BadParamBlock);

	if (wgpp->dstSize < 2)
		return (wg_DstSizeTooSmall);
	gDstSize = wgpp->dstSize - 1;	/* Leave room for nul. */
	
	if (wgpp->fieldLen < 1)
		return (wg_WindowTooSmall);
	gWindowWidth = wgpp->fieldLen;

	if (wgpp->w == NULL)
		return (wg_BadCursesWINDOW);
	gW = wgpp->w;

	getmaxyx(gW, maxy, maxx);
	if ((wgpp->sy < 0) || (wgpp->sy > maxy))
		return (wg_BadCoordinates);
	gSy = wgpp->sy;

	if ((wgpp->sx < 0) || (wgpp->sx > maxx))
		return (wg_BadCoordinates);
	gSx = wgpp->sx;

	if (wgpp->dst == NULL)
		return (wg_BadBufferPointer);
	gDst = wgpp->dst;

	gHistory = wgpp->history;	/* Will be NULL if not using history. */
	gCurHistLine = NULL;		/* Means we haven't scrolled into history. */

	gEchoMode = wgpp->echoMode;
	gChanged = 0;
	gMoved = 0;
	
	result = 0;
	wmove(gW, gSy, gSx);
	wrefresh(gW);

#ifdef WG_DEBUG
	trace = fopen(wg_TraceFileName, FOPEN_APPEND_TEXT);
	if (trace != NULL) {
		fprintf(trace, "<START>\n");
	}
#endif

	cbreak();
	/* Should already have echo turned off. */
	/* noecho(); */
	nodelay(gW, FALSE);
	keypad(gW, TRUE);
#ifdef HAVE_NOTIMEOUT
	notimeout(gW, TRUE);
#endif

	lineKill = (int) killchar();

	gNeedUpdate = 1;
	gBufPtr = gDst;
	gWinStartPtr = gBufPtr;
	gWinEndPtr = gWinStartPtr + gWindowWidth - 1;
	gBufPtr[gDstSize] = '\0';
	gHadStartingString = 0;
	if (wgpp->useCurrentContents) {
		gBufLen = strlen(gBufPtr);
		if (gBufLen > 0)
			gHadStartingString = 1;
	} else {
		gBufLen = 0;
	}

	for (;;) {
		if (gNeedUpdate) 
			wg_Update();

		c = wgetch(gW);
#ifdef WG_DEBUG
		if (trace != NULL) {
			switch (c) {
				case '\r': fprintf(trace, "(\\r)\n"); break;
				case '\n': fprintf(trace, "(\\n)\n"); break;
#ifdef KEY_ENTER
				case KEY_ENTER: fprintf(trace, "(KEY_ENTER)\n"); break;
#endif
				default: fprintf(trace, "[%c] = 0x%X\n", c, c);
			}
		}
#endif
		switch (c) {
			case '\r':
			case '\n':
#ifdef KEY_ENTER
			case KEY_ENTER:
#endif
				goto done;			

			case '\b':
#ifdef KEY_BACKSPACE
			case KEY_BACKSPACE:
#endif
			case 0x7f:
				wg_KillCh(1);
				break;

#ifdef KEY_FWDDEL		/* Need to find a real symbol for forward delete. */
			case KEY_FWDDEL:
				wg_ForwardKillCh();
				break;
#endif

#ifdef KEY_EXIT
			case KEY_EXIT:
#endif
#ifdef KEY_CLOSE
			case KEY_CLOSE:
#endif
#ifdef KEY_CANCEL
			case KEY_CANCEL:
#endif
			case 0x04:		/* Control-D */
				/* If we haven't changed the buffer, and the cursor has
				 * not moved from the first position, return EOF.
				 */
				if (!gChanged && !gMoved) {
					result = wg_EOF;
					goto done;
				}
				/*FALLTHROUGH*/
#ifdef KEY_DC
			case KEY_DC:
#endif
				if (gBufPtr == gDst + gBufLen) {
#if 0
					wg_AddCh('*'); wg_Update();
					CompleteOptions(gDst, gBufPtr-gDst-1);
					wg_KillCh(1);
#endif
				} else {
					wg_ForwardKillCh();		/* Emacs ^D */
				}
				break;

#ifdef KEY_CLEAR
			case KEY_CLEAR:
#endif
			case 0x0C:		/* Control-L */
				touchwin(curscr);
				wrefresh(curscr);
				break;

#ifdef KEY_LEFT
			case KEY_LEFT:
#endif
			case 0x02:		/* Control-F */
				wg_GoLeft();
				break;

#ifdef KEY_RIGHT
			case KEY_RIGHT:
#endif
			case 0x06:		/* Control-B */
				wg_GoRight();
				break;

#ifdef KEY_UP
			case KEY_UP:
#endif
			case 0x10:		/* Control-P */
				wg_HistoryUp();
				break;

#ifdef KEY_DOWN
			case KEY_DOWN:
#endif
			case 0x0E:		/* Control-N */
				wg_HistoryDown();
				break;

#ifdef KEY_HOME
			case KEY_HOME:
#endif
			case 0x01:		/* Control-A */
				wg_GoLineStart();
				break;
#ifdef KEY_END
			case KEY_END:
#endif
			case 0x05:		/* Control-E */
				wg_GoLineEnd();
				break;
#ifdef KEY_EOL
			case KEY_EOL:
#endif
			case 0x0B:
				while (gBufLen > 0 && gBufPtr < gDst + gBufLen)
					wg_ForwardKillCh();     /* Emacs ^K */
				break;

			case -1:
				/* This can happen if getch() was interrupted by a
				 * signal like ^Z.
				 */
				break;

			case 23:  /* ^W */
				wg_KillWord();
				break;

			case '\t': {
#if 0
				int i;
				char *comp;
				char *tmp;
				for (i=0;i<3;i++)
					wg_AddCh('.');
				wg_Update();
				comp = CompleteGet(gDst, gBufPtr-gDst-3);
				wg_KillCh(3);
				gDst[gBufLen] = '\0';
				if (comp) {
					for (tmp = comp; *tmp; tmp++)
						wg_AddCh(*tmp);
					free(comp);
				}
#endif
				break;
			}
				
			default:
				if (c < 0400) {
					if (c == lineKill)
						wg_LineKill();
					else
						wg_AddCh(c);
				}
		}
	}

done:
	nocbreak();

	gDst[gBufLen] = '\0';
	wgpp->changed = gChanged;
	wgpp->dstLen = (int) gBufLen;
	if ((gHistory != wg_NoHistory) && (gBufLen > 0))
		AddLine(wgpp->history, gDst);
	
#ifdef WG_DEBUG
		if (trace != NULL) {
			fprintf(trace, "<DONE>\n");
			fclose(trace);
		}
#endif
	return (result);
}	/* wg_Gets */

/* eof */
