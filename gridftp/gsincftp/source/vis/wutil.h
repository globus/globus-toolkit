/* wutil.h */
 
#define kNormal		00000
#define kStandout	00001
#define kUnderline	00002
#define kReverse	00004
#define kBlink		00010
#define kDim		00020
#define kBold		00040

void EndWin(void);
void Exit(int exitStatus);
void SaveScreen(void);
void TTYWaitForReturn(void);
void RestoreScreen(int pressKey);
void Beep(int on);
void WAttr(WINDOW *w, int attr, int on);
void swclrtoeol(WINDOW *w);
void WAddCenteredStr(WINDOW *w, int y, const char *str);
int PrintDimensions(int);
int InitWindows(void);
