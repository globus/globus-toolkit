#include "syshdrs.h"

#ifndef NO_SIGNALS
extern volatile Sjmp_buf gNetTimeoutJmp;
extern volatile Sjmp_buf gPipeJmp;
#endif

int
SClose(int sfd, int tlen)
{
#ifndef NO_SIGNALS
	vsio_sigproc_t sigalrm, sigpipe;

	if (SSetjmp(gNetTimeoutJmp) != 0) {
		alarm(0);
		(void) SSignal(SIGALRM, (sio_sigproc_t) sigalrm);
		(void) SSignal(SIGPIPE, (sio_sigproc_t) sigpipe);
		if (shutdown(sfd, 2) == 0)
			return (0);
		return (-1);
	}

	sigalrm = (vsio_sigproc_t) SSignal(SIGALRM, SIOHandler);
	sigpipe = (vsio_sigproc_t) SSignal(SIGPIPE, SIG_IGN);

	alarm((unsigned int) tlen);
	for (;;) {
		if (closesocket(sfd) == 0) {
			errno = 0;
			break;
		}
		if (errno != EINTR)
			break;
	} 
	alarm(0);

	if ((errno != 0) && (errno != EBADF)) {
		(void) shutdown(sfd, 2);
	}
	(void) SSignal(SIGALRM, (sio_sigproc_t) sigalrm);
	(void) SSignal(SIGPIPE, (sio_sigproc_t) sigpipe);

	return ((errno == 0) ? 0 : (-1));
#else
	return closesocket(sfd);
#endif
}	/* SClose */
