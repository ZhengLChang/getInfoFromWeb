#include "util.h"


void set_signal_handler(int sig,
		signalHandler handler)
{
	struct sigaction act;
	sigset_t empty_mask;
	memset(&act, 0, sizeof(act));
	sigemptyset(&empty_mask);
	act.sa_handler = handler;
	act.sa_mask = empty_mask;
	act.sa_flags = 0;
	sigaction(sig, &act, NULL);
	return;
}
void fd_close_on_exec(int fd) {
#ifdef FD_CLOEXEC
	if (fd < 0) return;
	assert(-1 != fcntl(fd, F_SETFD, FD_CLOEXEC));
#else
	UNUSED(fd);
#endif
}
