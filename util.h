#ifndef UTIL_H_
#define UTIL_H_
#include <signal.h>
#include <string.h>
typedef void (* signalHandler) (int sig);
void set_signal_handler(int sig,
		signalHandler handler);
#endif
