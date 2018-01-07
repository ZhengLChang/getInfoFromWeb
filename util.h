#ifndef UTIL_H_
#define UTIL_H_
#include <signal.h>
#include <string.h>
#include <assert.h>
#define UNUSED(x) ( (void)(x) )
typedef void (* signalHandler) (int sig);
void set_signal_handler(int sig,
		signalHandler handler);
#endif
