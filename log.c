#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
# include <syslog.h>
#include "util.h"
#include "log.h"
#include "buffer.h"


#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

/* retry write on EINTR or when not all data was written */
ssize_t write_all(int fd, const void* buf, size_t count) {
	ssize_t written = 0;

	while (count > 0) {
		ssize_t r = write(fd, buf, count);
		if (r < 0) {
			switch (errno) {
			case EINTR:
				/* try again */
				break;
			default:
				/* fail - repeating probably won't help */
				return -1;
			}
		} else if (0 == r) {
			/* really shouldn't happen... */
			errno = EIO;
			return -1;
		} else {
			force_assert(r <= (ssize_t) count);
			written += r;
			buf = r + (char const*) buf;
			count -= r;
		}
	}

	return written;
}

/* Close fd and _try_ to get a /dev/null for it instead.
 * close() alone may trigger some bugs when a
 * process opens another file and gets fd = STDOUT_FILENO or STDERR_FILENO
 * and later tries to just print on stdout/stderr
 *
 * Returns 0 on success and -1 on failure (fd gets closed in all cases)
 */
int openDevNull(int fd) {
	int tmpfd;
	close(fd);
	tmpfd = open("/dev/null", O_RDWR);
	if (tmpfd != -1 && tmpfd != fd) {
		dup2(tmpfd, fd);
		close(tmpfd);
	}
	return (tmpfd != -1) ? 0 : -1;
}

/**
 * open the errorlog
 *
 * we have 4 possibilities:
 * - stderr (default)
 * - syslog
 * - logfile
 * - pipe
 *
 * if the open failed, report to the user and die
 *
 */

int log_error_open() {
	/* perhaps someone wants to use syslog() */
	openlog("Message", LOG_CONS | LOG_PID, LOG_DAEMON);
	return 0;
}

int log_error_close() {
	closelog();
	return 0;
}

/* lowercase: append space, uppercase: don't */
static void log_buffer_append_printf(buffer *out, const char *fmt, va_list ap) {
	for(; *fmt; fmt++) {
		int d;
		char *s;
		buffer *b;
		off_t o;

		switch(*fmt) {
		case 's':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string_c_escaped(out, s, (NULL != s) ? strlen(s) : 0);
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'b':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_c_escaped(out, CONST_BUF_LEN(b));
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'd':           /* int */
			d = va_arg(ap, int);
			buffer_append_int(out, d);
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'o':           /* off_t */
			o = va_arg(ap, off_t);
			buffer_append_int(out, o);
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'x':           /* int (hex) */
			d = va_arg(ap, int);
			buffer_append_string_len(out, CONST_STR_LEN("0x"));
			buffer_append_uint_hex(out, d);
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'S':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string_c_escaped(out, s, (NULL != s) ? strlen(s) : 0);
			break;
		case 'B':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_c_escaped(out, CONST_BUF_LEN(b));
			break;
		case 'D':           /* int */
			d = va_arg(ap, int);
			buffer_append_int(out, d);
			break;
		case 'O':           /* off_t */
			o = va_arg(ap, off_t);
			buffer_append_int(out, o);
			break;
		case 'X':           /* int (hex) */
			d = va_arg(ap, int);
			buffer_append_string_len(out, CONST_STR_LEN("0x"));
			buffer_append_uint_hex(out, d);
			break;
		case '(':
		case ')':
		case '<':
		case '>':
		case ',':
		case ' ':
			buffer_append_string_len(out, fmt, 1);
			break;
		}
	}
}

static void log_write(buffer *b) {
//	syslog(LOG_ERR, "%s", b->ptr);
	fprintf(stderr, "%s\n", b->ptr);
}

int log_error_write(const char *filename, unsigned int line, const char *fmt, ...) {
	va_list ap;
	buffer *error_buf = buffer_init();
	
	buffer_copy_string_len(error_buf, CONST_STR_LEN("("));
	buffer_append_string(error_buf, filename);
	buffer_append_string_len(error_buf, CONST_STR_LEN("."));
	buffer_append_int(error_buf, line);
	buffer_append_string_len(error_buf, CONST_STR_LEN(") "));

	va_start(ap, fmt);
	log_buffer_append_printf(error_buf, fmt, ap);
	va_end(ap);

	log_write(error_buf);
	buffer_free(error_buf);
	return 0;
}
