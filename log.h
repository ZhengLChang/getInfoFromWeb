#ifndef _LOG_H_
#define _LOG_H_

ssize_t write_all(int fd, const void* buf, size_t count);

/* Close fd and _try_ to get a /dev/null for it instead.
 * Returns 0 on success and -1 on failure (fd gets closed in all cases)
 */
int openDevNull(int fd);


int log_error_open();
int log_error_close();
int log_error_write(const char *filename, unsigned int line, const char *fmt, ...);

#endif
