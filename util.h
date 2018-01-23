#ifndef UTIL_H_
#define UTIL_H_
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
# include <openssl/md5.h>
#include <signal.h>
#include <stdbool.h>
#include "base64.h"

struct address_list;
#define UNUSED(x) ( (void)(x) )
/* The number of elements in an array.  For example:
   static char a[] = "foo";     -- countof(a) == 4 (note terminating \0)
   int a[5] = {1, 2};           -- countof(a) == 5
   char *a[] = {                -- countof(a) == 3
     "foo", "bar", "baz"
   }; */
#define countof(array) (sizeof (array) / sizeof ((array)[0]))
#define XDIGIT_TO_NUM(h) ((h) < 'A' ? (h) - '0' : c_toupper (h) - 'A' + 10)
#define X2DIGITS_TO_NUM(h1, h2) ((XDIGIT_TO_NUM (h1) << 4) + XDIGIT_TO_NUM (h2))
#define xzero(x) memset (&(x), '\0', sizeof (x))
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

typedef void (* signalHandler) (int sig);
void set_signal_handler(int sig,
		signalHandler handler);

#define xnew(type) (xmalloc (sizeof (type)))
#define xnew0(type) (xcalloc (1, sizeof (type)))
#define xnew_array(type, len) (xmalloc ((len) * sizeof (type)))
#define xnew_array0(type, len) (xcalloc ((len),  sizeof (type)))
#define alloca_array(type, size) ((type *) alloca ((size) * sizeof (type)))

#define NEXT_CHAR(c, p) do {                    \
  c = (unsigned char) *p++;                     \
} while (c_isspace (c))

#define IS_ASCII(c) (((c) & 0x80) == 0)

#define xfree(x) do{ \
	if((x)) \
	{ free((x));(x)=NULL;}\
}while(0)

#define xfree_null(p) if (!(p)) ; else xfree (p)

/* Generally useful if you want to avoid arbitrary size limits but
   don't need a full dynamic array.  Assumes that BASEVAR points to a
   malloced array of TYPE objects (or possibly a NULL pointer, if
   SIZEVAR is 0), with the total size stored in SIZEVAR.  This macro
   will realloc BASEVAR as necessary so that it can hold at least
   NEEDED_SIZE objects.  The reallocing is done by doubling, which
   ensures constant amortized time per element.  */

#define DO_REALLOC(basevar, sizevar, needed_size, type)	do {		\
  long DR_needed_size = (needed_size);					\
  long DR_newsize = 0;							\
  while ((sizevar) < (DR_needed_size)) {				\
    DR_newsize = sizevar << 1;						\
    if (DR_newsize < 16)						\
      DR_newsize = 16;							\
    (sizevar) = DR_newsize;						\
  }									\
  if (DR_newsize)							\
    basevar = xrealloc (basevar, DR_newsize * sizeof (type));		\
} while (0)

#define SKIP_WS(x) do {                         \
  while (isspace (*(x)))                        \
    ++(x);                                      \
} while (0)

#define CLOSE_FD(fd) do{ \
	if(fd >= 0) \
	{\
		close(fd);\
		fd=-1;	  \
	} \
}while(0)
#define APPEND(p, str) do {                     \
  int A_len = strlen (str);                     \
  memcpy (p, str, A_len);                       \
  p += A_len;                                   \
} while (0)
enum {
  WAIT_FOR_READ = 1,
  WAIT_FOR_WRITE = 2
};

typedef struct {
  /* Address family, one of AF_INET or AF_INET6. */
  int family;

  /* The actual data, in the form of struct in_addr or in6_addr: */
  union {
    struct in_addr d4;		/* IPv4 address */
    struct in6_addr d6;		/* IPv6 address */
  } data;
} ip_address;
void fd_close_on_exec(int fd);
void *xmemcpy(void *dest, size_t dest_len, void *src, size_t src_len);
void *xmalloc (size_t n);
void *xcalloc (size_t n, size_t s);
void *xrealloc (void *p, size_t n);
bool c_isxdigit (int c);
int c_toupper (int c);
int c_isspace (int c);
char *xstrdup(const char *s);
inline char *strpbrk_or_eos (const char *s, const char *accept);
char *strdupdelim (const char *beg, const char *end);
char *aprintf (const char *fmt, ...);
bool is_valid_ipv4_address (const char *str, const char *end);
bool is_valid_ipv6_address (const char *str, const char *end);
int select_fd (int fd, double maxtime, int wait_for);
bool is_fd_ready(int fd, double maxtime, int wait_for, int *error_code);
const char *file_len_terminator (const char *start, const char *peeked, int peeklen);
char *concat_strings (const char *str0, ...);
const char * get_error_string(int error_number);
struct error_data
{
	int error_num;
	const char *error_string;
};
enum {
	NO_ERROR = 0,
	ERROR_UNSUPPORTED_SCHEME,
	ERROR_MISSING_SCHEME,
	ERROR_INVALID_HOST_NAME,
	ERROR_BAD_PORT_NUMBER,
	ERROR_INVALID_USER_NAME,
	ERROR_UNTERMINATED_IPV6_ADDRESS,
	ERROR_INVALID_IPV4_ADDRESS,
	ERROR_IPV6_NOT_SUPPORTED,
	ERROR_INVALID_IPV6_ADDRESS,
	ERROR_BAD_URL,
	ERROR_NO_MEMORY,
	ERROR_HOST,
	ERROR_WRITE,
	ERROR_READ,
	ERROR_AUTHFAILED,
	ERROR_TIMEOUT,
	ERROR_CNT
};

extern struct error_data error_array[];

#endif
