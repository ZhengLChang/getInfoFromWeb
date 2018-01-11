#include "util.h"
struct error_data error_array[] =
{
	{NO_ERROR, "no error"},
	{ERROR_UNSUPPORTED_SCHEME, "Unsupported scheme"},
	{ERROR_MISSING_SCHEME, "Scheme missing"},
	{ERROR_INVALID_HOST_NAME, "Invalid host name"},
	{ERROR_BAD_PORT_NUMBER, "Invalid user name"},
	{ERROR_UNTERMINATED_IPV6_ADDRESS, "Unterminated IPv6 numeric address"},
	{ERROR_INVALID_IPV4_ADDRESS, "IPv6 addresses not supported"},
	{ERROR_INVALID_IPV6_ADDRESS, "Invalid IPv6 numeric address"},
	{ERROR_BAD_URL, "Invalid url"},
	{ERROR_NO_MEMORY, "No Enough Memory"},
	{ERROR_HOST, "Error Host"},
	{ERROR_WRITE, "Write to Host Error"},
	{ERROR_READ, "Read from Host Error"},
	{ERROR_AUTHFAILED, "Authentication Failed"},
	{ERROR_TIMEOUT, "Timeout"},
	{-1, NULL}
};
const char * get_error_string(int error_number)
{
	int i = 0;
	for(i = 0; error_array[i].error_num != -1; i++)
	{
		if(error_array[i].error_num != error_number)
		{
			continue;
		}
		return error_array[i].error_string;
	}
	return NULL;
}
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


void *xmemcpy(void *dest, size_t dest_len, void *src, size_t src_len)
{
	int min_len = MIN(dest_len, src_len);
	return memcpy(dest, src, min_len);
}

void *xmalloc (size_t n)
{
  void *p = malloc (n);
  if (!p && n != 0)
  {
	  fprintf(stderr, "%s %d error: %s", __func__, __LINE__, strerror(errno));
	  abort();
  }
  return p;
}

void *xcalloc (size_t n, size_t s)
{
  void *p;
  if (! (p = calloc (n, s)))
  {
	  fprintf(stderr, "%s %d error: %s", __func__, __LINE__, strerror(errno));
	  abort();
  }
  return p;
}
void *xrealloc (void *p, size_t n)
{
  p = realloc (p, n);
  if (!p && n != 0)
    abort ();
  return p;
}

bool c_isxdigit (int c)
{
  return ((c >= '0' && c <= '9')
          || ((c & ~0x20) >= 'A' && (c & ~0x20) <= 'F'));
}
int c_toupper (int c)
{
	return (c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c);
}
int c_isspace (int c)
{
  switch (c)
    {
    case ' ': case '\t': case '\n': case '\v': case '\f': case '\r':
      return 1;
    default:
      return 0;
    }
}

char *xstrdup(const char *s)
{
	char *new_s = xmalloc(strlen(s) + 1);
	memcpy(new_s, s, strlen(s) + 1);
	return new_s;
}

/* Like strpbrk, with the exception that it returns the pointer to the
 * terminating zero (end-of-string aka "eos") if no matching character
 * is found.  */

inline char * strpbrk_or_eos (const char *s, const char *accept)
{
	char *p = strpbrk (s, accept);
	if (!p)
		p = strchr (s, '\0');
      	return p;
}

/* Copy the string formed by two pointers (one on the beginning, other
   on the char after the last char) to a new, malloc-ed location.
   0-terminate it.  */
char *strdupdelim (const char *beg, const char *end)
{
	char *res = xmalloc (end - beg + 1);
	memcpy (res, beg, end - beg);
	res[end - beg] = '\0';
	return res;
}

char *aprintf (const char *fmt, ...)
{
  /* Use vasprintf. */
  int ret;
  va_list args;
  char *str;
  va_start (args, fmt);
  ret = vasprintf (&str, fmt, args);
  va_end (args);
  if (ret < 0 && errno == ENOMEM)
  {
	  abort();
  }
  else if (ret < 0)
    return NULL;
  return str;
}

bool is_valid_ipv4_address (const char *str, const char *end)
{
  bool saw_digit = false;
  int octets = 0;
  int val = 0;

  while (str < end)
    {
      int ch = *str++;

      if (ch >= '0' && ch <= '9')
        {
          val = val * 10 + (ch - '0');

          if (val > 255)
            return false;
          if (!saw_digit)
            {
              if (++octets > 4)
                return false;
              saw_digit = true;
            }
        }
      else if (ch == '.' && saw_digit)
        {
          if (octets == 4)
            return false;
          val = 0;
          saw_digit = false;
        }
      else
        return false;
    }
  if (octets < 4)
    return false;

  return true;
}

bool is_valid_ipv6_address (const char *str, const char *end)
{
	  /* Use lower-case for these to avoid clash with system headers.  */
	  enum {
		  ns_inaddrsz  = 4,
		  ns_in6addrsz = 16,
		  ns_int16sz   = 2
	  };

	  const char *curtok;
	  int tp;
	  const char *colonp;
	  bool saw_xdigit;
	  unsigned int val;

	  tp = 0;
	  colonp = NULL;

	  if (str == end)
		  return false;
	  /* Leading :: requires some special handling. */
		    if (*str == ':')
		    {
			    ++str;
			    if (str == end || *str != ':')
				    return false;
		    }

		    curtok = str;
    		    saw_xdigit = false;
  		    val = 0;

		    while (str < end)
		    {
			    int ch = *str++;
			    /* if ch is a number, add it to val. */
			    if (c_isxdigit (ch))
			    {
				    val <<= 4;
				    val |= XDIGIT_TO_NUM (ch);
				    if (val > 0xffff)
					    return false;
				    saw_xdigit = true;
				    continue;
			    }
			    /* if ch is a colon ... */
			    if (ch == ':')
			    {
				    curtok = str;
				    if (!saw_xdigit)
				    {
					    if (colonp != NULL)
						    return false;
					    colonp = str + tp;
					    continue;
				    }
				    else if (str == end)
					    return false;
				    if (tp > ns_in6addrsz - ns_int16sz)
					    return false;
				    tp += ns_int16sz;
				    saw_xdigit = false;
				    val = 0;
				    continue;
			    }
			    /* if ch is a dot ... */
			    if (ch == '.' && (tp <= ns_in6addrsz - ns_inaddrsz)
					    && is_valid_ipv4_address (curtok, end) == 1)
			    {
				    tp += ns_inaddrsz;
				    saw_xdigit = false;
				    break;
			    }
			    return false;
		    }
		    if (saw_xdigit)
		    {
			    if (tp > ns_in6addrsz - ns_int16sz)
				    return false;
			    tp += ns_int16sz;
		    }
		    if (colonp != NULL)
		    {
			    if (tp == ns_in6addrsz)
				    return false;
			    tp = ns_in6addrsz;
		    }
		    if (tp != ns_in6addrsz)
			    return false;
		    return true;
}

int select_fd (int fd, double maxtime, int wait_for)
{
  fd_set fdset;
  fd_set *rd = NULL, *wr = NULL;
  struct timeval tmout;
  int result;

  if (fd >= FD_SETSIZE)
    {
	  fprintf(stderr, "%s %d, Too many fds open.  Cannot use select on a fd >= %d", __func__, __LINE__, FD_SETSIZE);
      abort ();
    }
  FD_ZERO (&fdset);
  FD_SET (fd, &fdset);
  if (wait_for & WAIT_FOR_READ)
    rd = &fdset;
  if (wait_for & WAIT_FOR_WRITE)
    wr = &fdset;

  tmout.tv_sec = (long) maxtime;
  tmout.tv_usec = 1000000 * (maxtime - (long) maxtime);

  do
  {
    result = select (fd + 1, rd, wr, NULL, &tmout);
  }
  while (result < 0 && errno == EINTR);

  return result;
}

bool is_fd_ready(int fd, double maxtime, int wait_for, int *error_code)
{
	assert(error_code != NULL);

	if(maxtime > 0)
	{
		int ret;
		ret = select_fd (fd, maxtime, wait_for);
		if(ret == 0)
		{
			*error_code = ERROR_TIMEOUT;
		}
		if(ret <= 0)
		{
			return false;
		}
	}
	return true;
}
const char *file_len_terminator (const char *start, const char *peeked, int peeklen)
{
  const char *p, *end;

  p = peeked - start < 1 ? start : peeked - 1;
  end = peeked + peeklen;

  /* Check for \n\r\n or \n\n anywhere in [p, end-2). */
  for (; p < end - 1; p++)
    if (*p == '\n')
      {
          return p + 1;
      }
  return NULL;
}
/* Concatenate the NULL-terminated list of string arguments into
   freshly allocated space.  */

char *concat_strings (const char *str0, ...)
{
  va_list args;
  int saved_lengths[5];         /* inspired by Apache's apr_pstrcat */
  char *ret, *p;

  const char *next_str;
  int total_length = 0;
  size_t argcount;

  /* Calculate the length of and allocate the resulting string. */

  argcount = 0;
  va_start (args, str0);
  for(next_str = str0; next_str != NULL; next_str = va_arg (args, char *))
    {
      int len = strlen (next_str);
      if (argcount < countof (saved_lengths))
        saved_lengths[argcount++] = len;
      total_length += len;
    }
  va_end (args);
  p = ret = xmalloc (total_length + 1);

  /* Copy the strings into the allocated space. */

  argcount = 0;
  va_start (args, str0);
  for (next_str = str0; next_str != NULL; next_str = va_arg (args, char *))
    {
      int len;
      if (argcount < countof (saved_lengths))
        len = saved_lengths[argcount++];
      else
        len = strlen (next_str);
      memcpy (p, next_str, len);
      p += len;
    }
  va_end (args);
  *p = '\0';

  return ret;
}


