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
/* Fill SA as per the data in IP and PORT.  SA shoult point to struct
   sockaddr_storage if ENABLE_IPV6 is defined, to struct sockaddr_in
   otherwise.  */

void sockaddr_set_data (struct sockaddr *sa, const ip_address *ip, int port)
{
  switch (ip->family)
    {
    case AF_INET:
      {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        xzero (*sin);
        sin->sin_family = AF_INET;
        sin->sin_port = htons (port);
        sin->sin_addr = ip->data.d4;
        break;
      }
    case AF_INET6:
      {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        xzero (*sin6);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons (port);
        sin6->sin6_addr = ip->data.d6;
        break;
      }
    default:
      abort ();
    }
}
/* Return the size of the sockaddr structure depending on its
   family.  */
socklen_t sockaddr_size (const struct sockaddr *sa)
{
  switch (sa->sa_family)
    {
    case AF_INET:
      return sizeof (struct sockaddr_in);
    case AF_INET6:
      return sizeof (struct sockaddr_in6);
    default:
      abort ();
    }
  return 0;
}
/* Connect via TCP to the specified address and port.

   If PRINT is non-NULL, it is the host name to print that we're
   connecting to.  */

int connect_to_ip (const ip_address *ip, int port)
{
	struct sockaddr_storage ss;
	struct sockaddr *sa = (struct sockaddr *)&ss;
	int sock;
	/* Store the sockaddr info to SA.  */
	sockaddr_set_data (sa, ip, port);
	/* Create the socket of the family appropriate for the address.  */
	sock = socket (sa->sa_family, SOCK_STREAM, 0);
	if (sock < 0)
		goto err;
	if(0 != connect(sock, sa, sockaddr_size (sa)))
	{
		goto err;
	}
	return sock;
err:
	return -1;
}

/* Connect via TCP to a remote host on the specified port.

   HOST is resolved as an Internet host name.  If HOST resolves to
   more than one IP address, they are tried in the order returned by
   DNS until connecting to one of them succeeds.  */

int connect_to_host (const char *host, int port)
{
  int i, start, end;
  int sock;

  struct address_list *al = lookup_host (host);

  if(al == NULL)
  {
	  return -1;
  }
  address_list_get_bounds (al, &start, &end);
  for (i = start; i < end; i++)
    {
      const ip_address *ip = address_list_address_at (al, i);
      sock = connect_to_ip (ip, port);
      if (sock >= 0)
        {
          /* Success. */
          address_list_set_connected (al);
          address_list_release (al);
          return sock;
        }

      /* The attempt to connect has failed.  Continue with the loop
         and try next address. */

      address_list_set_faulty (al, i);
    }
  address_list_release (al);

  return -1;
}


/* Like fd_read, except it provides a "preview" of the data that will
   be read by subsequent calls to fd_read.  Specifically, it copies no
   more than BUFSIZE bytes of the currently available data to BUF and
   returns the number of bytes copied.  Return values and timeout
   semantics are the same as those of fd_read.

   CAVEAT: Do not assume that the first subsequent call to fd_read
   will retrieve the same amount of data.  Reading can return more or
   less data, depending on the TCP implementation and other
   circumstances.  However, barring an error, it can be expected that
   all the peeked data will eventually be read by fd_read.  */
int sock_peek (int fd, char *buf, int bufsize)
{
  int res;
  do
    res = recv (fd, buf, bufsize, MSG_PEEK);
  while (res == -1 && errno == EINTR);
  return res;
}

int sock_read (int fd, char *buf, int bufsize)
{
  int res;
  do
    res = read (fd, buf, bufsize);
  while (res == -1 && errno == EINTR);
  return res;
}

/* Read a hunk of data from FD, up until a terminator.  The hunk is
   limited by whatever the TERMINATOR callback chooses as its
   terminator.  For example, if terminator stops at newline, the hunk
   will consist of a line of data; if terminator stops at two
   newlines, it can be used to read the head of an HTTP response.
   Upon determining the boundary, the function returns the data (up to
   the terminator) in malloc-allocated storage.

   In case of read error, NULL is returned.  In case of EOF and no
   data read, NULL is returned and errno set to 0.  In case of having
   read some data, but encountering EOF before seeing the terminator,
   the data that has been read is returned, but it will (obviously)
   not contain the terminator.

   The TERMINATOR function is called with three arguments: the
   beginning of the data read so far, the beginning of the current
   block of peeked-at data, and the length of the current block.
   Depending on its needs, the function is free to choose whether to
   analyze all data or just the newly arrived data.  If TERMINATOR
   returns NULL, it means that the terminator has not been seen.
   Otherwise it should return a pointer to the charactre immediately
   following the terminator.

   The idea is to be able to read a line of input, or otherwise a hunk
   of text, such as the head of an HTTP request, without crossing the
   boundary, so that the next call to fd_read etc. reads the data
   after the hunk.  To achieve that, this function does the following:

   1. Peek at incoming data.

   2. Determine whether the peeked data, along with the previously
      read data, includes the terminator.

      2a. If yes, read the data until the end of the terminator, and
          exit.

      2b. If no, read the peeked data and goto 1.

   The function is careful to assume as little as possible about the
   implementation of peeking.  For example, every peek is followed by
   a read.  If the read returns a different amount of data, the
   process is retried until all data arrives safely.

   SIZEHINT is the buffer size sufficient to hold all the data in the
   typical case (it is used as the initial buffer size).  MAXSIZE is
   the maximum amount of memory this function is allowed to allocate,
   or 0 if no upper limit is to be enforced.

   This function should be used as a building block for other
   functions -- see fd_read_line as a simple example.  */

char *fd_read_hunk (int fd, hunk_terminator_t terminator, long sizehint, long maxsize)
{
  long bufsize = sizehint;
  char *hunk = xmalloc (bufsize);
  int tail = 0;                 /* tail position in HUNK */

  assert (!maxsize || maxsize >= bufsize);

  while (1)
    {
      const char *end;
      int pklen, rdlen, remain;

      /* First, peek at the available data. */

      pklen = sock_peek (fd, hunk + tail, bufsize - 1 - tail);
      if (pklen < 0)
        {
          xfree (hunk);
          return NULL;
        }
      end = terminator (hunk, hunk + tail, pklen);
      if (end)
        {
          /* The data contains the terminator: we'll drain the data up
             to the end of the terminator.  */
          remain = end - (hunk + tail);
          assert (remain >= 0);
          if (remain == 0)
            {
              /* No more data needs to be read. */
              hunk[tail] = '\0';
              return hunk;
            }
          if (bufsize - 1 < tail + remain)
            {
              bufsize = tail + remain + 1;
              hunk = xrealloc (hunk, bufsize);
            }
        }
      else
        /* No terminator: simply read the data we know is (or should
           be) available.  */
        remain = pklen;

      /* Now, read the data.  Note that we make no assumptions about
         how much data we'll get.  (Some TCP stacks are notorious for
         read returning less data than the previous MSG_PEEK.)  */

      rdlen = sock_read (fd, hunk + tail, remain);
      if (rdlen < 0)
        {
          xfree_null (hunk);
          return NULL;
        }
      tail += rdlen;
      hunk[tail] = '\0';

      if (rdlen == 0)
        {
          if (tail == 0)
            {
              /* EOF without anything having been read */
              xfree (hunk);
              errno = 0;
              return NULL;
            }
          else
            /* EOF seen: return the data we've read. */
            return hunk;
        }
      if (end && rdlen == remain)
        /* The terminator was seen and the remaining data drained --
           we got what we came for.  */
        return hunk;

      /* Keep looping until all the data arrives. */

      if (tail == bufsize - 1)
        {
          /* Double the buffer size, but refuse to allocate more than
             MAXSIZE bytes.  */
          if (maxsize && bufsize >= maxsize)
            {
              xfree (hunk);
              errno = ENOMEM;
              return NULL;
            }
          bufsize <<= 1;
          if (maxsize && bufsize > maxsize)
            bufsize = maxsize;
          hunk = xrealloc (hunk, bufsize);
        }
    }
}

