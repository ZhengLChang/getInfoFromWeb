#include "http.h"
#include "log.h"

struct http_stat * http_stat_new()
{
	struct http_stat *hs = NULL;
	hs = xnew0( struct http_stat );
	return hs;
}

void http_stat_data_free(struct http_stat *hs)
{
	if(hs != NULL)
	{
		xfree(hs->respond_head);
		xfree(hs->stat_data);
		xfree(hs->location);
		xfree(hs->content_data);
		xfree(hs->connection_stat);
		xfree(hs->WWWAuthenticate);
		xfree(hs->ContentType);
		hs->stat_code = 0;
		hs->content_len = 0;
	}

}

void http_stat_free(struct http_stat *hs)
{
	if(hs != NULL)
	{
		http_stat_data_free(hs);
		xfree(hs);
	}
}

/* Supported schemes: */
struct scheme_data supported_schemes[] =
{
	{ "http",     "http://",  DEFAULT_HTTP_PORT,  scm_has_query|scm_has_fragment },
//	{ "https",    "https://", DEFAULT_HTTPS_PORT, scm_has_query|scm_has_fragment },
	/* SCHEME_INVALID */
	{ NULL,       NULL,       -1,                 0 }
};

enum url_scheme url_scheme (const char *url)
{
	int i;
	for (i = 0; supported_schemes[i].leading_string; i++)
	{
		if (0 == strncasecmp (url, supported_schemes[i].leading_string,
					strlen (supported_schemes[i].leading_string)))
		{
			if (!(supported_schemes[i].flags & scm_disabled))
				return (enum url_scheme) i;
			else
				return SCHEME_INVALID;
		}
	}
  	return SCHEME_INVALID;
}
int scheme_default_port (enum url_scheme scheme)
{
  return supported_schemes[scheme].default_port;
}

/* Skip the username and password, if present in the URL.  The
 * function should *not* be called with the complete URL, but with the
 * portion after the scheme.
 *
 * If no username and password are found, return URL.  */

const char *url_skip_credentials (const char *url)
{
	/* Look for '@' that comes before terminators, such as '/', '?',
	 * *      '#', or ';'.  */
	const char *p = (const char *)strpbrk (url, "@/?#;");
	if (!p || *p != '@')
		return url;
	return p + 1;
}

const char *init_seps (enum url_scheme scheme)
{
	static char seps[8] = ":/";
	char *p = seps + 2;
	int flags = supported_schemes[scheme].flags;

	if (flags & scm_has_params)
		*p++ = ';';
	if (flags & scm_has_query)
		*p++ = '?';
	if (flags & scm_has_fragment)
		*p++ = '#';
	*p++ = '\0';
	return seps;
}


/* Split PATH into DIR and FILE.  PATH comes from the URL and is
 * expected to be URL-escaped.
 *
 * The path is split into directory (the part up to the last slash)
 * and file (the part after the last slash), which are subsequently
 * unescaped.  Examples:
 * PATH                 DIR           FILE
 * "foo/bar/baz"        "foo/bar"     "baz"
 * "foo/bar/"           "foo/bar"     ""
 * "foo"                ""            "foo"
 * "foo/bar/baz%2fqux"  "foo/bar"     "baz/qux" (!)
 * DIR and FILE are freshly allocated.  */
void split_path (const char *path, char **dir, char **file)
{
	char *last_slash = strrchr (path, '/');
	if (!last_slash)
	{
		*dir = strdup ("");
		*file = strdup (path);
	}
	else
	{
		*dir = strdupdelim (path, last_slash);
		*file = strdup (last_slash + 1);
	}
	url_unescape (*dir);
	url_unescape (*file);
}

/* URL-unescape the string S.
 *
 * This is done by transforming the sequences "%HH" to the character
 * represented by the hexadecimal digits HH.  If % is not followed by
 * two hexadecimal digits, it is inserted literally.
 *
 * The transformation is done in place.  If you need the original
 * string intact, make a copy before calling this function.  */

void url_unescape (char *s)
{
	char *t = s;                  /* t - tortoise */
	char *h = s;                  /* h - hare     */

  	for (; *h; h++, t++)
	{
		if (*h != '%')
		{
copychar:
			*t = *h;
		}
		else
		{
			char c;
			/* Do nothing if '%' is not followed by two hex digits. */
			if (!h[1] || !h[2] || !(isxdigit (h[1]) && isxdigit (h[2])))
				goto copychar;
			c = X2DIGITS_TO_NUM (h[1], h[2]);
			/* Don't unescape %00 because there is no way to insert it
			 * into a C string without effectively truncating it. */
			if (c == '\0')
				goto copychar;
			*t = c;
			h += 2;
		}
	}
	*t = '\0';
}

bool path_simplify(enum url_scheme scheme, char *path)
{
	return false;
}

/* Parse credentials contained in [BEG, END).  The region is expected
   to have come from a URL and is unescaped.  */

bool parse_credentials (const char *beg, const char *end, char **user, char **passwd)
{
  char *colon;
  const char *userend;

  if (beg == end)
    return false;               /* empty user name */

  colon = memchr (beg, ':', end - beg);
  if (colon == beg)
    return false;               /* again empty user name */

  if (colon)
    {
      *passwd = strdupdelim (colon + 1, end);
      userend = colon;
      url_unescape (*passwd);
    }
  else
    {
      *passwd = NULL;
      userend = end;
    }
  *user = strdupdelim (beg, userend);
  url_unescape (*user);
  return true;
}

struct url *url_parse (const char *url, int *error_number)
{
	struct url *u = NULL;
	const char *p = NULL;
	bool path_modified, host_modified;

	host_modified = 0;
	enum url_scheme scheme;
	const char *seps = NULL;

	const char *uname_b = NULL,     *uname_e = NULL;
	const char *host_b = NULL,      *host_e = NULL;
	const char *path_b = NULL,      *path_e = NULL;
	const char *params_b = NULL,    *params_e = NULL;
	const char *query_b = NULL,     *query_e = NULL;
	const char *fragment_b = NULL,  *fragment_e = NULL;
	int port;
	char *user = NULL, *passwd = NULL;
	*error_number = NO_ERROR;

	scheme = url_scheme (url);
	if (scheme == SCHEME_INVALID)
	{
		*error_number = ERROR_UNSUPPORTED_SCHEME;
		goto ERROR;
	}

	p = url;
	p += strlen(supported_schemes[scheme].leading_string);
	uname_b = p;
	p = url_skip_credentials (p);
	uname_e = p;

	/* scheme://user:pass@host[:port]... */
	/*                    ^              */
    /* We attempt to break down the URL into the components path,
	 * params, query, and fragment.  They are ordered like this:
	 *
	 * scheme://host[:port][/path][;params][?query][#fragment]  */
	seps = init_seps (scheme);

	host_b = p;

	if (*p == '[')
	{
		/* Handle IPv6 address inside square brackets.  Ideally we'd
		 * * just look for the terminating ']', but rfc2732 mandates
		 * * rejecting invalid IPv6 addresses.  */
	      /* The address begins after '['. */
	     	host_b = p + 1;
		host_e = strchr (host_b, ']');
		if (!host_e)
	        {
   			*error_number = ERROR_UNTERMINATED_IPV6_ADDRESS;
			goto ERROR;
		}
		/* Check if the IPv6 address is valid. */
		if (!is_valid_ipv6_address(host_b, host_e))
	       	{
			*error_number = ERROR_INVALID_IPV6_ADDRESS;
			goto ERROR;
	       	}
		/* Continue parsing after the closing ']'. */
		p = host_e + 1;

	  	/* The closing bracket must be followed by a separator or by the
       			* null char.  */
		/* http://[::1]... */
	       	/*             ^   */
		if (!strchr (seps, *p))
	        {
    			/* Trailing garbage after []-delimited IPv6 address. */
			*error_number = ERROR_UNTERMINATED_IPV6_ADDRESS;
			goto ERROR;
		}
	}
	else
	{
		p = strpbrk_or_eos (p, seps);
		host_e = p;
	}
	++seps;                       /* advance to '/' */
	if (host_b == host_e)
	{
		*error_number = ERROR_INVALID_HOST_NAME;
		goto ERROR;
	}

	port = scheme_default_port (scheme);
	if (*p == ':')
	{
		const char *port_b, *port_e, *pp;
		/* scheme://host:port/tralala */
		/*              ^             */
		++p;
		port_b = p;
		p = strpbrk_or_eos (p, seps);
		port_e = p;
		/* Allow empty port, as per rfc2396. */
		if (port_b != port_e)
			for (port = 0, pp = port_b; pp < port_e; pp++)
			{
				if (!isdigit (*pp))
				{
					/* http://host:12randomgarbage/blah */
					/*               ^                  */
					*error_number = ERROR_BAD_PORT_NUMBER;
					goto ERROR;
				}
				port = 10 * port + (*pp - '0');
				/* Check for too large port numbers here, before we have
				 * *                a chance to overflow on bogus port values.  */
				if (port > 0xffff)
				{
					*error_number = ERROR_BAD_PORT_NUMBER;
					goto ERROR;
				}
			}
	}
	/* Advance to the first separator *after* '/' (either ';' or '?',
	 * depending on the scheme).  */
	++seps;

    	/* Get the optional parts of URL, each part being delimited by
	 * current location and the position of the next separator.  */
#define GET_URL_PART(sepchar, var) do {            \
	  if (*p == sepchar)                                            \
	    var##_b = ++p, var##_e = p = strpbrk_or_eos (p, seps);      \
	  ++seps;                                                       \
} while (0)
	GET_URL_PART ('/', path);
	if (supported_schemes[scheme].flags & scm_has_params)
		GET_URL_PART (';', params);
	if (supported_schemes[scheme].flags & scm_has_query)
		GET_URL_PART ('?', query);
	if (supported_schemes[scheme].flags & scm_has_fragment)
		GET_URL_PART ('#', fragment);
#undef GET_URL_PART
	if(*p != 0)
	{
		*error_number = ERROR_BAD_URL;
		goto ERROR;
	}
	if (uname_b != uname_e)
	{
		/* http://user:pass@host */
		/*        ^         ^    */
		/*     uname_b   uname_e */
		if (!parse_credentials (uname_b, uname_e - 1, &user, &passwd))
		{
			*error_number = ERROR_INVALID_USER_NAME;
			goto ERROR;
		}
	}

	u = xnew0 (struct url);
	u->scheme = scheme;
	u->host   = strdupdelim (host_b, host_e);
	u->port   = port;
	u->user   = user;
	u->passwd = passwd;
	u->path = strdupdelim (path_b, path_e);

	path_modified = path_simplify (scheme, u->path);
	split_path (u->path, &u->dir, &u->file);

	if (params_b)
		u->params = strdupdelim (params_b, params_e);
	if (query_b)
		u->query = strdupdelim (query_b, query_e);
	if (fragment_b)
		u->fragment = strdupdelim (fragment_b, fragment_e);

	u->url = strdup (url);

	return u;
ERROR:
	return NULL;
}

void url_free (struct url *url)
{
	if (url)
    {
		xfree (url->host);
		xfree (url->path);
		xfree (url->url);

		xfree (url->params);
		xfree (url->query);
		xfree (url->fragment);
		xfree (url->user);
		xfree (url->passwd);

		xfree (url->dir);
		xfree (url->file);

		xfree (url);
    }
}


/* Create a new, empty request.  At least request_set_method must be
   called before the request can be used.  */

struct request *request_new (void)
{
  struct request *req = xnew0 (struct request);
  req->hcapacity = 8;
  req->headers = xnew_array (struct request_header, req->hcapacity);
  return req;
}
/* Note: URL's "full path" is the path with the query string and
   params appended.  The "fragment" (#foo) is intentionally ignored,
   but that might be changed.  For example, if the original URL was
   "http://host:port/foo/bar/baz;bullshit?querystring#uselessfragment",
   the full path will be "/foo/bar/baz;bullshit?querystring".  */

/* Return the length of the full path, without the terminating
   zero.  */
int full_path_length (const struct url *url)
{
  int len = 0;

#define FROB(el) if (url->el) len += 1 + strlen (url->el)

  FROB (path);
  FROB (params);
  FROB (query);

#undef FROB

  return len;
}

/* Write out the full path. */

void full_path_write (const struct url *url, char *where)
{
#define FROB(el, chr) do {                      \
  char *f_el = url->el;                         \
  if (f_el) {                                   \
    int l = strlen (f_el);                      \
    *where++ = chr;                             \
    memcpy (where, f_el, l);                    \
    where += l;                                 \
  }                                             \
} while (0)

  FROB (path, '/');
  FROB (params, ';');
  FROB (query, '?');

#undef FROB
}

/* Public function for getting the "full path".  E.g. if u->path is
   "foo/bar" and u->query is "param=value", full_path will be
   "/foo/bar?param=value". */

char *url_full_path (const struct url *url)
{
  int length = full_path_length (url);
  char *full_path = xmalloc (length + 1);

  full_path_write (url, full_path);
  full_path[length] = '\0';

  return full_path;
}

/* Set the request's method and its arguments.  METH should be a
   literal string (or it should outlive the request) because it will
   not be freed.  ARG will be freed by request_free.  */
void request_set_method (struct request *req, const char *meth, char *arg)
{
  req->method = meth;
  req->arg = arg;
}

/* Return the method string passed with the last call to
   request_set_method.  */

const char *request_method (const struct request *req)
{
  return req->method;
}

/* Free one header according to the release policy specified with
   request_set_header.  */

void release_header (struct request_header *hdr)
{
  switch (hdr->release_policy)
    {
    case rel_none:
      break;
    case rel_name:
      xfree (hdr->name);
      break;
    case rel_value:
      xfree (hdr->value);
      break;
    case rel_both:
      xfree (hdr->name);
      xfree (hdr->value);
      break;
    }
}

/* Set the request named NAME to VALUE.  Specifically, this means that
   a "NAME: VALUE\r\n" header line will be used in the request.  If a
   header with the same name previously existed in the request, its
   value will be replaced by this one.  A NULL value means do nothing.

   RELEASE_POLICY determines whether NAME and VALUE should be released
   (freed) with request_free.  Allowed values are:

    - rel_none     - don't free NAME or VALUE
    - rel_name     - free NAME when done
    - rel_value    - free VALUE when done
    - rel_both     - free both NAME and VALUE when done

   Setting release policy is useful when arguments come from different
   sources.  For example:

     // Don't free literal strings!
     request_set_header (req, "Pragma", "no-cache", rel_none);

     // Don't free a global variable, we'll need it later.
     request_set_header (req, "Referer", opt.referer, rel_none);

     // Value freshly allocated, free it when done.
     request_set_header (req, "Range",
                         aprintf ("bytes=%s-", number_to_static_string (hs->restval)),
                         rel_value);
   */

void request_set_header (struct request *req, char *name, char *value,
                    enum rp release_policy)
{
  struct request_header *hdr;
  int i;

  if (!value)
    {
      /* A NULL value is a no-op; if freeing the name is requested,
         free it now to avoid leaks.  */
      if (release_policy == rel_name || release_policy == rel_both)
        xfree (name);
      return;
    }

  for (i = 0; i < req->hcount; i++)
    {
      hdr = &req->headers[i];
      if (0 == strcasecmp (name, hdr->name))
        {
          /* Replace existing header. */
          release_header (hdr);
          hdr->name = name;
          hdr->value = value;
          hdr->release_policy = release_policy;
          return;
        }
    }

  /* Install new header. */

  if (req->hcount >= req->hcapacity)
    {
      req->hcapacity <<= 1;
      req->headers = xrealloc (req->headers, req->hcapacity * sizeof (*hdr));
    }
  hdr = &req->headers[req->hcount++];
  hdr->name = name;
  hdr->value = value;
  hdr->release_policy = release_policy;
}

/* Remove the header with specified name from REQ.  Returns true if
   the header was actually removed, false otherwise.  */

bool request_remove_header (struct request *req, char *name)
{
  int i;
  for (i = 0; i < req->hcount; i++)
    {
      struct request_header *hdr = &req->headers[i];
      if (0 == strcasecmp (name, hdr->name))
        {
          release_header (hdr);
          /* Move the remaining headers by one. */
          if (i < req->hcount - 1)
            memmove (hdr, hdr + 1, (req->hcount - i - 1) * sizeof (*hdr));
          --req->hcount;
          return true;
        }
    }
  return false;
}
/* Get the bounds of the address list.  */

void address_list_get_bounds (const struct address_list *al, int *start, int *end)
{
  *start = al->faulty;
  *end   = al->count;
}
/* Return a pointer to the address at position POS.  */

const ip_address *address_list_address_at (const struct address_list *al, int pos)
{
  assert (pos >= al->faulty && pos < al->count);
  return al->addresses + pos;
}




static void address_list_delete (struct address_list *al)
{
  xfree (al->addresses);
  xfree (al);
}

/* Mark the address list as being no longer in use.  This will reduce
   its reference count which will cause the list to be freed when the
   count reaches 0.  */

void
address_list_release (struct address_list *al)
{
	--al->refcount;
	if (al->refcount <= 0)
	{
		address_list_delete (al);
	}
}

void address_list_set_connected (struct address_list *al)
{
  al->connected = true;
}

/* Mark the INDEXth element of AL as faulty, so that the next time
   this address list is used, the faulty element will be skipped.  */

void
address_list_set_faulty (struct address_list *al, int index)
{
  /* We assume that the address list is traversed in order, so that a
     "faulty" attempt is always preceded with all-faulty addresses,
     and this is how Wget uses it.  */
  assert (index == al->faulty);

  ++al->faulty;
  if (al->faulty >= al->count)
    /* All addresses have been proven faulty.  Since there's not much
       sense in returning the user an empty address list the next
       time, we'll rather make them all clean, so that they can be
       retried anew.  */
    al->faulty = 0;
}

/* Create an address_list from the addresses in the given struct
   addrinfo.  */

struct address_list *address_list_from_addrinfo (const struct addrinfo *ai)
{
  struct address_list *al;
  const struct addrinfo *ptr;
  int cnt;
  ip_address *ip;

  cnt = 0;
  for (ptr = ai; ptr != NULL ; ptr = ptr->ai_next)
    if (ptr->ai_family == AF_INET || ptr->ai_family == AF_INET6)
      ++cnt;
  if (cnt == 0)
    return NULL;

  al = xnew0 (struct address_list);
  al->addresses = xnew_array (ip_address, cnt);
  al->count     = cnt;
  al->refcount  = 1;

  ip = al->addresses;
  for (ptr = ai; ptr != NULL; ptr = ptr->ai_next)
    if (ptr->ai_family == AF_INET6)
      {
        const struct sockaddr_in6 *sin6 =
          (const struct sockaddr_in6 *)ptr->ai_addr;
        ip->family = AF_INET6;
        ip->data.d6 = sin6->sin6_addr;
        ++ip;
      }
    else if (ptr->ai_family == AF_INET)
      {
        const struct sockaddr_in *sin =
          (const struct sockaddr_in *)ptr->ai_addr;
        ip->family = AF_INET;
        ip->data.d4 = sin->sin_addr;
        ++ip;
      }
  assert (ip - al->addresses == cnt);
  return al;
}

struct address_list *lookup_host (const char *host)
{
	struct address_list *al;
    int err;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags |= AI_PASSIVE;

    err = getaddrinfo (host, NULL, &hints, &res);
    if(err != 0)
    {
	log_error_write(__func__, __LINE__, "ss", host, gai_strerror (err));
    	return NULL;
    }
    al = address_list_from_addrinfo (res);
    freeaddrinfo (res);
    return al;
}

/* Release the resources used by REQ. */
void request_free (struct request *req)
{
  int i;
  xfree_null (req->arg);
  for (i = 0; i < req->hcount; i++)
    release_header (&req->headers[i]);
  xfree_null (req->headers);
  xfree (req);
}

void resp_free (struct response *resp)
{
  xfree_null (resp->headers);
  xfree (resp);
}

int fd_write (int fd, char *buf, int bufsize)
{
	  int res = 0;
	  while (bufsize > 0)
	  {
		  if((res = write(fd, buf, bufsize)) < 0)
		  {
			  break;
		  }
		  buf += res;
		  bufsize -= res;
	  }
	  return res;
}

/* Construct the request and write it to FD using fd_write.  */
int request_send (const struct request *req, int fd)
{
	char *request_string, *p;
	int i, size, write_error;

	/* Count the request size. */
	size = 0;
	/* METHOD " " ARG " " "HTTP/1.0" "\r\n" */
	size += strlen (req->method) + 1 + strlen (req->arg) + 1 + 8 + 2;
	for (i = 0; i < req->hcount; i++)
	{
		struct request_header *hdr = &req->headers[i];
		/* NAME ": " VALUE "\r\n" */
		size += strlen (hdr->name) + 2 + strlen (hdr->value) + 2;
	}
	/* "\r\n\0" */
	size += 3;
	p = request_string = alloca_array (char, size);
	/* Generate the request. */

	APPEND (p, req->method); *p++ = ' ';
	APPEND (p, req->arg);    *p++ = ' ';
	memcpy (p, "HTTP/1.1\r\n", 10); p += 10;
	for (i = 0; i < req->hcount; i++)
	{
		struct request_header *hdr = &req->headers[i];
		APPEND (p, hdr->name);
		*p++ = ':', *p++ = ' ';
		APPEND (p, hdr->value);
		*p++ = '\r', *p++ = '\n';
	}
	*p++ = '\r', *p++ = '\n', *p++ = '\0';
	assert (p - request_string == size);
	write_error = fd_write (fd, request_string, size - 1);
	return write_error;
}


/* Determine whether [START, PEEKED + PEEKLEN) contains an empty line.
   If so, return the pointer to the position after the line, otherwise
   return NULL.  This is used as callback to fd_read_hunk.  The data
   between START and PEEKED has been read and cannot be "unread"; the
   data after PEEKED has only been peeked.  */

const char *response_head_terminator (const char *start, const char *peeked, int peeklen)
{
  const char *p, *end;

  /* If at first peek, verify whether HUNK starts with "HTTP".  If
     not, this is a HTTP/0.9 request and we must bail out without
     reading anything.  */
  if (start == peeked && 0 != memcmp (start, "HTTP", MIN (peeklen, 4)))
    return start;

  /* Look for "\n[\r]\n", and return the following position if found.
     Start two chars before the current to cover the possibility that
     part of the terminator (e.g. "\n\r") arrived in the previous
     batch.  */
  p = peeked - start < 2 ? start : peeked - 2;
  end = peeked + peeklen;

  /* Check for \n\r\n or \n\n anywhere in [p, end-2). */
  for (; p < end - 2; p++)
    if (*p == '\n')
      {
        if (p[1] == '\r' && p[2] == '\n')
          return p + 3;
        else if (p[1] == '\n')
          return p + 2;
      }
  /* p==end-2: check for \n\n directly preceding END. */
  if (p[0] == '\n' && p[1] == '\n')
    return p + 2;

  return NULL;
}
int fd_read_body(int fd, char *buf, const int buf_size,
		int toread, int *error_code)
{
	int sum_read = 0;
	int read_len = 0;
	char *p = buf;
//	double maxTime = 5;

	assert(error_code != NULL);
	if(buf == NULL)
	{
		abort();
	}
	if(!is_fd_ready(fd, 5, WAIT_FOR_READ, error_code))
	{
		return -1;
	}
	for(sum_read = 0; toread > 0 && sum_read < buf_size; )
	{
		read_len = sock_read (fd, p, toread);
		if(read_len < 0)
		{
			/*error occur*/
			return sum_read;
		}
		else if(read_len == 0)
		{
			/*end of file*/
			return sum_read;
		}
		p += read_len;
		sum_read += read_len;
		toread -= read_len;
	}
	return sum_read;
}

char *read_http_response_head (int fd)
{
  return fd_read_hunk (fd, response_head_terminator, 512,
                       HTTP_RESPONSE_MAX_SIZE);
}

char *read_http_body_len_head (int fd)
{
  return fd_read_hunk (fd, file_len_terminator, 512,
                       HTTP_RESPONSE_MAX_SIZE);
}


/* Create a new response object from the text of the HTTP response,
   available in HEAD.  That text is automatically split into
   constituent header lines for fast retrieval using
   resp_header_*.  */

struct response *resp_new (const char *head)
{
  const char *hdr;
  int count, size;

  struct response *resp = xnew0 (struct response);
  resp->data = head;

  if (*head == '\0')
    {
      /* Empty head means that we're dealing with a headerless
         (HTTP/0.9) response.  In that case, don't set HEADERS at
         all.  */
      return resp;
    }

  /* Split HEAD into header lines, so that resp_header_* functions
     don't need to do this over and over again.  */

  size = count = 0;
  hdr = head;
  while (1)
    {
      DO_REALLOC (resp->headers, size, count + 1, const char *);
      resp->headers[count++] = hdr;

      /* Break upon encountering an empty line. */
      if (!hdr[0] || (hdr[0] == '\r' && hdr[1] == '\n') || hdr[0] == '\n')
        break;

      /* Find the end of HDR, including continuations. */
      do
        {
          const char *end = strchr (hdr, '\n');
          if (end)
            hdr = end + 1;
          else
            hdr += strlen (hdr);
        }
      while (*hdr == ' ' || *hdr == '\t');
    }
  DO_REALLOC (resp->headers, size, count + 1, const char *);
  resp->headers[count] = NULL;

  return resp;
}

/* Parse the HTTP status line, which is of format:

   HTTP-Version SP Status-Code SP Reason-Phrase

   The function returns the status-code, or -1 if the status line
   appears malformed.  The pointer to "reason-phrase" message is
   returned in *MESSAGE.  */

int resp_status (const struct response *resp, char **message)
{
  int status;
  const char *p, *end;

  if (!resp->headers)
    {
      /* For a HTTP/0.9 response, assume status 200. */
      if (message)
        *message = NULL;
      return -1;
    }

  p = resp->headers[0];
  end = resp->headers[1];

  if (!end)
    return -1;

  /* "HTTP" */
  if (end - p < 4 || 0 != strncmp (p, "HTTP", 4))
    return -1;
  p += 4;

  /* Match the HTTP version.  This is optional because Gnutella
     servers have been reported to not specify HTTP version.  */
  if (p < end && *p == '/')
    {
      ++p;
      while (p < end && isdigit (*p))
        ++p;
      if (p < end && *p == '.')
        ++p;
      while (p < end && isdigit (*p))
        ++p;
    }

  while (p < end && isspace (*p))
    ++p;
  if (end - p < 3 || !isdigit (p[0]) || !isdigit (p[1]) || !isdigit (p[2]))
    return -1;

  status = 100 * (p[0] - '0') + 10 * (p[1] - '0') + (p[2] - '0');
  p += 3;

  if (message)
    {
      while (p < end && isspace (*p))
        ++p;
      while (p < end && isspace (end[-1]))
        --end;
      *message = strdupdelim (p, end);
    }

  return status;
}
/* Find and retrieve the header named NAME in the request data.  If
   found, set *BEGPTR to its starting, and *ENDPTR to its ending
   position, and return true.  Otherwise return false.

   This function is used as a building block for resp_header_copy
   and resp_header_strdup.  */

bool resp_header_get (const struct response *resp, const char *name,
                 const char **begptr, const char **endptr)
{
  int pos = resp_header_locate (resp, name, 0, begptr, endptr);
  return pos != -1;
}

/* Copy the response header named NAME to buffer BUF, no longer than
   BUFSIZE (BUFSIZE includes the terminating 0).  If the header
   exists, true is returned, false otherwise.  If there should be no
   limit on the size of the header, use resp_header_strdup instead.

   If BUFSIZE is 0, no data is copied, but the boolean indication of
   whether the header is present is still returned.  */

bool resp_header_copy (const struct response *resp, const char *name,
                  char *buf, int bufsize)
{
  const char *b, *e;
  if (!resp_header_get (resp, name, &b, &e))
    return false;
  if (bufsize)
    {
      int len = MIN (e - b, bufsize - 1);
      memcpy (buf, b, len);
      buf[len] = '\0';
    }
  return true;
}

/* Return the value of header named NAME in RESP, allocated with
   malloc.  If such a header does not exist in RESP, return NULL.  */

char *
resp_header_strdup (const struct response *resp, const char *name)
{
  const char *b, *e;
  if (!resp_header_get (resp, name, &b, &e))
    return NULL;
  return strdupdelim (b, e);
}

bool known_authentication_scheme_p (const char *au)
{
  return (strncasecmp(au, "Basic", sizeof("Basic") - 1) == 0)||
		 (strncasecmp(au, "Digest", sizeof("Digest") - 1) == 0);
}



/* Extract a parameter from the string (typically an HTTP header) at
   **SOURCE and advance SOURCE to the next parameter.  Return false
   when there are no more parameters to extract.  The name of the
   parameter is returned in NAME, and the value in VALUE.  If the
   parameter has no value, the token's value is zeroed out.

   For example, if *SOURCE points to the string "attachment;
   filename=\"foo bar\"", the first call to this function will return
   the token named "attachment" and no value, and the second call will
   return the token named "filename" and value "foo bar".  The third
   call will return false, indicating no more valid tokens.  */

bool extract_param (const char **source, param_token *name, param_token *value,
               char separator)
{
  const char *p = *source;

  while (isspace (*p)) ++p;
  if (!*p)
    {
      *source = p;
      return false;             /* no error; nothing more to extract */
    }

  /* Extract name. */
  name->b = p;
  while (*p && !isspace (*p) && *p != '=' && *p != separator) ++p;
  name->e = p;
  if (name->b == name->e)
    return false;               /* empty name: error */
  while (isspace (*p)) ++p;
  if (*p == separator || !*p)           /* no value */
    {
      xzero (*value);
      if (*p == separator) ++p;
      *source = p;
      return true;
    }
  if (*p != '=')
    return false;               /* error */

  /* *p is '=', extract value */
  ++p;
  while (isspace (*p)) ++p;
  if (*p == '"')                /* quoted */
    {
      value->b = ++p;
      while (*p && *p != '"') ++p;
      if (!*p)
        return false;
      value->e = p++;
      /* Currently at closing quote; find the end of param. */
      while (isspace (*p)) ++p;
      while (*p && *p != separator) ++p;
      if (*p == separator)
        ++p;
      else if (*p)
        /* garbage after closed quote, e.g. foo="bar"baz */
        return false;
    }
  else                          /* unquoted */
    {
      value->b = p;
      while (*p && *p != separator) ++p;
      value->e = p;
      while (value->e != value->b && isspace (value->e[-1]))
        --value->e;
      if (*p == separator) ++p;
    }
  *source = p;
  return true;
}

void get_response_head_stat(char *head, struct http_stat *http_status)
{
	struct response *resp = resp_new (head);
	char *content_len_data = NULL;
	http_status->respond_head = head;
	http_status->stat_code = resp_status(resp, &http_status->stat_data);
	http_status->connection_stat = resp_header_strdup (resp, "Connection");
	if(http_status->connection_stat == NULL)
	{
		http_status->connection_stat = resp_header_strdup (resp, "Keep-Alive");
	}
	content_len_data = resp_header_strdup (resp, "Content-Length");
	if(content_len_data != NULL)
	{
		http_status->content_len = atoi(content_len_data);
		xfree (content_len_data);
		content_len_data = NULL;
	}
	else
	{
		http_status->content_len = 0;
	}
	http_status->location = resp_header_strdup (resp, "Location");
	http_status->WWWAuthenticate = resp_header_strdup (resp, "WWW-Authenticate");
	http_status->ContentType = resp_header_strdup (resp, "Content-Type");
	resp_free(resp);
	return ;
}

/* Create the HTTP authorization request header.  When the
   `WWW-Authenticate' response header is seen, according to the
   authorization scheme specified in that header (`Basic' and `Digest'
   are supported by the current implementation), produce an
   appropriate HTTP authorization request header.  */
char *create_authorization_line (const char *au, const char *user,
                           const char *passwd, const char *method,
                           const char *path)
{
  /* We are called only with known schemes, so we can dispatch on the
     first letter. */
  switch (c_toupper (*au))
    {
    case 'B':                   /* Basic */
      return basic_authentication_encode (user, passwd);
    case 'D':                   /* Digest */
      return digest_authentication_encode (au, user, passwd, method, path);
    default:
      /* We shouldn't get here -- this function should be only called
         with values approved by known_authentication_scheme_p.  */
      abort ();
    }
}

void add_authentication_head_to_request(struct url *u, struct request *req, const char *www_authenticate)
{
	char *pth = url_full_path (u);
	request_set_header (req, "Authorization",
          create_authorization_line (www_authenticate, u->user, u->passwd, request_method (req),pth),
				  rel_value);
	xfree (pth);
	return;
}

struct request *ini_request_head_without_auth(struct url *u, const char *method)
{
	struct request *req = request_new ();
	char *meth_arg = NULL;
	if(method == NULL || method[0] == '\0')
	{
		return NULL;
	}
	meth_arg = url_full_path (u);
	request_set_method (req, method, meth_arg);

    request_set_header (req, "User-Agent",                               \
                        aprintf ("Atcom/%s (%s)",                         \
                        		"1.0", "Linux"),                        \
                        rel_value);
    request_set_header (req, "Accept", "*/*", rel_none);
    /* Generate the Host header, HOST:PORT.  Take into account that:

       - Broken server-side software often doesn't recognize the PORT
         argument, so we must generate "Host: www.server.com" instead of
         "Host: www.server.com:80" (and likewise for https port).

       - IPv6 addresses contain ":", so "Host: 3ffe:8100:200:2::2:1234"
         becomes ambiguous and needs to be rewritten as "Host:
         [3ffe:8100:200:2::2]:1234".  */
    {
      /* Formats arranged for hfmt[add_port][add_squares].  */
      static const char *hfmt[][2] = {
        { "%s", "[%s]" }, { "%s:%d", "[%s]:%d" }
      };
      int add_port = u->port != scheme_default_port (u->scheme);
      int add_squares = strchr (u->host, ':') != NULL;
      request_set_header (req, "Host",
                          aprintf (hfmt[add_port][add_squares], u->host, u->port),
                          rel_value);
    }

    request_set_header (req, "Connection", "Keep-Alive", rel_none);
    request_set_header (req, "Content-Encoding", "gzip", rel_none);
   // request_set_header (req, "Cookie", "v=AVdubXP2waqui0Um-hR6VDAO4MCknCuVBXCvcqmEcyaN2Hm0sWy7ThVAP-W5", rel_none);
   // request_set_header (req, "If-Modified-Since", "Mon, 13 Nov 2017 14:51:01 GMT", rel_none);
    request_set_header (req, "Referer", "http://stockpage.10jqka.com.cn/realHead_v2.html", rel_none);
    request_set_header (req, "Cookie", "spversion=20130314; Hm_lvt_78c58f01938e4d85eaf619eae71b4ed1=1510241482; Hm_lpvt_78c58f01938e4d85eaf619eae71b4ed1=1510584498; historystock=601989%7C*%7C000538%7C*%7C002594; v=AXlAAyEMB2ycAdv1usl8UsLUju5Whm04V3qRzJuu9aAfIpca49Z9COfKoZ4r", rel_none);
#if 0
    request_set_header (req, "", "", rel_none);
    request_set_header (req, "", "", rel_none);
#endif
    return req;
}

/* Authorization support: We support three authorization schemes:

   * `Basic' scheme, consisting of base64-ing USER:PASSWORD string;

   * `Digest' scheme, added by Junio Hamano <junio@twinsun.com>,
   consisting of answering to the server's challenge with the proper
   MD5 digests.
  */

/* Create the authentication header contents for the `Basic' scheme.
   This is done by encoding the string "USER:PASS" to base64 and
   prepending the string "Basic " in front of it.  */

char *basic_authentication_encode (const char *user, const char *passwd)
{
  char *t1, *t2;
  int len1 = strlen (user) + 1 + strlen (passwd);

  t1 = (char *)alloca (len1 + 1);
  sprintf (t1, "%s:%s", user, passwd);

  t2 = (char *)alloca (BASE64_LENGTH (len1) + 1);
  base64_encode (t1, len1, t2);

  return concat_strings ("Basic ", t2, (char *) 0);
}


/* Locate the header named NAME in the request data, starting with
   position START.  This allows the code to loop through the request
   data, filtering for all requests of a given name.  Returns the
   found position, or -1 for failure.  The code that uses this
   function typically looks like this:

     for (pos = 0; (pos = resp_header_locate (...)) != -1; pos++)
       ... do something with header ...

   If you only care about one header, use resp_header_get instead of
   this function.  */

int resp_header_locate (const struct response *resp, const char *name, int start,
                    const char **begptr, const char **endptr)
{
  int i;
  const char **headers = resp->headers;
  int name_len;

  if (!headers || !headers[1])
    return -1;

  name_len = strlen (name);
  if (start > 0)
    i = start;
  else
    i = 1;

  for (; headers[i + 1]; i++)
    {
      const char *b = headers[i];
      const char *e = headers[i + 1];
      if (e - b > name_len
          && b[name_len] == ':'
          && 0 == strncasecmp (b, name, name_len))
        {
          b += name_len + 1;
          while (b < e && isspace (*b))
            ++b;
          while (b < e && isspace (e[-1]))
            --e;
          *begptr = b;
          *endptr = e;
          return i;
        }
    }
  return -1;
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
