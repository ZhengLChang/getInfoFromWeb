/*
 *gcc httpRequest.c  gen-md5.c base64.c -l crypto
 *usage: ./a.out www.baidu.com http
	./a.out http://www.baidu.com/index.html http 
http://d.10jqka.com.cn/v2/realhead/hs_002594/last.js
 * */
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
#include "base64.h"
#include <ctype.h>
# include <openssl/md5.h>
#include "json.h"
#include "config.h"
#include "util.h"
#include "signal.h"


static bool is_exit = 0;
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
static void url_unescape (char *s);
#define MD5_HASHLEN 16
/* HTTP/1.0 status codes from RFC1945, provided for reference.  */
/* Successful 2xx.  */
#define HTTP_STATUS_OK                    200
#define HTTP_STATUS_CREATED               201
#define HTTP_STATUS_ACCEPTED              202
#define HTTP_STATUS_NO_CONTENT            204
#define HTTP_STATUS_PARTIAL_CONTENTS      206

/* Redirection 3xx.  */
#define HTTP_STATUS_MULTIPLE_CHOICES      300
#define HTTP_STATUS_MOVED_PERMANENTLY     301
#define HTTP_STATUS_MOVED_TEMPORARILY     302
#define HTTP_STATUS_SEE_OTHER             303 /* from HTTP/1.1 */
#define HTTP_STATUS_NOT_MODIFIED          304
#define HTTP_STATUS_TEMPORARY_REDIRECT    307 /* from HTTP/1.1 */

/* Client error 4xx.  */
#define HTTP_STATUS_BAD_REQUEST           400
#define HTTP_STATUS_UNAUTHORIZED          401
#define HTTP_STATUS_FORBIDDEN             403
#define HTTP_STATUS_NOT_FOUND             404
#define HTTP_STATUS_RANGE_NOT_SATISFIABLE 416

/* Server errors 5xx.  */
#define HTTP_STATUS_INTERNAL              500
#define HTTP_STATUS_NOT_IMPLEMENTED       501
#define HTTP_STATUS_BAD_GATEWAY           502
#define HTTP_STATUS_UNAVAILABLE           503

# define MIN(x, y) ((x) > (y) ? (y) : (x))
typedef const char *(*hunk_terminator_t) (const char *, const char *, int);

enum authentication_scheme
{
	AUTHENTICATION_SCHEME_BASIC,
	AUTHENTICATION_SCHEME_DIGEST
};

enum {
  WAIT_FOR_READ = 1,
  WAIT_FOR_WRITE = 2
};

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
#define xnew(type) (xmalloc (sizeof (type)))
#define xnew0(type) (xcalloc (1, sizeof (type)))
#define xnew_array(type, len) (xmalloc ((len) * sizeof (type)))
#define xnew_array0(type, len) (xcalloc ((len),  sizeof (type)))
#define alloca_array(type, size) ((type *) alloca ((size) * sizeof (type)))

#define xfree(x) do{ \
	if((x)) \
	{ free((x));(x)=NULL;}\
}while(0)

#define xfree_null(p) if (!(p)) ; else xfree (p)
bool c_isxdigit (int c)
{
  return ((c >= '0' && c <= '9')
          || ((c & ~0x20) >= 'A' && (c & ~0x20) <= 'F'));
}
int c_toupper (int c)
{
	return (c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c);
}

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

#define CLOSE_FD(fd) do{ \
	if(fd >= 0) \
	{\
		close(fd);\
		fd=-1;	  \
	} \
}while(0)

static void signal_handler(int sig)
{
	switch(sig)
	{
		case SIGINT:
			is_exit = 1;
			fprintf(stderr, "SIGINT\n");
			break;
		case SIGCHLD:
	//		fprintf(stderr, "SIGINT\n");
			break;
	}
	return;
}

enum rp {
  rel_none, rel_name, rel_value, rel_both
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

struct http_stat
{
	int stat_code;
	char *respond_head;
	char *stat_data;
	char *location;
	int content_len;
	char *content_data;
	char *connection_stat;
	char *WWWAuthenticate;
	char *server;
	char *ContentType;
};

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
/* Lists of IP addresses that result from running DNS queries.  See
   lookup_host for details.  */
struct address_list {
  int count;                    /* number of adrresses */
  ip_address *addresses;        /* pointer to the string of addresses */

  int faulty;                   /* number of addresses known not to work. */
  bool connected;               /* whether we were able to connect to
                                   one of the addresses in the list,
                                   at least once. */

  int refcount;                 /* reference count; when it drops to
                                   0, the entry is freed. */
};

static char *xstrdup(const char *s)
{
	char *new_s = xmalloc(strlen(s) + 1);
	memcpy(new_s, s, strlen(s) + 1);
	return new_s;
}

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

static struct error_data error_array[] = 
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
struct request {
  const char *method;
  char *arg;

  struct request_header {
    char *name, *value;
    enum rp release_policy;
  } *headers;
  int hcount, hcapacity;
};

static const char * get_error_string(int error_number)
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
enum {
	scm_disabled = 1,             /* for https when OpenSSL fails to init. */
	scm_has_params = 2,           /* whether scheme has ;params */
	scm_has_query = 4,            /* whether scheme has ?query */
	scm_has_fragment = 8          /* whether scheme has #fragment */
};

enum url_scheme {
	  SCHEME_HTTP,
//	  SCHEME_HTTPS,
	  SCHEME_INVALID
};

struct url
{
	char *url;			/* Original URL */
	enum url_scheme scheme;	/* URL scheme */
	char *host;			/* Extracted hostname */
	int port;			/* Port number */
	/* URL components (URL-quoted). */
	char *path;
	char *params;
	char *query;
	char *fragment;

	/* Extracted path info (unquoted). */
	char *dir;
	char *file;
	/* Username and password (unquoted). */
	char *user;
	char *passwd;
};

/* Default port definitions */
#define DEFAULT_HTTP_PORT 80
#define DEFAULT_HTTPS_PORT 443


struct scheme_data
{
	/* Short name of the scheme, such as "http" or "ftp". */
	const char *name;
	/* Leading string that identifies the scheme, such as "https://". */
	const char *leading_string;
	/* Default port of the scheme when none is specified. */
	int default_port;
	/* Various flags. */
	int flags;
};
/* Supported schemes: */
static struct scheme_data supported_schemes[] =
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

/* Skip the username and password, if present in the URL.  The
 * function should *not* be called with the complete URL, but with the
 * portion after the scheme.
 *
 * If no username and password are found, return URL.  */

static const char *url_skip_credentials (const char *url)
{
	/* Look for '@' that comes before terminators, such as '/', '?',
	 * *      '#', or ';'.  */
	const char *p = (const char *)strpbrk (url, "@/?#;");
	if (!p || *p != '@')
		return url;
	return p + 1;
}

static const char *init_seps (enum url_scheme scheme)
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

static bool
is_valid_ipv4_address (const char *str, const char *end)
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

/* Like strpbrk, with the exception that it returns the pointer to the
 * terminating zero (end-of-string aka "eos") if no matching character
 * is found.  */

static inline char *
strpbrk_or_eos (const char *s, const char *accept)
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
static void split_path (const char *path, char **dir, char **file)
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

static void url_unescape (char *s)
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

static bool path_simplify(enum url_scheme scheme, char *path)
{
	return false;
}

/* Parse credentials contained in [BEG, END).  The region is expected
   to have come from a URL and is unescaped.  */

static bool
parse_credentials (const char *beg, const char *end, char **user, char **passwd)
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

static struct request *request_new (void)
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
static int full_path_length (const struct url *url)
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

static void full_path_write (const struct url *url, char *where)
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

char *
url_full_path (const struct url *url)
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
static void request_set_method (struct request *req, const char *meth, char *arg)
{
  req->method = meth;
  req->arg = arg;
}

/* Return the method string passed with the last call to
   request_set_method.  */

static const char *
request_method (const struct request *req)
{
  return req->method;
}

/* Free one header according to the release policy specified with
   request_set_header.  */

static void
release_header (struct request_header *hdr)
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

static void request_set_header (struct request *req, char *name, char *value,
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

static bool
request_remove_header (struct request *req, char *name)
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

/* Create an address_list from the addresses in the given struct
   addrinfo.  */

static struct address_list *address_list_from_addrinfo (const struct addrinfo *ai)
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
    	fprintf(stderr, "%s %d: %s\n", __func__, __LINE__, gai_strerror (err));
    	return NULL;
    }
    al = address_list_from_addrinfo (res);
    freeaddrinfo (res);
    return al;
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

/* Fill SA as per the data in IP and PORT.  SA shoult point to struct
   sockaddr_storage if ENABLE_IPV6 is defined, to struct sockaddr_in
   otherwise.  */

static void sockaddr_set_data (struct sockaddr *sa, const ip_address *ip, int port)
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

static socklen_t sockaddr_size (const struct sockaddr *sa)
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


/* Release the resources used by REQ. */
static void request_free (struct request *req)
{
  int i;
  xfree_null (req->arg);
  for (i = 0; i < req->hcount; i++)
    release_header (&req->headers[i]);
  xfree_null (req->headers);
  xfree (req);
}


struct response {
  /* The response data. */
  const char *data;

  /* The array of pointers that indicate where each header starts.
     For example, given this HTTP response:

       HTTP/1.0 200 Ok
       Description: some
        text
       Etag: x

     The headers are located like this:

     "HTTP/1.0 200 Ok\r\nDescription: some\r\n text\r\nEtag: x\r\n\r\n"
     ^                   ^                             ^          ^
     headers[0]          headers[1]                    headers[2] headers[3]

     I.e. headers[0] points to the beginning of the request,
     headers[1] points to the end of the first header and the
     beginning of the second one, etc.  */

  const char **headers;
};


static void resp_free (struct response *resp)
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

#define APPEND(p, str) do {                     \
  int A_len = strlen (str);                     \
  memcpy (p, str, A_len);                       \
  p += A_len;                                   \
} while (0)


/* Construct the request and write it to FD using fd_write.  */
static int request_send (const struct request *req, int fd)
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
static int sock_peek (int fd, char *buf, int bufsize)
{
  int res;
  do
    res = recv (fd, buf, bufsize, MSG_PEEK);
  while (res == -1 && errno == EINTR);
  return res;
}

static int sock_read (int fd, char *buf, int bufsize)
{
  int res;
  do
    res = read (fd, buf, bufsize);
  while (res == -1 && errno == EINTR);
  return res;
}
#define HTTP_RESPONSE_MAX_SIZE 65536
/* Determine whether [START, PEEKED + PEEKLEN) contains an empty line.
   If so, return the pointer to the position after the line, otherwise
   return NULL.  This is used as callback to fd_read_hunk.  The data
   between START and PEEKED has been read and cannot be "unread"; the
   data after PEEKED has only been peeked.  */

static const char *response_head_terminator (const char *start, const char *peeked, int peeklen)
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

static const char *file_len_terminator (const char *start, const char *peeked, int peeklen)
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

static char *read_http_response_head (int fd)
{
  return fd_read_hunk (fd, response_head_terminator, 512,
                       HTTP_RESPONSE_MAX_SIZE);
}

static char *read_http_body_len_head (int fd)
{
  return fd_read_hunk (fd, file_len_terminator, 512,
                       HTTP_RESPONSE_MAX_SIZE);
}
/* Create a new response object from the text of the HTTP response,
   available in HEAD.  That text is automatically split into
   constituent header lines for fast retrieval using
   resp_header_*.  */

static struct response *resp_new (const char *head)
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

static int resp_status (const struct response *resp, char **message)
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

/* Locate the header named NAME in the request data, starting with
   position START.  This allows the code to loop through the request
   data, filtering for all requests of a given name.  Returns the
   found position, or -1 for failure.  The code that uses this
   function typically looks like this:

     for (pos = 0; (pos = resp_header_locate (...)) != -1; pos++)
       ... do something with header ...

   If you only care about one header, use resp_header_get instead of
   this function.  */

static int resp_header_locate (const struct response *resp, const char *name, int start,
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

/* Find and retrieve the header named NAME in the request data.  If
   found, set *BEGPTR to its starting, and *ENDPTR to its ending
   position, and return true.  Otherwise return false.

   This function is used as a building block for resp_header_copy
   and resp_header_strdup.  */

static bool resp_header_get (const struct response *resp, const char *name,
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

static bool resp_header_copy (const struct response *resp, const char *name,
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

static char *
resp_header_strdup (const struct response *resp, const char *name)
{
  const char *b, *e;
  if (!resp_header_get (resp, name, &b, &e))
    return NULL;
  return strdupdelim (b, e);
}

static bool known_authentication_scheme_p (const char *au)
{
  return (strncasecmp(au, "Basic", sizeof("Basic") - 1) == 0)||
		 (strncasecmp(au, "Digest", sizeof("Digest") - 1) == 0);
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

typedef struct {
  /* A token consists of characters in the [b, e) range. */
  const char *b, *e;
} param_token;
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
/* How many bytes it will take to store LEN bytes in base64.  */
#define BASE64_LENGTH(len) (4 * (((len) + 2) / 3))

/* Authorization support: We support three authorization schemes:

   * `Basic' scheme, consisting of base64-ing USER:PASSWORD string;

   * `Digest' scheme, added by Junio Hamano <junio@twinsun.com>,
   consisting of answering to the server's challenge with the proper
   MD5 digests.
  */

/* Create the authentication header contents for the `Basic' scheme.
   This is done by encoding the string "USER:PASS" to base64 and
   prepending the string "Basic " in front of it.  */

static char *basic_authentication_encode (const char *user, const char *passwd)
{
  char *t1, *t2;
  int len1 = strlen (user) + 1 + strlen (passwd);

  t1 = (char *)alloca (len1 + 1);
  sprintf (t1, "%s:%s", user, passwd);

  t2 = (char *)alloca (BASE64_LENGTH (len1) + 1);
  base64_encode (t1, len1, t2);

  return concat_strings ("Basic ", t2, (char *) 0);
}

#define SKIP_WS(x) do {                         \
  while (isspace (*(x)))                        \
    ++(x);                                      \
} while (0)

#define XNUM_TO_DIGIT(x) ("0123456789ABCDEF"[x] + 0)
#define XNUM_TO_digit(x) ("0123456789abcdef"[x] + 0)
/* The reverse of the above: convert a number in the [0, 16) range to
   the ASCII representation of the corresponding hexadecimal digit.
   `+ 0' is there so you can't accidentally use it as an lvalue.  */

/* Dump the hexadecimal representation of HASH to BUF.  HASH should be
   an array of 16 bytes containing the hash keys, and BUF should be a
   buffer of 33 writable characters (32 for hex digits plus one for
   zero termination).  */
static void dump_hash (char *buf, const unsigned char *hash)
{
  int i;

  for (i = 0; i < MD5_HASHLEN; i++, hash++)
    {
      *buf++ = XNUM_TO_digit (*hash >> 4);
      *buf++ = XNUM_TO_digit (*hash & 0xf);
    }
  *buf = '\0';
}

/* Take the line apart to find the challenge, and compose a digest
   authorization header.  See RFC2069 section 2.1.2.  */
static char *digest_authentication_encode (const char *au, const char *user,
                              const char *passwd, const char *method,
                              const char *path)
{
  static char *realm, *opaque, *nonce;
  static struct {
    const char *name;
    char **variable;
  } options[] = {
    { "realm", &realm },
    { "opaque", &opaque },
    { "nonce", &nonce }
  };
  char *res;
  param_token name, value;

  realm = opaque = nonce = NULL;

  au += 6;                      /* skip over `Digest' */
  while (extract_param (&au, &name, &value, ','))
    {
      size_t i;
      size_t namelen = name.e - name.b;
      for (i = 0; i < countof (options); i++)
        if (namelen == strlen (options[i].name)
            && 0 == strncmp (name.b, options[i].name,
                             namelen))
          {
            *options[i].variable = strdupdelim (value.b, value.e);
            break;
          }
    }
  if (!realm || !nonce || !user || !passwd || !path || !method)
    {
      xfree_null (realm);
      xfree_null (opaque);
      xfree_null (nonce);
      return NULL;
    }

  /* Calculate the digest value.  */
  {
	MD5_CTX ctx;
    unsigned char hash[MD5_HASHLEN];
    char a1buf[MD5_HASHLEN * 2 + 1], a2buf[MD5_HASHLEN * 2 + 1];
    char response_digest[MD5_HASHLEN * 2 + 1];

    /* A1BUF = H(user ":" realm ":" password) */
    MD5_Init (&ctx);
    MD5_Update (&ctx, (unsigned char *)user, strlen (user));
    MD5_Update (&ctx, (unsigned char *)":", 1);
    MD5_Update (&ctx, (unsigned char *)realm, strlen (realm));
    MD5_Update (&ctx, (unsigned char *)":", 1);
    MD5_Update (&ctx, (unsigned char *)passwd, strlen (passwd));
    MD5_Final (hash, &ctx);
    dump_hash (a1buf, hash);

    /* A2BUF = H(method ":" path) */
    MD5_Init (&ctx);
    MD5_Update (&ctx, (unsigned char *)method, strlen (method));
    MD5_Update (&ctx, (unsigned char *)":", 1);
    MD5_Update (&ctx, (unsigned char *)path, strlen (path));
    MD5_Final (hash, &ctx);
    dump_hash (a2buf, hash);

    /* RESPONSE_DIGEST = H(A1BUF ":" nonce ":" A2BUF) */
    MD5_Init (&ctx);
    MD5_Update (&ctx, (unsigned char *)a1buf, MD5_HASHLEN * 2);
    MD5_Update (&ctx, (unsigned char *)":", 1);
    MD5_Update (&ctx, (unsigned char *)nonce, strlen (nonce));
    MD5_Update (&ctx, (unsigned char *)":", 1);
    MD5_Update (&ctx, (unsigned char *)a2buf, MD5_HASHLEN * 2);
    MD5_Final (hash, &ctx);
    dump_hash (response_digest, hash);

    res = xmalloc (strlen (user)
                   + strlen (user)
                   + strlen (realm)
                   + strlen (nonce)
                   + strlen (path)
                   + 2 * MD5_HASHLEN /*strlen (response_digest)*/
                   + (opaque ? strlen (opaque) : 0)
                   + 128);
    sprintf (res, "Digest \
username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
             user, realm, nonce, path, response_digest);
//    fprintf(stderr, "%s\n", res);
    if (opaque)
      {
        char *p = res + strlen (res);
        strcat (p, ", opaque=\"");
        strcat (p, opaque);
        strcat (p, "\"");
      }
  }
  xfree_null (realm);
  xfree_null (opaque);
  xfree_null (nonce);
  return res;
}

/* Create the HTTP authorization request header.  When the
   `WWW-Authenticate' response header is seen, according to the
   authorization scheme specified in that header (`Basic' and `Digest'
   are supported by the current implementation), produce an
   appropriate HTTP authorization request header.  */
static char *create_authorization_line (const char *au, const char *user,
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
#if 0
    request_set_header (req, "", "", rel_none);
    request_set_header (req, "", "", rel_none);
#endif
    return req;
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
	http_status->server = resp_header_strdup (resp, "Server");
	http_status->ContentType = resp_header_strdup (resp, "Content-Type");
	resp_free(resp);
	return ;
}

int get_http(struct url *u, struct http_stat *http_status)
{
	struct request *req = NULL;
	bool auth_finished = false;
	struct url *conn = u;
	int sock = -1;
	char *head = NULL;
	int error_code = NO_ERROR;

	req = ini_request_head_without_auth(u, "GET");

	while(1)
	{
//		fprintf(stderr, "%s %d\n", __func__, __LINE__);
		if(sock < 0)
		{
			sock = connect_to_host (conn->host, conn->port);
			if(sock < 0)
			{
				error_code = ERROR_HOST;
				goto END;
			}
		}
	    /* Send the request to server.  */
	    if(request_send(req, sock) < 0)
	    {
	    	error_code = ERROR_WRITE;
	    	goto END;
	    }

	    /*analysis response head*/
		head = read_http_response_head (sock);
		if(head == NULL || *head == '\0')
		{
			error_code = ERROR_READ;
			goto END;
		}
//		fprintf(stderr, "head:\n%s\n", head);
		http_stat_data_free(http_status);
		get_response_head_stat(head, http_status);
#if 0
		if(head != NULL)
		{
			xfree(head);
		}
#endif
		if(http_status->content_len != 0 && sock >= 0)
		{
			if(http_status->content_data != NULL)
			{
				xfree(http_status->content_data);
				http_status->content_data = NULL;
			}
			http_status->content_data = xmalloc(http_status->content_len);
			if(fd_read_body(sock, http_status->content_data,
					http_status->content_len, http_status->content_len, &error_code) <= 0)
				goto END;
		}
		else if(sock >= 0)
		{
			int size_tmp = -1;
			char *body_len = NULL;
#if 1
			body_len = read_http_body_len_head(sock);
			if(body_len != NULL)
			{
				int i = 0;
				http_status->content_len = 0;
//				printf("%s\n", body_len);
				for(i = 0; i < strlen(body_len); i++)
				{
					if(body_len[i] >= '0' && body_len[i] <= '9')
					{
						http_status->content_len = http_status->content_len * 16 + body_len[i] - '0';
					}
					else if(body_len[i] >= 'a' && body_len[i] <= 'z')
					{
						http_status->content_len = http_status->content_len * 16 + body_len[i] - 'a' + 10;
					}
					else if(body_len[i] >= 'A' && body_len[i] <= 'Z')
					{
						http_status->content_len = http_status->content_len * 16 + body_len[i] - 'A' + 10;
					}
				}
				xfree(body_len);
			}
#endif
#define HTTP_CONTENT_MAX_LEN (http_status->content_len)
			if(http_status->content_data != NULL)
			{
				xfree(http_status->content_data);
				http_status->content_data = NULL;
			}
			if(http_status->content_len > 0)
			{
			http_status->content_data = xmalloc(HTTP_CONTENT_MAX_LEN);
			//if((size_tmp = fd_read_body(sock, http_status->content_data,
			//		HTTP_CONTENT_MAX_LEN, HTTP_CONTENT_MAX_LEN, &error_code)) <= 0)
			if((size_tmp = fd_read_body(sock, http_status->content_data,
					HTTP_CONTENT_MAX_LEN, HTTP_CONTENT_MAX_LEN, &error_code)) <= 0)
			{
				goto END;
			}
			http_status->content_len = size_tmp;
			}
#undef HTTP_CONTENT_MAX_LEN
		}
		if(http_status->stat_code == HTTP_STATUS_OK)
		{
			error_code = NO_ERROR;
			goto END;
		}
		else if(http_status->stat_code == HTTP_STATUS_UNAUTHORIZED)
		{
			error_code = ERROR_AUTHFAILED;
			break;
		}
		else
		{error_code = ERROR_READ;break;}
		if(http_status->connection_stat && 0 == strncasecmp(http_status->connection_stat, "Close", sizeof("Close") - 1) &&
				sock >= 0)
		{
			CLOSE_FD(sock);
		}
	}


END:
#if 0
	if(head != NULL)
	{
		xfree(head);
	}
#endif
	if(req != NULL)
	{
		request_free(req);
	}
	if(sock >= 0)
	{
		CLOSE_FD(sock);
	}
	return error_code;
}

bool dump_to_file(const char *data, size_t data_len, const char *file_name)
{
	int fd = -1;
	const char *p = "./dump.file";
	assert(file_name != NULL && file_name[0] != '\0');
	if(file_name[strlen(file_name) - 1] != '\\')
	{
		p = file_name;
	}
	fd = open(p, O_CREAT | O_WRONLY | O_CLOEXEC | O_TRUNC, S_IRWXU);
	if(fd != -1)
	{
		write_all(fd, data, data_len);
		close(fd);
		fd = -1;
		return true;
	}
	fprintf(stderr, "%s %d, %s\n", __func__, __LINE__, strerror(errno));
	return false;
}

struct http_stat * get_url_stat(char *urlStr)
{
	struct url *u = NULL;
	int error_number = NO_ERROR;
	struct http_stat *http_status = NULL;
	if(urlStr == NULL || urlStr[0] == '\0')
	{
		return NULL;
	}
	u = url_parse(urlStr, &error_number);
	if(u != NULL && error_number == NO_ERROR)
	{
		http_status = http_stat_new();
		error_number = get_http(u, http_status);
	}

	url_free(u);
	u = NULL;
	return http_status;
}
int main(int argc, char **argv)
{
	struct http_stat *http_status = NULL;
	char url[1024] = "";
	char phoneAnswer[1024] = "";
	char *p = NULL;
	int i = 0, fork_num = 0;

	set_signal_handler (SIGCHLD, signal_handler);
	set_signal_handler (SIGINT, signal_handler);

	for(i = 1; i < 255; i++)
	{
		if(snprintf(url, sizeof(url), "http://172.16.0.%d", i) > sizeof(url))
		{
			fprintf(stderr, "stock code too long\n");
			return -1;
		}

		if(fork() == 0)
		{
		if((http_status = get_url_stat(url)) != NULL)
		{
			if(http_status->stat_code == HTTP_STATUS_UNAUTHORIZED)
			{
				if(http_status != NULL &&
						NULL != (p = strstr(http_status->WWWAuthenticate, "Digest realm")))
				{
					p += sizeof("Digest realm") - 1; 
					while(isspace(*p) || *p == '\"' || *p == '=')
					{
						p++;
					}
					strncpy(phoneAnswer, p, sizeof(phoneAnswer));
					p = phoneAnswer;
					while(*p != '\"')
					{p++;}
					*p = '\0';
					if(strcmp(phoneAnswer, "IP Phone Web Configuration") == 0)
					{
						fprintf(stderr, "%12s\t%s\n", url, "Atcom Device");
					}
					else
					{
						fprintf(stderr, "%12s\t%s\n", url, phoneAnswer);
					}
				}
			}
			if(http_status->stat_code == HTTP_STATUS_OK &&
					http_status->server != NULL && 
						strcmp(http_status->server, "embed httpd") == 0)
			{
				fprintf(stderr, "%12s\t%s\n", url, "Maybe Yealink Device");
			}
		}
		http_stat_free(http_status);
		http_status = NULL;
		exit(0);
		}
		usleep(100);
		fork_num++;
	}
	http_stat_free(http_status);
	http_status = NULL;
	int status;
	while(fork_num > 0 && 
			wait(&status))
	{
		fork_num--;
	}
	fprintf(stderr, "Done\n");
	return 0;
}



