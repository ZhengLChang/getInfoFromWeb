#ifndef HTTP_H_
#define HTTP_H_
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
#include "util.h"
#include <netdb.h>
#include <ifaddrs.h>
#include "buffer.h"
#include "httpstatus.h"
#include "config.h"
#define HTTP_RESPONSE_MAX_SIZE 65536

enum authentication_scheme
{
	AUTHENTICATION_SCHEME_BASIC,
	AUTHENTICATION_SCHEME_DIGEST
};

enum rp {
  rel_none, rel_name, rel_value, rel_both
};
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
struct http_stat
{
	int stat_code;
	char *respond_head;
	char *stat_data;
	char *location;
	int content_len;
	char *content_data;
	char *connection_stat;
	char *transferEncoding;
	char *WWWAuthenticate;
	char *server;
	char *ContentType;
};
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

struct request {
  const char *method;
  char *arg;

  struct request_header {
    char *name, *value;
    enum rp release_policy;
  } *headers;
  int hcount, hcapacity;

  const char *data;
  int dataLen;
};

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
typedef struct {
  /* A token consists of characters in the [b, e) range. */
  const char *b, *e;
} param_token;

typedef enum{
	CONNECT_STATUS_CONNECTING,
	CONNECT_STATUS_CONNECTED,
	CONNECT_STATUS_UNAUTHORIZED,
	CONNECT_STATUS_AUTHORIZATION_SENT,
	CONNECT_STATUS_REQUEST_SENT,
	CONNECT_STATUS_RESPONSE_GET,
	CONNECT_STATUS_ERROR,
	CONNECT_STATUS_CLOSE, /*beginning and ending status*/
	CONNECT_STATUS_NOTLOOP,
}connect_status_t;

typedef struct {
	buffer *urloriginal;
	struct url *urlparse;
	connect_status_t connect_status;
	struct request *req;
	buffer *method;
	struct http_stat http_status;
	int sock;
}user_url_data_t;

struct http_stat * http_stat_new();
void http_stat_data_free(struct http_stat *hs);
void http_stat_free(struct http_stat *hs);
enum url_scheme url_scheme (const char *url);
int scheme_default_port (enum url_scheme scheme);
const char *url_skip_credentials (const char *url);
const char *init_seps (enum url_scheme scheme);
void split_path (const char *path, char **dir, char **file);
void url_unescape (char *s);
bool path_simplify(enum url_scheme scheme, char *path);
bool parse_credentials (const char *beg, const char *end, char **user, char **passwd);
struct url *url_parse (const char *url, int *error_number);
void url_free (struct url *url);
struct request *request_new (void);
int full_path_length (const struct url *url);
void full_path_write (const struct url *url, char *where);
char *url_full_path (const struct url *url);
void request_set_method (struct request *req, const char *meth, char *arg);
void request_set_data(struct request *req, const char *data, const int dataLen);
const char *request_method (const struct request *req);
void release_header (struct request_header *hdr);
void request_set_header (struct request *req, char *name, char *value, enum rp release_policy);
bool request_remove_header (struct request *req, char *name);
struct address_list *address_list_from_addrinfo (const struct addrinfo *ai);
struct address_list *lookup_host (const char *host);
void request_free (struct request *req);
void resp_free (struct response *resp);
int fd_write (int fd, char *buf, int bufsize);
int request_send (const struct request *req, int fd);
const char *response_head_terminator (const char *start, const char *peeked, int peeklen);
int fd_read_body(int fd, char *buf, const int buf_size,
		int toread, int *error_code);
char *read_http_response_head (int fd);
char *read_http_body_len_head (int fd);
struct response *resp_new (const char *head);
int resp_status (const struct response *resp, char **message);
bool resp_header_get (const struct response *resp, const char *name,
                 const char **begptr, const char **endptr);
bool resp_header_copy (const struct response *resp, const char *name,
                  char *buf, int bufsize);
char *resp_header_strdup (const struct response *resp, const char *name);
bool known_authentication_scheme_p (const char *au);
bool extract_param (const char **source, param_token *name, param_token *value,
               char separator);
void get_response_head_stat(char *head, struct http_stat *http_status);
void get_response_body(user_url_data_t *url_data);
int get_http(struct url *u, struct http_stat *http_status);
struct http_stat * get_url_stat(char *urlStr);
char *create_authorization_line (const char *au, const char *user,
                           const char *passwd, const char *method,
                           const char *path);
void add_authentication_head_to_request(struct url *u, struct request *req, const char *www_authenticate);
struct request *ini_request_head_without_auth(struct url *u, const char *method, const char *data, const int dataLen);
bool request_head_add_authorization_head(user_url_data_t *url_data);
char *basic_authentication_encode (const char *user, const char *passwd);
int resp_header_locate (const struct response *resp, const char *name, int start,
                    const char **begptr, const char **endptr);
void sockaddr_set_data (struct sockaddr *sa, const ip_address *ip, int port);
socklen_t sockaddr_size (const struct sockaddr *sa);
int sock_peek (int fd, char *buf, int bufsize);
int connect_to_ip (const ip_address *ip, int port);
int connect_to_host (const char *host, int port);
int sock_read (int fd, char *buf, int bufsize);
typedef const char *(*hunk_terminator_t) (const char *, const char *, int);
char *fd_read_hunk (int fd, hunk_terminator_t terminator, long sizehint, long maxsize);
bool is_sock_connected(int sock);
char* network_get_host_ip(char *buf, int buf_size);
char* network_get_host_ip_with_suffix(char *buf, int buf_size);
char* network_get_host_subnetwork(char *buf, int buf_size);
char *network_get_host_ip_by_interface(const char *interface, char *buf, int buf_size);
#endif
