#include "util.h"
#include "http.h"
#include "config.h"
#include "buffer.h"
#include "httpstatus.h"
#include "json.h"
#include <alloca.h>
#include <time.h>
#include "log.h"

static bool is_exit = 0;
#define IP_SUM (255)
static void signal_handler(int sig)
{
	switch(sig)
	{
		case SIGINT:
			is_exit = 1;
			fprintf(stderr, "SIGINT\n");
			break;
		case SIGCHLD:
			fprintf(stderr, "SIGINT\n");
			break;
	}
	return;
}
static void daemonize(void) {
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	if (0 != fork()) exit(0);

	if (-1 == setsid()) exit(0);

	signal(SIGHUP, SIG_IGN);

	if (0 != fork()) exit(0);

	if (0 != chdir("/")) exit(0);
}

static void init_url_array(user_url_data_t* url_data_array, int sum)
{
	int i = 0;
	for(i = 0; i < sum; i++)
	{
		int error_number = NO_ERROR;
		user_url_data_t *p = url_data_array + i;
		p->urloriginal = buffer_init_printf("http://admin:admin@172.16.0.%d/cgi-bin/web_cgi_main.cgi?status_get", i);
		p->urlparse = url_parse(url_data_array[i].urloriginal->ptr, &error_number);
		p->connect_status = CONNECT_STATUS_CLOSE;
		p->method = buffer_init_string("GET");
		p->req = ini_request_head_without_auth(p->urlparse, buffer_get_c_string(p->method));
		p->sock = -1;
		memset(&p->http_status, 0, sizeof(p->http_status));
	}
	return ;
}
int main(int argc, char **argv)
{
	int i = 0;
	user_url_data_t* url_data_array = NULL;
	time_t cur_time = 0, last_time = 0, interval = 1;
	fd_set rfds, wfds;
	struct timeval timeout;
	int retval = 0;
	int nfds = 0;
	int error_code = NO_ERROR;
	const char *p = NULL;
	int pid = 0;
	bool is_everything_over = true;

	UNUSED(error_code);
	UNUSED(cur_time);
	UNUSED(last_time);
	p = (const char *)strrchr(argv[0], '/');
	if(p == NULL)
	{
		p = argv[0];
	}
	else
	{
		p++;
	}
	if((pid = getPidByName(p)) > 0 && pid != getpid())
	{
		log_error_write(__func__, __LINE__, "ss", p, " is running");
		return (-1);
	}
	set_signal_handler (SIGCHLD, signal_handler);
	set_signal_handler (SIGINT, signal_handler);
	set_signal_handler (SIGPIPE, signal_handler);

	log_error_open();
	if(0)
		daemonize();

	url_data_array = alloca(IP_SUM * sizeof(user_url_data_t));
	if(url_data_array == NULL)
	{
		log_error_write(__func__, __LINE__, "s", "lack of memory");
		abort();
	}
	/**init*/
	init_url_array(url_data_array, IP_SUM);

	/*progressing*/
	log_error_write(__func__, __LINE__, "s", "Init Success");
	while(!is_exit)
	{
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		is_everything_over = true;
		nfds = 0;
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = interval;

		/*init link*/
		for(i = 0; i < IP_SUM; i++)
		{
			if(url_data_array[i].connect_status == CONNECT_STATUS_NOTLOOP)
			{
				continue;
			}
			is_everything_over = false;
			if(url_data_array[i].urlparse != NULL &&
					url_data_array[i].connect_status == CONNECT_STATUS_CLOSE)
			{
				url_data_array[i].sock = connect_to_host (url_data_array[i].urlparse->host, url_data_array[i].urlparse->port);
				if(url_data_array[i].sock < 0)
				{
					url_data_array[i].connect_status = CONNECT_STATUS_NOTLOOP;
					log_error_write(__func__, __LINE__, "ssds", "Connect to ",url_data_array[i].urlparse->host, url_data_array[i].urlparse->port ," failed");
					continue;
					//return -1;
				}
				url_data_array[i].connect_status = CONNECT_STATUS_CONNECTING;
			}

		    if(url_data_array[i].sock >= 0 &&
		    		(url_data_array[i].connect_status == CONNECT_STATUS_CONNECTED ||
		    				url_data_array[i].connect_status == CONNECT_STATUS_UNAUTHORIZED) &&
		    		request_send(url_data_array[i].req, url_data_array[i].sock) < 0)
		    {
		    	log_error_write(__func__, __LINE__, "sbs", "Send data to ",url_data_array[i].urloriginal," failed");
		    	url_data_array[i].connect_status = CONNECT_STATUS_ERROR;
		    	continue;
		    }
		    else if(url_data_array[i].connect_status == CONNECT_STATUS_UNAUTHORIZED)
		    {
		    	url_data_array[i].connect_status = CONNECT_STATUS_AUTHORIZATION_SENT;
		    }
		    else if(url_data_array[i].connect_status == CONNECT_STATUS_CONNECTING)
		    {
		    	FD_SET(url_data_array[i].sock, &wfds);
		    	nfds = MAX(nfds, url_data_array[i].sock + 1);
		    	continue;
		    }
		    else
		    {
		    	url_data_array[i].connect_status = CONNECT_STATUS_REQUEST_SENT;
		    }
			FD_SET(url_data_array[i].sock, &rfds);
			nfds = MAX(nfds, url_data_array[i].sock + 1);
		}

		if(true == is_everything_over)
		{
			break;
		}
		/*select progressing*/
		{
			if(nfds == 0)
			{
				for(i = 0; i < IP_SUM; i++)
				{
					if(url_data_array[i].connect_status == CONNECT_STATUS_NOTLOOP)
					{
						continue;
					}
				}
				log_error_write(__func__, __LINE__, "s", "no link to watch");
				continue;
			}
			retval = select(nfds, &rfds, &wfds, NULL, &timeout);
			if(retval == -1)
			{
				log_error_write(__func__, __LINE__, "s", "select error");
				continue;
			}
			else if(retval == 0)
			{
				log_error_write(__func__, __LINE__, "s", "select timeout");
				continue;
			}
			for(i = 0; i < IP_SUM && retval > 0; i++)
			{
				if(url_data_array[i].connect_status == CONNECT_STATUS_ERROR ||
						url_data_array[i].connect_status == CONNECT_STATUS_CLOSE ||
						url_data_array[i].connect_status == CONNECT_STATUS_NOTLOOP)
				{
					continue;
				}

				if(FD_ISSET(url_data_array[i].sock, &wfds))
				{
					if(is_sock_connected(url_data_array[i].sock))
					{
						int flags;
						/*
						log_error_write(__func__, __LINE__, "s", "Link Succeed");
						*/
						flags = fcntl(url_data_array[i].sock, F_GETFL, 0);
						fcntl(url_data_array[i].sock, F_SETFL, flags & ~O_NONBLOCK);
						url_data_array[i].connect_status = CONNECT_STATUS_CONNECTED;
					}
					else
					{/*
						log_error_write(__func__, __LINE__, "s", "Link failed");
						*/
						url_data_array[i].connect_status = CONNECT_STATUS_NOTLOOP;
					}
					continue;
				}
				else if(url_data_array[i].sock > 0 &&
						FD_ISSET(url_data_array[i].sock, &rfds))
				{
					int sock = url_data_array[i].sock;
					char *head = NULL;
					struct http_stat *http_status = &url_data_array[i].http_status;
					retval--;
					head = read_http_response_head (sock);
					if(head == NULL || head[0] == '\0')
					{
						fprintf(stderr, "%s %d respond head is empty\n", __func__, __LINE__);
						log_error_write(__func__, __LINE__, "s", "respond head is empty");
						url_data_array[i].connect_status = CONNECT_STATUS_ERROR;
						continue;
					}
					get_response_head_stat(head, http_status);
					get_response_body(&url_data_array[i]);

					if(http_status->stat_code == HTTP_STATUS_UNAUTHORIZED &&
							url_data_array[i].connect_status != CONNECT_STATUS_AUTHORIZATION_SENT &&
							url_data_array[i].urlparse->user && url_data_array[i].urlparse->passwd)
					{
							if(http_status->WWWAuthenticate != NULL &&
									known_authentication_scheme_p(http_status->WWWAuthenticate))
							{
								log_error_write(__func__, __LINE__, "s", "Unauthorized, will send authorization page");
								url_data_array[i].connect_status = CONNECT_STATUS_UNAUTHORIZED;
								request_head_add_authorization_head(&url_data_array[i]);
								http_stat_data_free(&url_data_array[i].http_status);
								memset(&url_data_array[i].http_status, 0, sizeof(url_data_array[i].http_status));
								continue;
							}
					}
					else if(http_status->stat_code == HTTP_STATUS_UNAUTHORIZED)
					{
						log_error_write(__func__, __LINE__, "s", "Unauthorized");
						request_remove_header (url_data_array[i].req, "Authorization");
					}

					log_error_write(__func__, __LINE__, "d", http_status->stat_code);
					/*end of communication*/
					if((http_status->stat_code == HTTP_STATUS_OK || http_status->stat_code == HTTP_STATUS_NOT_FOUND) &&
							http_status->content_data != NULL&&
							http_status->server != NULL &&
							strcasecmp(http_status->server, "embed httpd") == 0)
					{
						fprintf(stderr, "%s\t%s\n", buffer_get_c_string(url_data_array[i].urloriginal), "Look like Yealink Device");
						log_error_write(__func__, __LINE__, "s", "Look like Yealink Device");
					}
					else if(http_status->stat_code == HTTP_STATUS_OK &&
							http_status->content_data != NULL)
					{
						JsonNode *json = NULL;
						JsonNode *node = NULL;
					//	fprintf(stderr, "%s\n", http_status->content_data);
						json = json_decode(http_status->content_data);
						if(json == NULL)
						{
							log_error_write(__func__, __LINE__, "s", "json == NULL");
						}
						else
						{
							node = json_find_member(json, "product_name");
							if(node != NULL)
							{
								char *str = NULL;
								if((str = json_stringify(node, NULL)) != NULL)
								{
									fprintf(stderr, "%s\t%s\t%s\n", buffer_get_c_string(url_data_array[i].urloriginal) + sizeof("http://admin:admin@") - 1,
											"Atcom Device", str);
									log_error_write(__func__, __LINE__, "sss",
											buffer_get_c_string(url_data_array[i].urloriginal),
											"Atcom Device", str);
									xfree(str);
								}
							}
							else
							{
								log_error_write(__func__, __LINE__, "s", "node == NULL");
							}
						}
						if(json != NULL)
						{
							json_delete(json);
							json = NULL;
						}
					}
					else if(http_status->stat_code == HTTP_STATUS_OK &&
							http_status->content_data == NULL)
					{
						log_error_write(__func__, __LINE__, "s", "Data is NULL");
					}
					if(http_status->connection_stat &&
							0 == strncasecmp(http_status->connection_stat, "Keep-Alive", sizeof("Keep-Alive") - 1) &&
							sock >= 0)
					{
						http_stat_data_free(&url_data_array[i].http_status);
						memset(&url_data_array[i].http_status, 0, sizeof(url_data_array[i].http_status));

						url_data_array[i].connect_status = CONNECT_STATUS_CONNECTED;
						continue;
					}
					else
					{
						log_error_write(__func__, __LINE__, "sd", "Will Over", url_data_array[i].connect_status);
						url_data_array[i].connect_status = CONNECT_STATUS_NOTLOOP;
					}
				}

			}
		}/*end select*/
		log_error_write(__func__, __LINE__, "s", "select over");
		/*clean*/
		for(i = 0; i < IP_SUM; i++)
		{
			if(url_data_array[i].connect_status == CONNECT_STATUS_ERROR ||
				url_data_array[i].connect_status == CONNECT_STATUS_CLOSE ||
				url_data_array[i].connect_status == CONNECT_STATUS_NOTLOOP)
			{
			http_stat_data_free(&url_data_array[i].http_status);
			memset(&url_data_array[i].http_status, 0, sizeof(url_data_array[i].http_status));
		/*
			request_remove_header (url_data_array[i].req, "Authorization");
			*/
			shutdown(url_data_array[i].sock, SHUT_RD);
			url_data_array[i].connect_status = CONNECT_STATUS_NOTLOOP;
			}
		}
		log_error_write(__func__, __LINE__, "s", "clean over");
		//sleep(1);
	}
	log_error_write(__func__, __LINE__, "s", "exec over");
	for(i = 0; i < IP_SUM; i++)
	{
		if(url_data_array[i].urloriginal != NULL)
		{
			buffer_free(url_data_array[i].urloriginal);
			url_data_array[i].urloriginal = NULL;
		}
		if(url_data_array[i].method != NULL)
		{
			buffer_free(url_data_array[i].method);
			url_data_array[i].method = NULL;
		}
		if(url_data_array[i].urlparse != NULL)
		{
			url_free(url_data_array[i].urlparse);
			url_data_array[i].urlparse = NULL;
		}
		url_data_array[i].connect_status = CONNECT_STATUS_NOTLOOP;
		if(url_data_array[i].req != NULL)
		{
			request_free(url_data_array[i].req);
			url_data_array[i].req = NULL;
		}
		if(url_data_array[i].sock > 0)
		{
			CLOSE_FD(url_data_array[i].sock);
		}
		http_stat_data_free(&url_data_array[i].http_status);
		memset(&url_data_array[i].http_status, 0, sizeof(url_data_array[i].http_status));
	}
	log_error_write(__func__, __LINE__, "s", "Everything is done, Goodbye");
	log_error_close();
	return 0;
}

