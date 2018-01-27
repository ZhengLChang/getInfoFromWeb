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


int main(int argc, char **argv)
{
	cfg_stock_t *cfg_head = NULL, *cfg_p = NULL;
	int i = 0, cfg_size = 0;
	user_url_data_t* url_data_array = NULL;
	time_t cur_time = 0, last_time = 0, interval = (2 * 60);
	fd_set rfds;
	struct timeval timeout;
	int retval = 0;
	int nfds = 0;
	int error_code = NO_ERROR;
	const char *p = NULL;
	int pid = 0;

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

	cfg_head = cfg_parser("./getInfoFromWeb.conf");
	if(cfg_head == NULL ||
			(cfg_size = getCfgSize(cfg_head)) == 0)
	{
		log_error_write(__func__, __LINE__, "s", "configure file is empty");
		return -1;
	}

	log_error_open();
	daemonize();


	/*init*/
	url_data_array = alloca(cfg_size * sizeof(user_url_data_t));
	if(url_data_array == NULL)
	{
		log_error_write(__func__, __LINE__, "s", "lack of memory");
		abort();
	}
	for(cfg_p = cfg_head, i = 0; i < cfg_size; i++, cfg_p = cfg_p->next)
	{
		int error_number = NO_ERROR;
		user_url_data_t *p = url_data_array + i;
		p->urloriginal = buffer_init_printf("http://d.10jqka.com.cn/v2/realhead/%s/last.js", cfg_p->stock_code);
		p->urlparse = url_parse(url_data_array[i].urloriginal->ptr, &error_number);
		p->connect_status = CONNECT_STATUS_CLOSE;
		p->method = buffer_init_string("GET");
		p->req = ini_request_head_without_auth(p->urlparse, buffer_get_c_string(p->method));
		p->cfg_p = cfg_p;
		p->sock = -1;
		memset(&p->http_status, 0, sizeof(p->http_status));
	}

	log_error_write(__func__, __LINE__, "s", "Init Success");
	while(!is_exit)
	{
		FD_ZERO(&rfds);
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = interval;

		for(i = 0; i < cfg_size; i++)
		{
			if(url_data_array[i].urlparse != NULL &&
					url_data_array[i].connect_status == CONNECT_STATUS_CLOSE)
			{
				url_data_array[i].sock = connect_to_host (url_data_array[i].urlparse->host, url_data_array[i].urlparse->port);
				if(url_data_array[i].sock < 0)
				{
					url_data_array[i].connect_status = CONNECT_STATUS_CLOSE;
					log_error_write(__func__, __LINE__, "sbs", "Connect to ",url_data_array[i].urloriginal," failed");
					continue;
				}
				url_data_array[i].connect_status = CONNECT_STATUS_CONNECTED;
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
		    else
		    {
		    	url_data_array[i].connect_status = CONNECT_STATUS_REQUEST_SENT;
		    }
			FD_SET(url_data_array[i].sock, &rfds);
			nfds = MAX(nfds, url_data_array[i].sock + 1);
		}
		{
			retval = select(nfds, &rfds, NULL, NULL, &timeout);
			if(retval == -1)
			{
				log_error_write(__func__, __LINE__, "s", "select error");
				continue;
			}
			else if(retval == 0)
			{
				log_error_write(__func__, __LINE__, "s", "select timeout");
			}
			for(i = 0; i < cfg_size && retval > 0; i++)
			{
				if(url_data_array[i].connect_status == CONNECT_STATUS_ERROR ||
						url_data_array[i].connect_status == CONNECT_STATUS_CLOSE)
				{
					continue;
				}
				if(url_data_array[i].sock > 0 &&
						FD_ISSET(url_data_array[i].sock, &rfds))
				{
					int sock = url_data_array[i].sock;
					char *head = read_http_response_head (sock);
					struct http_stat *http_status = &url_data_array[i].http_status;
					retval--;
					if(head == NULL || *head == '\0')
					{
						url_data_array[i].connect_status = CONNECT_STATUS_ERROR;
						continue;
					}
					get_response_head_stat(head, http_status);
					get_response_body(&url_data_array[i]);

					if(http_status->stat_code == HTTP_STATUS_UNAUTHORIZED &&
							url_data_array[i].connect_status != CONNECT_STATUS_AUTHORIZATION_SENT &&
							url_data_array[i].urlparse->user && url_data_array[i].urlparse->passwd)
					{
							if(known_authentication_scheme_p(http_status->WWWAuthenticate))
							{
								url_data_array[i].connect_status = CONNECT_STATUS_UNAUTHORIZED;
								request_head_add_authorization_head(&url_data_array[i]);
							}
					}
					else if(http_status->stat_code == HTTP_STATUS_UNAUTHORIZED)
					{
						log_error_write(__func__, __LINE__, "s", "Unauthorized");
						request_remove_header (url_data_array[i].req, "Authorization");
					}

					/*end of communication*/
					{
					cfg_p = url_data_array[i].cfg_p;
					if(http_status->stat_code == HTTP_STATUS_OK &&
							http_status->content_data != NULL)
					{
						JsonNode *json = NULL;
						char *items = NULL, *end = NULL;
						if((items = strstr(http_status->content_data, "\"items\"")) != NULL &&
								(end = strchr(items, '}')) != NULL)
						{
							char *p = NULL;
							items+=sizeof("\"items\":") - 1;
							end[1] = '\0';
							json = json_decode(items);
							if(json == NULL)
							{
								log_error_write(__func__, __LINE__, "s", "json == NULL\n");
							}
							else
							{
								JsonNode *node = json_find_member(json, "10");
								if(node != NULL)
								{
									if((p = json_stringify(node, NULL)) != NULL)
									{
										xmemcpy(cfg_p->stock_cur_price, sizeof(cfg_p->stock_cur_price) - 1, p, strlen(p) + 1);
										cfg_p->stock_cur_price[sizeof(cfg_p->stock_cur_price) - 1] = '\0';
										xfree(p);
									}
								}
								node = json_find_member(json, "199112");
								if(node != NULL)
								{
									if((p = json_stringify(node, NULL)) != NULL)
									{
										xmemcpy(cfg_p->stock_inc_rate, sizeof(cfg_p->stock_inc_rate) - 1, p, strlen(p) + 1);
										cfg_p->stock_inc_rate[sizeof(cfg_p->stock_inc_rate) - 1] = '\0';
										xfree(p);
									}
								}
								if(cfg_p->stock_cur_price[0] != '\0')
								{
									log_error_write(__func__, __LINE__, "ssss", cfg_p->stock_name, cfg_p->stock_cur_price, "%", cfg_p->stock_inc_rate);
								}
								json_delete(json);
							}
						}
					}
					else if(http_status->stat_code == HTTP_STATUS_OK &&
							http_status->content_data != NULL)
					{
						log_error_write(__func__, __LINE__, "s", "Data is NULL");
					}
					if(http_status->connection_stat && 0 == strncasecmp(http_status->connection_stat, "Keep-Alive", sizeof("Keep-Alive") - 1) &&
							sock >= 0)
					{
						http_stat_data_free(&url_data_array[i].http_status);
						memset(&url_data_array[i].http_status, 0, sizeof(url_data_array[i].http_status));

						url_data_array[i].connect_status = CONNECT_STATUS_CONNECTED;
						continue;
					}
					else
					{
						url_data_array[i].connect_status = CONNECT_STATUS_CLOSE;
					}
				}
				}

			}
		}/*end select*/
		for(i = 0; i < cfg_size; i++)
		{
			if(url_data_array[i].connect_status == CONNECT_STATUS_ERROR ||
				url_data_array[i].connect_status == CONNECT_STATUS_CLOSE)
			{
			http_stat_data_free(&url_data_array[i].http_status);
			memset(&url_data_array[i].http_status, 0, sizeof(url_data_array[i].http_status));
		/*
			request_remove_header (url_data_array[i].req, "Authorization");
			*/
			CLOSE_FD(url_data_array[i].sock);
			url_data_array[i].connect_status = CONNECT_STATUS_CLOSE;
			}
		}
		sleep(1);
	}
	for(i = 0; i < cfg_size; i++)
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
		url_data_array[i].connect_status = CONNECT_STATUS_CLOSE;
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
		url_data_array[i].cfg_p = NULL;
	}
	cfg_free(cfg_head);
	log_error_write(__func__, __LINE__, "s", "Everything is done, Goodbye");
	log_error_close();
	return 0;
}

