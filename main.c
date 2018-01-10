#include "util.h"
#include "http.h"
#include "config.h"
#include "buffer.h"
#include "httpstatus.h"
#include "json.h"
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
	struct http_stat *http_status = NULL;
	cfg_stock_t *cfg_head = NULL, *cfg_p = NULL;
	char url[1024] = "";


	set_signal_handler (SIGCHLD, signal_handler);
	set_signal_handler (SIGINT, signal_handler);

	cfg_head = cfg_parser("./getInfoFromWeb.conf");
	if(cfg_head == NULL)
	{
		fprintf(stderr, "configure file is empty\n");
		return -1;
	}

	log_error_open();

	daemonize();

	while(!is_exit)
	{
	for(cfg_p = cfg_head; cfg_p != NULL; )
	{
		if(snprintf(url, sizeof(url), "http://d.10jqka.com.cn/v2/realhead/%s/last.js", cfg_p->stock_code) > sizeof(url))
		{
			fprintf(stderr, "stock code too long\n");
			cfg_free(cfg_head);
			return -1;
		}
	if((http_status = get_url_stat(url)) != NULL)
	{
#if 1
		if(http_status->stat_code == HTTP_STATUS_OK)
		{
			JsonNode *json = NULL;
			char *items = NULL, *end = NULL;
			if((items = strstr(http_status->content_data, "\"items\"")) != NULL &&
					(end = strchr(items, '}')) != NULL)
			{
				char *p = NULL;
				items+=sizeof("\"items\":") - 1;
				end[1] = '\0';
		//		printf("%s\n", items);
				json = json_decode(items);
				if(json == NULL)
				{
					printf("json == NULL\n");
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
	//				printf("%s%10s%10s%10s%%\n", cfg_p->stock_name, cfg_p->stock_code, json_encode(json_find_member(json, "10")), json_encode(json_find_member(json, "199112")));
					if(cfg_p->stock_cur_price[0] != '\0')
					{
						log_error_write(__func__, __LINE__, "ssss", cfg_p->stock_name, cfg_p->stock_cur_price, "%", cfg_p->stock_inc_rate);
						//fprintf(stderr, "%s%10s%10s%10s%% %s\n", cfg_p->stock_name, cfg_p->stock_code, cfg_p->stock_cur_price, cfg_p->stock_inc_rate, http_status->connection_stat);
						//fprintf(stderr, "%s%10s\n", cfg_p->stock_cur_price, cfg_p->stock_inc_rate);
					}
					json_delete(json);
				}
			}
			cfg_p = cfg_p->next;
		}
		else if(http_status->stat_code == HTTP_STATUS_FORBIDDEN)
		{
	//		fprintf(stderr, "head = %s\n", http_status->respond_head);
	//		fprintf(stderr, "%s%10s\n", cfg_p->stock_cur_price, cfg_p->stock_inc_rate);
			//fprintf(stderr, "%s%10s\n", cfg_p->stock_cur_price, cfg_p->stock_inc_rate);
		//	fprintf(stderr, "Visit the web Frequently, wait 20 seconds\n");
		//	sleep(20);
		}
		else
		{
			if(http_status->respond_head != NULL)
			{
				fprintf(stderr, "head = %s\n", http_status->respond_head);
			}
			else
			{
				fprintf(stderr, "Unkonw error\n");
			}
			sleep(10);
		}
#endif
#if 0
		fprintf(stderr, "stat_code: %d\n", http_status->stat_code);
		fprintf(stderr, "content_len: %d\n", http_status->content_len);
		if(http_status->stat_data)
		{
			fprintf(stderr, "stat_data: %s\n", http_status->stat_data);
		}
		if(http_status->location)
		{
			fprintf(stderr, "Location: %s\n", http_status->location);
		}
		if(http_status->WWWAuthenticate)
		{
			fprintf(stderr, "WWWAuthenticate: %s\n", http_status->WWWAuthenticate);
		}
		if(http_status->ContentType)
		{
			fprintf(stderr, "ContentType: %s\n", http_status->ContentType);
		}
		if(http_status->content_data)
		{
			//fprintf(stderr, "content_data: %s\n", http_status->content_data);
			if(dump_to_file(http_status->content_data, http_status->content_len, "test"))
			{
				fprintf(stderr, "content data dump to file success\n");
			}
			else
			{
				fprintf(stderr, "content data dump to file failed\n");
			}
		}
#endif
	}
	http_stat_free(http_status);
	http_status = NULL;
	}
	sleep(10);
	}
	http_stat_free(http_status);
	http_status = NULL;
	cfg_free(cfg_head);

	log_error_close();
	return 0;
}

