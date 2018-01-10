#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include "config.h"

bool is_empty_line(char *file_line)
{
	int i = 0;
	while(file_line[i] == ' ' && file_line[i] == '\t')
	{
		i++;
	}
	if(file_line[i] == '\0' || file_line[i] == '\n')
	{
		return true;
	}
	return false;
}
static void skip_space(char *sp)
{
	const char *s = sp;
	while (isspace(*s))
		s++;
	memmove(sp, s, strlen(s) + 1);
}
cfg_stock_t *cfg_parser(char *file_name)
{
	FILE *fp = NULL;
	char file_line[1024] = "";
	cfg_stock_t *cfg_head = NULL;
	if((fp = fopen(file_name, "r")) == NULL)
	{
		fprintf(stderr, "%s %d fopen %s error: %s\n", __func__, __LINE__, file_name, strerror(errno));	
		return NULL;
	}
	while(fgets(file_line, sizeof(file_line), fp) != NULL)
	{
		cfg_stock_t *cfg_p = NULL;
		skip_space(file_line);
		if(is_empty_line(file_line) || file_line[0] == '#')
		{
			continue;
		}
		cfg_p = malloc(sizeof(cfg_stock_t));
		if(cfg_p == NULL)
			abort();
		memcpy(cfg_p->stock_cur_price, "0.0", sizeof(cfg_p->stock_cur_price));
		memcpy(cfg_p->stock_inc_rate, "0", sizeof(cfg_p->stock_inc_rate));
		if(sscanf(file_line, "%16s %10s", cfg_p->stock_name, cfg_p->stock_code) != 2)
		{
			cfg_free(cfg_head);
			fprintf(stderr, "%s %d format %s error: %s\n", __func__, __LINE__, file_name, strerror(errno));	
			goto ERR;
		}
		if(strlen(cfg_p->stock_code) > 10)
		{
			free(cfg_p);
			cfg_p = NULL;
			continue;
		}
		cfg_p->next = cfg_head;
		cfg_head = cfg_p;
	}
	if(fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
	return cfg_head;
ERR:
	if(fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
	return NULL;
}
void cfg_free(cfg_stock_t *head)
{
	if(head != NULL)
	{
		cfg_free(head->next);
		free(head);
	}
	return ;
}
int getCfgSize(cfg_stock_t *head)
{
	int i = 0;
	while(head != NULL)
	{
		i++;
		head = head->next;
	}
	return i;
}
