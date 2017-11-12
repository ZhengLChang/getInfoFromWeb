#ifndef _CONFIG_
#define _CONFIG_

typedef struct cfg_stock
{
	char stock_name[64];
	char stock_code[64];
	char stock_cur_price[64];
	char stock_inc_rate[64];
	struct cfg_stock *next;
}cfg_stock_t;

cfg_stock_t *cfg_parser(char *file_name);
void cfg_free(cfg_stock_t *head);
#endif
