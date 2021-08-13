#include "pusha/helper.h"
#include <string.h>

size_t host_path_separator(const char* endpoint, char** host_start)
{
	char* host_init = strstr(endpoint, "://");
	if(!host_init) return 0;
	host_init += 3;
	if(host_start) *host_start = host_init;

	while(*host_init != '\0')
	{
		if(*host_init == '/')
			return host_start ? host_init - *host_start : host_init - endpoint;
		host_init++;
	}
	return 0;
}
