#include "pusha/helper.h"
#include <string.h>

//https://stackoverflow.com/a/25705264
static char
*strnstr(const char *haystack, const char *needle, size_t len)
{
	int i;
	size_t needle_len;

	if (0 == (needle_len = strnlen(needle, len)))
		return (char *)haystack;

	for (i=0; i<=(int)(len-needle_len); i++)
	{
		if ((haystack[0] == needle[0]) &&
				(0 == strncmp(haystack, needle, needle_len)))
				return (char *)haystack;

		haystack++;
	}
	return NULL;
}


size_t host_path_separator(const char* endpoint, size_t endpoint_len, char** host_start)
{
	char* host_init = strnstr(endpoint, "://", endpoint_len);
	if(!host_init) return 0;
	host_init += 3;
	if(host_start) *host_start = host_init;

	size_t size = endpoint_len - (host_init - endpoint);
	while(size--)
	{
		if(*host_init == '/')
			return host_start ? host_init - *host_start : host_init - endpoint;
		host_init++;
	}
	return 0;
}
