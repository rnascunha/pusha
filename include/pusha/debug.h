#ifndef PUSHA_DEBUG_HPP__
#define PUSHA_DEBUG_HPP__

#include "web_push.h"
#include "http.h"
#include <stdlib.h> //size_t
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void print_http_request(const char* endpoint, pusha_http_headers* headers,
						const uint8_t* payload, size_t payload_len);
void print_http_request2(pusha_http_request* req);

char* curl_output(const char* endpoint,
		pusha_http_headers*,
		const void* cypher_payload, size_t payload_len);

int send_web_push(const char* endpoint,
		pusha_http_headers*,
		const void* cypher_payload, size_t payload_len,
		int verbose);

#define PUSHA_PRINT(verbose, ...)	if(verbose) fprintf(stdout, __VA_ARGS__);
#define PUSHA_ERROR(...)			fprintf(stderr, __VA_ARGS__);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_DEBUG_HPP__ */
