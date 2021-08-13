#ifndef PUSHA_HTTP_HPP__
#define PUSHA_HTTP_HPP__

#include "web_push.h"
#include <stdlib.h> //size_t
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum{
	HTTPver_1_1 = 0,
	HTTPver_2
}HTTP_Version;

/**
 * Holds a HTTP header
 */
typedef struct{
	const char*	key;		///< Header option
	char* 		value;		///< Option value
}http_header;

/**
 * Holds all the headers necessary to make a push request.
 */
typedef struct{
	char* 			start_line;		///< First line of the HTTP request
	http_header* 	headers;		///< Array of headers
	size_t			header_count;	///< Number of headers (size of the array abose)
	void*			body;			///< Encrypted body
	size_t			body_len;		///< Size of encrypted body
}http_request;

int make_http_request(http_request*,
					const char* endpoint,
					push_http_headers*,
					const void* cypher_payload, size_t payload_len,
					HTTP_Version ver);

void free_http_header(http_header*);
void free_http_request(http_request*);

char* http_request_header_serialize(const char* endpoint,
		push_http_headers*,
		const void* cypher_payload, size_t payload_len,
		size_t* header_size);

uint8_t* http_request_serialize(const char* endpoint,
		push_http_headers*,
		const void* cypher_payload, size_t payload_len,
		size_t* packet_size);

uint8_t* http_request_serialize2(http_request*, size_t* packet_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_HTTP_HPP__ */
