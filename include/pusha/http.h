#ifndef PUSHA_HTTP_HPP__
#define PUSHA_HTTP_HPP__

#include "web_push.h"
#include <stdlib.h> //size_t
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum{
	pusha_HTTPver_1_1 = 0,
	pusha_HTTPver_2
}Pusha_HTTP_Version;

/**
 * Holds a HTTP header
 */
typedef struct{
	const char*	key;		///< Header option
	char* 		value;		///< Option value
}pusha_http_header;

/**
 * Holds all the headers necessary to make a push request.
 */
typedef struct{
	char* 			start_line;		///< First line of the HTTP request
	pusha_http_header* 	headers;		///< Array of headers
	size_t			header_count;	///< Number of headers (size of the array abose)
	void*			body;			///< Encrypted body
	size_t			body_len;		///< Size of encrypted body
}pusha_http_request;

int make_http_request(pusha_http_request*,
					const char* endpoint,
					pusha_http_headers*,
					const void* cypher_payload, size_t payload_len,
					Pusha_HTTP_Version ver);

void free_http_header(pusha_http_header*);
void free_http_request(pusha_http_request*);

char* http_request_header_serialize(const char* endpoint,
		pusha_http_headers*,
		const void* cypher_payload, size_t payload_len,
		size_t* header_size);

uint8_t* http_request_serialize(const char* endpoint,
		pusha_http_headers*,
		const void* cypher_payload, size_t payload_len,
		size_t* packet_size);

uint8_t* http_request_serialize2(pusha_http_request*, size_t* packet_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_HTTP_HPP__ */
