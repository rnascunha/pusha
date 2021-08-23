#include "pusha/http.h"
#include <stdio.h>
#include <string.h>

#define HEADERS_COUNT_WITHOUT_PAYLOAD	4
#define HEADERS_COUNT_WITH_PAYLOAD		7

static const char* http_header_options[] = {
		"Authorization",
		"Content-Length",
		"TTL",
		"Crypto-Key",
		"Encryption",
		"Content-Type",
		"Content-Encoding"
};

static const char* http_content_type = "application/octet-stream";
static const char* http_content_encoding = "aesgcm";

static int make_header(pusha_http_header* header,
					const char* value, size_t value_len,
					const char* key)
{
	header->value = calloc(value_len + 1, 1);
	if(!header->value) return 0;

	memcpy(header->value, value, value_len);
	header->value[value_len] = '\0';
	header->key = key;

	return 1;
}

static int make_header_unsigned(pusha_http_header* header,
					unsigned value,
					const char* key)
{
	size_t value_len = snprintf(NULL, 0, "%u", value);
	header->value = calloc(value_len + 1, 1);
	if(!header->value) return 0;

	snprintf(header->value, value_len + 1, "%u", value);
	header->key = key;

	return 1;
}

static int make_header_crypto_encoding(
		pusha_http_header* header,
		pusha_http_headers* pheaders,
		const char* key)
{
	size_t value_len = snprintf(NULL, 0, "%s;%s", pheaders->crypto_key, pheaders->crypto_key_payload);

	header->value = calloc(value_len + 1, 1);
	if(!header->value) return 0;

	snprintf(header->value, value_len + 1, "%s;%s", pheaders->crypto_key, pheaders->crypto_key_payload);
	header->key = key;

	return 1;
}

static void init_http_request(pusha_http_request* req)
{
	req->start_line = NULL;
	req->headers = NULL;
	req->header_count = 0;
	req->body = NULL;
	req->body_len = 0;
}

int make_http_request(pusha_http_request* req,
						const char* endpoint,
						pusha_http_headers* headers,
						const void* cypher_payload, size_t payload_len,
						Pusha_HTTP_Version ver)
{
	init_http_request(req);
	int ret = 1;
	/**
	 * Start line
	 */
	size_t size = snprintf(NULL, 0, "POST %s HTTP/%s", endpoint, ver == pusha_HTTPver_2 ? "2" : "1.1");
	req->start_line = calloc(size + 1, 1);
	if(!req->start_line)
	{
		ret = 0;
		goto end;
	}
	snprintf(req->start_line, size + 1, "POST %s HTTP/%s", endpoint, ver == pusha_HTTPver_2 ? "2" : "1.1");
	/**
	 * Headers
	 */
	req->headers = calloc(payload_len ?
						HEADERS_COUNT_WITH_PAYLOAD :
						HEADERS_COUNT_WITHOUT_PAYLOAD, sizeof(pusha_http_header));

	if(!req->headers)
	{
		ret = 0;
		goto end;
	}
	if(!make_header(&req->headers[0], headers->authorization, strlen(headers->authorization), http_header_options[0]))
	{
		ret = 0;
		goto end;
	}
	req->header_count++;
	if(!make_header_unsigned(&req->headers[1], payload_len, http_header_options[1]))
	{
		ret = 0;
		goto end;
	}
	req->header_count++;
	if(!make_header_unsigned(&req->headers[2], headers->ttl, http_header_options[2]))
	{
		ret = 0;
		goto end;
	}
	req->header_count++;
	if(payload_len)
	{
		if(!make_header_crypto_encoding(&req->headers[3], headers, http_header_options[3]))
		{
			ret = 0;
			goto end;
		}
		req->header_count++;
		if(!make_header(&req->headers[4], headers->encryption, strlen(headers->encryption), http_header_options[4]))
		{
			ret = 0;
			goto end;
		}
		req->header_count++;
		if(!make_header(&req->headers[5], http_content_type, strlen(http_content_type), http_header_options[5]))
		{
			ret = 0;
			goto end;
		}
		req->header_count++;
		if(!make_header(&req->headers[6], http_content_encoding, strlen(http_content_encoding), http_header_options[6]))
		{
			ret = 0;
			goto end;
		}
		req->header_count++;
	}
	else
	{
		if(!make_header(&req->headers[3], headers->crypto_key, strlen(headers->crypto_key), http_header_options[3]))
		{
			ret = 0;
			goto end;
		}
		req->header_count++;
	}

	/**
	 * Body
	 */
	if(!payload_len)
	{
		//No body
		goto end;
	}

	req->body = calloc(payload_len, 1);
	if(!req->body)
	{
		ret = 0;
		goto end;
	}
	req->body_len = payload_len;
	memcpy(req->body, cypher_payload, payload_len);
end:
	if(!ret)
	{
		free_http_request(req);
	}
	return ret;
}

void free_http_header(pusha_http_header* header)
{
	header->key = NULL;
	free(header->value);
}


void free_http_request(pusha_http_request* req)
{
	free(req->start_line);
	if(req->body_len)
	{
		free(req->body);
		req->body_len = 0;
	}
	for(size_t i = 0; i < req->header_count; i++)
	{
		free_http_header(&req->headers[i]);
	}
	free(req->headers);
	req->headers = NULL;
	req->header_count = 0;
}

char* http_request_header_serialize(const char* endpoint,
		pusha_http_headers* headers,
		const void* cypher_payload, size_t payload_len,
		size_t* header_size)
{
	char* output;
	size_t size;
	if(header_size) *header_size = 0;

	if(payload_len)
	{
		size = snprintf(NULL, 0, "POST %s HTTP/1.1\r\n"
								"Authorization: %s\r\n"
								"Content-Length: %zu\r\n"
								"Content-Encoding: aesgcm\r\n"
								"Content-Type: application/octet-stream\r\n"
								"Crypto-Key: %s;%s\r\n"
								"Encryption: %s\r\n"
								"TTL: %u\r\n"
								"\r\n",
				endpoint,
				headers->authorization,
				payload_len,
				headers->crypto_key, headers->crypto_key_payload,
				headers->encryption,
				headers->ttl);
		output = calloc(size + 1, 1);
		if(!output) return NULL;
		snprintf(output, size + 1, "POST %s HTTP/1.1\r\n"
										"Authorization: %s\r\n"
										"Content-Length: %zu\r\n"
										"Content-Encoding: aesgcm\r\n"
										"Content-Type: application/octet-stream\r\n"
										"Crypto-Key: %s;%s\r\n"
										"Encryption: %s\r\n"
										"TTL: %u\r\n"
										"\r\n",
						endpoint,
						headers->authorization,
						payload_len,
						headers->crypto_key, headers->crypto_key_payload,
						headers->encryption,
						headers->ttl);
	}
	else
	{
		size = snprintf(NULL, 0, "POST %s HTTP/1.1\r\n"
								"Authorization: %s\r\n"
								"Crypto-Key: %s\r\n"
								"TTL: %u\r\n"
								"Content-Length: 0\r\n"
								"\r\n",
				endpoint,
				headers->authorization,
				headers->crypto_key,
				headers->ttl);
		output = calloc(size + 1, 1);
		if(!output) return NULL;
		snprintf(output, size + 1, "POST %s HTTP/1.1\r\n"
									"Authorization: %s\r\n"
									"Crypto-Key: %s\r\n"
									"TTL: %u\r\n"
									"Content-Length: 0\r\n"
									"\r\n",
						endpoint,
						headers->authorization,
						headers->crypto_key,
						headers->ttl);
	}

	if(header_size) *header_size = size;
	return output;
}

uint8_t* http_request_serialize(const char* endpoint,
		pusha_http_headers* headers,
		const void* cypher_payload, size_t payload_len,
		size_t* packet_size)
{
	size_t size;
	uint8_t* request = (uint8_t*)http_request_header_serialize(endpoint, headers,
												cypher_payload, payload_len,
												&size);
	if(packet_size) *packet_size = size;
	if(!request) return NULL;

	if(!payload_len)
		return request;

	uint8_t* mbuffer = realloc(request, size + payload_len);
	if(!mbuffer)
	{
		free(request);
		if(packet_size) *packet_size = 0;
		return NULL;
	}

	request = mbuffer;
	memcpy(request + size, cypher_payload, payload_len);

	if(packet_size) *packet_size = size + payload_len;
	return request;
}

uint8_t* http_request_serialize2(pusha_http_request* req, size_t* packet_size)
{
	size_t size = 0;
	if(packet_size) *packet_size = 0;

	size = strlen(req->start_line) + 2; //\r\n
	for(size_t i = 0; i < req->header_count; i++)
	{
		size += snprintf(NULL, 0, "%s: %s\r\n", req->headers[i].key, req->headers[i].value);
	}
	size += 2; //End of header \r\n
	size += req->body_len;

	uint8_t* request = calloc(size, 1);
	if(!request) return NULL;

	if(packet_size) *packet_size = size;

	size_t count = snprintf(request, size, "%s\r\n", req->start_line);;
	for(size_t i = 0; i < req->header_count; i++)
	{
		count += snprintf(request + count, size - count, "%s: %s\r\n", req->headers[i].key, req->headers[i].value);
	}
	count += snprintf(request + count, size - count, "\r\n"); //End of header \r\n

	if(req->body_len)
	{
		memcpy(request + count, req->body, size - count);
	}

	return request;
}

