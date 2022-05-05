#include "pusha/debug.h"
#include "pusha/error.h"
#include "pusha/helper.h"

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef __unix__
#	include <unistd.h>
#	include <sys/socket.h>
#	include <netdb.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>

#	define SOCKET_TYPE		int
#	define CLOSE(x)	close(x)
#else
#	include <winsock2.h>
#	include <ws2tcpip.h>

#	define SOCKET_TYPE		SOCKET
#	define CLOSE(x)			closesocket(x)
#endif

static void print_array(const uint8_t* payload, size_t length, size_t break_line)
{
	for(size_t i = 0; i < length; i++)
	{
		if(i && break_line && (i % break_line) == 0) printf("\n");
		printf("%02X ", payload[i]);
	}
}

void print_http_request(const char* endpoint,
						size_t endpoint_len,
						pusha_http_headers* headers,
						const uint8_t* payload, size_t payload_len)
{
	if(headers->crypto_key_payload)
	{
		printf("> POST %.*s HTTP/1.1\n"
				"> Authorization: %.*s\n"
				"> Content-Length: %zu\n"
				"> Content-Encoding: aesgcm\n"
				"> Content-Type: application/octet-stream\n"
				"> Crypto-Key: %.*s;%.*s\n"
				"> Encryption: %.*s\n"
				"> TTL: %u\n",
				(int)endpoint_len, endpoint,
				(int)headers->authorization_len, headers->authorization,
				payload_len,
				(int)headers->crypto_key_len, headers->crypto_key,
				(int)headers->crypto_key_payload_len, headers->crypto_key_payload,
				(int)headers->encryption_len, headers->encryption,
				headers->ttl);
		if(payload_len)
		{
			printf("Body[%zu]:\n", payload_len);
			print_array(payload, payload_len, 20);
			printf("\n");
		}
	}
	else
	{
		printf("> POST %.*s HTTP/1.1\n"
				"> Authorization: %.*s\n"
				"> Crypto-Key: %.*s\n"
				"> TTL: %u\n"
				"> Content-Length: 0\n",
			(int)endpoint_len, endpoint,
			(int)headers->authorization_len, headers->authorization,
			(int)headers->crypto_key_len, headers->crypto_key,
			headers->ttl);
	}
}

void print_http_request2(pusha_http_request* req)
{
	printf("> %s\n", req->start_line);
	for(size_t i = 0; i < req->header_count; i++)
	{
		printf("> %s: %s\n", req->headers[i].key, req->headers[i].value);
	}
	if(req->body_len)
	{
		printf("Body[%zu]:\n", req->body_len);
		print_array(req->body, req->body_len, 20);
		printf("\n");
	}
}

char* curl_output(const char* endpoint,
		size_t endpoint_len,
		pusha_http_headers* headers,
		const void* cypher_payload,
		size_t payload_len)
{
	char* output;
	size_t size;

	if(payload_len)
	{
		const char* filename = "aesgcm.bin";
		FILE* ciphertextFile = fopen(filename, "wb");
		if(!ciphertextFile)
		{
			return NULL;
		}
		size_t ciphertextFileLen = fwrite(cypher_payload,
									sizeof(uint8_t), payload_len,
									ciphertextFile);
		fclose(ciphertextFile);
		if(payload_len != ciphertextFileLen)
		{
			return NULL;
		}

		size = snprintf(NULL, 0, "curl -v POST -H \"Authorization: %.*s\" -H \"Content-Encoding: aesgcm\" -H \"Crypto-Key: "
				 "%.*s;%.*s\" -H \"Encryption: %.*s\" -H \"TTL: %u\" --data-binary @%s %.*s",
					 (int)headers->authorization_len, headers->authorization,
					 (int)headers->crypto_key_len, headers->crypto_key,
					 (int)headers->crypto_key_payload_len, headers->crypto_key_payload,
					 (int)headers->encryption_len, headers->encryption,
					 headers->ttl,
					 filename,
					 (int)endpoint_len, endpoint);
		output = calloc(size + 1, 1);
		if(!output) return NULL;
		snprintf(output, size + 1, "curl -v POST -H \"Authorization: %.*s\" -H \"Content-Encoding: aesgcm\" -H \"Crypto-Key: "
				"%.*s;%.*s\" -H \"Encryption: %.*s\" -H \"TTL: %u\" --data-binary @%s %.*s",
					(int)headers->authorization_len, headers->authorization,
					(int)headers->crypto_key_len, headers->crypto_key,
					(int)headers->crypto_key_payload_len, headers->crypto_key_payload,
					(int)headers->encryption_len, headers->encryption,
					headers->ttl,
					filename,
					(int)endpoint_len, endpoint);
	}
	else
	{
		size = snprintf(NULL, 0, "curl -v POST -H \"Authorization: %.*s\" -H \"Crypto-Key: %.*s\" -H \"TTL: %u\" %.*s",
					(int)headers->authorization_len, headers->authorization,
					(int)headers->crypto_key_len, headers->crypto_key,
					headers->ttl,
					(int)endpoint_len, endpoint);
		output = calloc(size + 1, 1);
		if(!output) return NULL;
		snprintf(output, size + 1, "curl -v POST -H \"Authorization: %.*s\" -H \"Crypto-Key: %.*s\" -H \"TTL: %u\" %.*s",
				(int)headers->authorization_len, headers->authorization,
				(int)headers->crypto_key_len, headers->crypto_key,
				headers->ttl,
				(int)endpoint_len, endpoint);
	}

	return output;
}

static int response_handler(const void* buf, size_t len, int verbose)
{
	int ret = 0;
	PUSHA_PRINT(verbose, "*+ Received %zu bytes\n", len);
	char *res = strstr(buf, "HTTP/1.1 ");
	if(res)
	{
		res += 9; //strlen("HTTP/1.1 ");
		long code = strtol(res, NULL, 10);
		if(code > 0)
		{
			if((code / 100) == 2)
			{
				PUSHA_PRINT(verbose, "*+ Web push request sent successfully\n");
			}
			else
			{
				PUSHA_ERROR("*- ERROR sending Web push request\n");
				ret = 1;
			}
			char* s = memchr(res, '\n', len - 9);
			if(s)
			{
				PUSHA_PRINT(verbose, "> HTTP response: %.*s\n", (int)(s - res), res);
			}
		}
	}
	return ret;
}

int send_web_push(const char* endpoint,
		size_t endpoint_len,
		pusha_http_headers* headers,
		const void* cypher_payload, size_t payload_len,
		int verbose)
{
	int ret = ECE_OK;
	size_t request_len;

	/**
	 * Serializing HTTP request
	 */
	PUSHA_PRINT(verbose, "* Serializing request...\n");
	uint8_t* request = http_request_serialize(endpoint, endpoint_len, headers, cypher_payload, payload_len, &request_len);

	if(!request_len)
	{
		PUSHA_ERROR("*- Fail to serializing request...\n");
		ret = PUSHA_ERROR_SERIALIZE_HTTP_REQUEST;
		goto end;
	}
	PUSHA_PRINT(verbose, "*+ Request serialized\n");

	/**
	 * Finding host
	 */
	char* host;
	size_t sep = host_path_separator(endpoint, endpoint_len, &host);
	if(!sep)
	{
		PUSHA_ERROR("*- Endpoint error...\n");
		ret = PUSHA_ERROR_INVALID_ENDPOINT;
		goto end;
	}

	char* host_str = calloc(sep + 1, 1);
	if(!host_str)
	{
		PUSHA_ERROR("*- Allocation memory error\n");
		ret = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}
	memcpy(host_str, host, sep);
	host_str[sep] = '\0';

	struct addrinfo hints = {0}, *res, *result;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	PUSHA_PRINT(verbose, "* Searching for host %s\n", host_str);
	int err = getaddrinfo(host_str, NULL, &hints, &result);
	free(host_str);
	if(err)
	{
		PUSHA_ERROR("*- Failed getting host addr\n");
		ret = err;
		goto end;
	}

	SOCKET_TYPE sock = 0;
	char addr_str[100];
	for (res = result; res != NULL; res = res->ai_next)
	{
		sock = socket(res->ai_family,
					res->ai_socktype,
					res->ai_protocol);
		if (sock == -1) continue;

		if(res->ai_family == AF_INET)
			((struct sockaddr_in *)res->ai_addr)->sin_port = htons(443);
		else
			((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(443);

		PUSHA_PRINT(verbose, "* Trying to connect to %s\n",
						inet_ntop(res->ai_family, res->ai_family == AF_INET6 ?
						(void*)&((struct sockaddr_in6 *) res->ai_addr)->sin6_addr :
						(void*)&((struct sockaddr_in *) res->ai_addr)->sin_addr,
						addr_str, 100));
#if __unix__
		if (connect(sock, res->ai_addr, res->ai_addrlen) != -1)
#else
		if (connect(sock, res->ai_addr, (int)res->ai_addrlen) != -1)
#endif
			break;

		CLOSE(sock);
	}
	freeaddrinfo(result);

	if(res == NULL)
	{
		PUSHA_ERROR("*- Connect error\n");
		ret = PUSHA_ERROR_CONNECT;
		goto end;
	}
	PUSHA_PRINT(verbose, "*+ Connected\n");

	SSL_library_init();
	SSLeay_add_ssl_algorithms();
	const SSL_METHOD *meth = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new (meth);

	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		PUSHA_ERROR("*- Error creating SSL.\n");
		ret = PUSHA_ERROR_SSL_CREATE;
		SSL_CTX_free(ctx);
		goto end;
	}
#ifdef __unix__
	SSL_set_fd(ssl, sock);
#else
	SSL_set_fd(ssl, (int)sock);
#endif
	err = SSL_connect(ssl);
	if (err <= 0)
	{
		PUSHA_ERROR("*- SSL connection error [err=%x]\n", err);
		ret = PUSHA_ERROR_SSL_CONNECT;
		goto ssl_end;
	}
	PUSHA_PRINT(verbose, "*+ SSL connected using %s\n", SSL_get_cipher (ssl));

	/**
	 * Sending packet
	 */
	PUSHA_PRINT(verbose, "* Sending SSL packet\n");
	err = SSL_write(ssl, request, (int)request_len);
	if (err < 0)
	{
		PUSHA_ERROR("*- Error sending SSL packet [%d]\n", err);
		ret = PUSHA_ERROR_SSL_SEND;
		goto ssl_end;
	}
	PUSHA_PRINT(verbose, "*+ SSL packet sent[%d]\n", err);
	/**
	 * Receiving
	 */
	PUSHA_PRINT(verbose, "* Wating response...\n");
	char buf[1000];
	err = SSL_read(ssl, buf, 1000);
	if(err > 0)
	{
		/**
		 * Response hander
		 */
		ret = response_handler(buf, err, verbose);
	}
	else if (err < 0)
	{
		PUSHA_ERROR("*- Error receivind SSL packet[%d]\n", err);
		ret = PUSHA_ERROR_SSL_RECEIVE;
	}
ssl_end:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	CLOSE(sock);
end:
	free(request);
	return ret;
}
