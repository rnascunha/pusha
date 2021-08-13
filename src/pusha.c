#include "pusha.h"
#include <string.h>

int pusha(push_http_headers* headers,
			push_payload* pp,
			EC_KEY*	key,
			const char* endpoint,
			const char* subscriber,
			const char* p256dh,
			const char* auth,
			unsigned expiration,
			const void* payload,
			size_t payload_len)
{
	if(payload_len && pp == NULL)
	{
		return PUSHA_ERROR_WRONG_ARGUMENTS;
	}

	size_t sep = host_path_separator(endpoint, NULL);
	if(!sep)
	{
		return PUSHA_ERROR_INVALID_ENDPOINT;
	}

	push_subscription nsub = {};
	if(!decode_subscription(&nsub, endpoint, p256dh, auth))
	{
		return PUSHA_ERROR_DECODE_SUBSCRIPTION;
	}

	int ret = ECE_OK;
	vapid token = {};
	if(!generate_vapid(&token, endpoint, sep, subscriber, strlen(subscriber), expiration, key))
	{
		return PUSHA_ERROR_GENERATE_VAPID;
	}

	if(payload_len)
	{
		if(make_push_payload(pp, &nsub, payload, payload_len, 0) != ECE_OK)
		{
			ret = PUSHA_ERROR_MAKE_PAYLOAD;
			goto end;
		}
	}

	if(make_push_http_headers(headers, &token, payload_len ? pp : NULL) != ECE_OK)
	{
		ret = PUSHA_ERROR_MAKE_HTTP_HEADERS;
		goto end;
	}
end:
	free_vapid(&token);

	return ret;
}

int pusha_http(http_request* req,
			EC_KEY*	key,
			const char* endpoint,
			const char* subscriber,
			const char* p256dh,
			const char* auth,
			unsigned expiration,
			unsigned ttl,
			const void* payload,
			size_t payload_len,
			HTTP_Version ver)
{
	push_payload pp = {};
	push_http_headers headers = {};
	headers.ttl = ttl;

	int err = pusha(&headers,
			&pp,
			key,
			endpoint,
			subscriber,
			p256dh,
			auth,
			expiration,
			payload,
			payload_len);

	if(err != ECE_OK)
	{
		goto end;
	}

	if(!make_http_request(req, endpoint, &headers, pp.cipher_payload, pp.cipher_payload_len, ver))
	{
		err = PUSHA_ERROR_MAKE_HTTP_REQUEST;
	}
end:
	free_push_payload(&pp);
	free_push_http_headers(&headers);

	return err;
}
