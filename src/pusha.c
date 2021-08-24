#include "pusha.h"
#include <string.h>
#include <stdio.h>

int pusha_notify(pusha_http_headers* headers,
			pusha_payload* pp,
			EC_KEY*	key,
			const char* endpoint, size_t endpoint_len,
			const char* subscriber, size_t subscriber_len,
			const char* p256dh, size_t p256dh_len,
			const char* auth, size_t auth_len,
			unsigned expiration,
			const void* payload, size_t payload_len)
{
	if(payload_len && pp == NULL)
	{
		return PUSHA_ERROR_WRONG_ARGUMENTS;
	}

	size_t sep = host_path_separator(endpoint, endpoint_len, NULL);
	if(!sep)
	{
		return PUSHA_ERROR_INVALID_ENDPOINT;
	}

	pusha_subscription nsub = {0,};
	if(!decode_subscription(&nsub,
			endpoint, endpoint_len,
			p256dh, p256dh_len,
			auth, auth_len))
	{
		return PUSHA_ERROR_DECODE_SUBSCRIPTION;
	}

	int ret = ECE_OK;
	vapid token = {0,};
	if(!generate_vapid(&token, endpoint, sep, subscriber, subscriber_len, expiration, key))
	{
		return PUSHA_ERROR_GENERATE_VAPID;
	}

	if(payload_len)
	{
		if(make_pusha_payload(pp, &nsub, payload, payload_len, 0) != ECE_OK)
		{
			ret = PUSHA_ERROR_MAKE_PAYLOAD;
			goto end;
		}
	}

	if(make_pusha_http_headers(headers, &token, payload_len ? pp : NULL) != ECE_OK)
	{
		ret = PUSHA_ERROR_MAKE_HTTP_HEADERS;
		goto end;
	}
end:
	free_vapid(&token);

	return ret;
}

int pusha_notify_http(pusha_http_request* req,
			EC_KEY*	key,
			const char* endpoint, size_t endpoint_len,
			const char* subscriber, size_t subscriber_len,
			const char* p256dh, size_t p256dh_len,
			const char* auth, size_t auth_len,
			unsigned expiration,
			unsigned ttl,
			const void* payload,
			size_t payload_len,
			Pusha_HTTP_Version ver)
{
	pusha_payload pp = {0,};
	pusha_http_headers headers = {0,};
	headers.ttl = ttl;

	int err = pusha_notify(&headers,
			&pp,
			key,
			endpoint, endpoint_len,
			subscriber, subscriber_len,
			p256dh, p256dh_len,
			auth, auth_len,
			expiration,
			payload, payload_len);

	if(err != ECE_OK)
	{
		goto end;
	}

	if(!make_http_request(req, endpoint, endpoint_len, &headers, pp.cipher_payload, pp.cipher_payload_len, ver))
	{
		err = PUSHA_ERROR_MAKE_HTTP_REQUEST;
	}
end:
	free_pusha_payload(&pp);
	free_pusha_http_headers(&headers);

	return err;
}
