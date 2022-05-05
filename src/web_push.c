#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pusha/error.h"
#include "pusha/web_push.h"
#include "pusha/vapid.h"

bool decode_subscription(pusha_subscription* sub,
						const char* endpoint,
						size_t endpoint_len,
						const char* p256dh_base64,
						size_t p256dh_b64_len,
						const char* auth_base64,
						size_t auth_b64_len)
{
	sub->endpoint = endpoint;
	sub->endpoint_len = endpoint_len;

	size_t p256_len = ece_base64url_decode(
								p256dh_base64, p256dh_b64_len, ECE_BASE64URL_REJECT_PADDING,
								sub->p256dh, ECE_WEBPUSH_PUBLIC_KEY_LENGTH);
	if(!p256_len) return false;

	size_t auth_len = ece_base64url_decode(
								auth_base64, auth_b64_len, ECE_BASE64URL_REJECT_PADDING,
								sub->auth, ECE_WEBPUSH_AUTH_SECRET_LENGTH);
	if(!auth_len) return false;

	return true;
}

bool encode_subscription(pusha_subscription_base64* sub_b64,
							pusha_subscription* sub)
{
	bool ret = true;

	sub_b64->endpoint = sub->endpoint;
	sub_b64->endpoint_len = sub->endpoint_len;

	size_t b64_p256dh_len = ece_base64url_encode(
	    sub->p256dh, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_BASE64URL_OMIT_PADDING, NULL, 0);
	sub_b64->p256dh = calloc(b64_p256dh_len + 1, sizeof(uint8_t));
	if(!sub_b64->p256dh)
	{
		ret = false;
		goto end;
	}
	ece_base64url_encode(
		    sub->p256dh, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_BASE64URL_OMIT_PADDING, sub_b64->p256dh, b64_p256dh_len);
	sub_b64->p256dh[b64_p256dh_len] = '\0';

	size_t b64_auth_len = ece_base64url_encode(
		sub->auth, ECE_WEBPUSH_AUTH_SECRET_LENGTH, ECE_BASE64URL_OMIT_PADDING, NULL, 0);
	sub_b64->auth = calloc(b64_auth_len + 1, sizeof(uint8_t));
	if(!sub_b64->auth)
	{
		ret = false;
		goto end;
	}
	ece_base64url_encode(
			sub->auth, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_BASE64URL_OMIT_PADDING, sub_b64->auth, b64_auth_len);
	sub_b64->auth[b64_auth_len] = '\0';

end:
	if(!ret)
		free_pusha_subscription_base64(sub_b64);

	return ret;
}

void free_pusha_subscription_base64(pusha_subscription_base64* sub_b64)
{
	free(sub_b64->p256dh);
	free(sub_b64->auth);

	memset(sub_b64, 0, sizeof(pusha_subscription_base64));
}

int make_pusha_payload(pusha_payload* pp,
						pusha_subscription* sub,
						const void* payload, size_t payload_len,
						size_t pad_len)
{
	pp->cipher_payload_len = ece_aesgcm_ciphertext_max_length(
								ECE_WEBPUSH_DEFAULT_RS, pad_len, payload_len);
	if(!pp->cipher_payload_len) return ECE_ERROR_ZERO_CIPHERTEXT;

	pp->cipher_payload = calloc(pp->cipher_payload_len, sizeof(uint8_t));
	if(!pp->cipher_payload) return ECE_ERROR_OUT_OF_MEMORY;

	int err = ece_webpush_aesgcm_encrypt(
		sub->p256dh, ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
		sub->auth, ECE_WEBPUSH_AUTH_SECRET_LENGTH,
		ECE_WEBPUSH_DEFAULT_RS, pad_len,
		payload, payload_len,
		pp->salt, ECE_SALT_LENGTH,
		pp->sender_public_key, ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
		pp->cipher_payload, &pp->cipher_payload_len);

	return err;
}

void free_pusha_payload(pusha_payload* payload)
{
	if(payload->cipher_payload_len)
		free(payload->cipher_payload);

	memset(payload, 0, sizeof(pusha_payload));
}

static int
make_encrypt_header(pusha_http_headers* headers,
					pusha_payload* pp)
{
	int err = ECE_OK;

	/* getting sizes of headers */
	err = ece_webpush_aesgcm_headers_from_params(
						pp->salt, ECE_SALT_LENGTH,
						pp->sender_public_key, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_WEBPUSH_DEFAULT_RS,
						NULL, &headers->crypto_key_payload_len,
						NULL, &headers->encryption_len);
	if(err != ECE_OK) goto end;
	// Allocate an extra byte for the null terminator.
	headers->crypto_key_payload = calloc(headers->crypto_key_payload_len, 1);
	if(!headers->crypto_key_payload)
	{
		err = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	headers->encryption = calloc(headers->encryption_len, 1);
	if(!headers->encryption)
	{
		err = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	err = ece_webpush_aesgcm_headers_from_params(
						pp->salt, ECE_SALT_LENGTH,
						pp->sender_public_key, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_WEBPUSH_DEFAULT_RS,
						headers->crypto_key_payload, &headers->crypto_key_payload_len,
						headers->encryption, &headers->encryption_len);
	if(err != ECE_OK)
		goto end;
end:
	if(err != ECE_OK)
	{
		free(headers->crypto_key_payload);
		free(headers->encryption);

		headers->crypto_key_payload = NULL;
		headers->crypto_key_payload_len = 0;
		headers->encryption = NULL;
		headers->encryption_len = 0;
	}

	return err;
}

#define P256ECDSA_HEADER "p256ecdsa="
#define P256ECDSA_HEADER_SIZE (sizeof(P256ECDSA_HEADER) - 1)

#define AUTHORIZATION_HEADER "WebPush "
#define AUTHORIZATION_HEADER_SIZE (sizeof(AUTHORIZATION_HEADER) - 1)

int make_pusha_http_headers(pusha_http_headers* headers,
					vapid* token,
					pusha_payload* pp)
{
	int ret = ECE_OK;

	if(pp)
	{
		//Headers specific to Push with payload
		ret = make_encrypt_header(headers, pp);
		if(ret != ECE_OK)
			goto end;
	}

	size_t str_len = strlen(token->public_key);
	headers->crypto_key_len = str_len + P256ECDSA_HEADER_SIZE;
	headers->crypto_key = calloc(headers->crypto_key_len, 1);
	if(!headers->crypto_key)
	{
		ret = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}
	memcpy(headers->crypto_key, P256ECDSA_HEADER, P256ECDSA_HEADER_SIZE);
	memcpy(headers->crypto_key + P256ECDSA_HEADER_SIZE, token->public_key, strlen(token->public_key));

	str_len = strlen(token->token);
	headers->authorization_len = AUTHORIZATION_HEADER_SIZE + str_len;
	headers->authorization = calloc(headers->authorization_len, 1);
	if(!headers->authorization)
	{
		ret = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}
	memcpy(headers->authorization, AUTHORIZATION_HEADER, AUTHORIZATION_HEADER_SIZE);
	memcpy(headers->authorization + AUTHORIZATION_HEADER_SIZE, token->token, str_len);
end:
	if(ret != ECE_OK)
	{
		free(headers->authorization);
		free(headers->crypto_key);

		headers->authorization = NULL;
		headers->authorization_len = 0;
		headers->crypto_key = NULL;
		headers->crypto_key_len = 0;
	}

	return ret;
}

void free_pusha_http_headers(pusha_http_headers* headers)
{
	free(headers->authorization);
	free(headers->crypto_key);
	free(headers->crypto_key_payload);
	free(headers->encryption);

	memset(headers, 0, sizeof(pusha_http_headers));
}

