#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pusha/error.h"
#include "pusha/web_push.h"
#include "pusha/vapid.h"

bool decode_subscription(push_subscription* sub,
						const char* endpoint,
						const char* p256dh_base64,
						const char* auth_base64)
{
	sub->endpoint = endpoint;

	size_t p256_len = ece_base64url_decode(
								p256dh_base64, strlen(p256dh_base64), ECE_BASE64URL_REJECT_PADDING,
								sub->p256dh, ECE_WEBPUSH_PUBLIC_KEY_LENGTH);
	if(!p256_len) return false;

	size_t auth_len = ece_base64url_decode(
								auth_base64, strlen(auth_base64), ECE_BASE64URL_REJECT_PADDING,
								sub->auth, ECE_WEBPUSH_AUTH_SECRET_LENGTH);
	if(!auth_len) return false;

	return true;
}

bool encode_subscription(push_subscription_base64* sub_b64,
							push_subscription* sub)
{
	bool ret = true;

	sub_b64->endpoint = sub->endpoint;

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
		free_push_subscription_base64(sub_b64);

	return ret;
}

void free_push_subscription_base64(push_subscription_base64* sub_b64)
{
	free(sub_b64->p256dh);
	free(sub_b64->auth);

	memset(sub_b64, 0, sizeof(push_subscription_base64));
}

int make_push_payload(push_payload* pp,
						push_subscription* sub,
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

void free_push_payload(push_payload* payload)
{
	if(payload->cipher_payload_len)
		free(payload->cipher_payload);

	memset(payload, 0, sizeof(push_payload));
}

static int
make_encrypt_header(push_http_headers* headers,
					push_payload* pp)
{
	size_t cryptoKeyHeaderLen = 0;
	size_t encryptionHeaderLen = 0;
	int err = ECE_OK;

	/* getting sizes of headers */
	err = ece_webpush_aesgcm_headers_from_params(
						pp->salt, ECE_SALT_LENGTH,
						pp->sender_public_key, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_WEBPUSH_DEFAULT_RS,
						NULL, &cryptoKeyHeaderLen,
						NULL, &encryptionHeaderLen);
	if(err != ECE_OK) goto end;
	// Allocate an extra byte for the null terminator.
	headers->crypto_key_payload = calloc(cryptoKeyHeaderLen + 1, 1);
	if(!headers->crypto_key_payload)
	{
		err = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	headers->encryption = calloc(encryptionHeaderLen + 1, 1);
	if(!headers->encryption)
	{
		err = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	err = ece_webpush_aesgcm_headers_from_params(
						pp->salt, ECE_SALT_LENGTH,
						pp->sender_public_key, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_WEBPUSH_DEFAULT_RS,
						headers->crypto_key_payload, &cryptoKeyHeaderLen,
						headers->encryption, &encryptionHeaderLen);
	if(err != ECE_OK)
		goto end;

	headers->crypto_key_payload[cryptoKeyHeaderLen] = '\0';
	headers->encryption[encryptionHeaderLen] = '\0';
end:
	if(err != ECE_OK)
	{
		free(headers->crypto_key_payload);
		free(headers->encryption);

		headers->crypto_key_payload = NULL;
		headers->encryption = NULL;
	}

	return err;
}

int make_push_http_headers(push_http_headers* headers,
					vapid* token,
					push_payload* pp)
{
	int ret = ECE_OK;
	size_t size;

	if(pp)
	{
		//Headers specific to Push with payload
		ret = make_encrypt_header(headers, pp);
		if(ret != ECE_OK)
			goto end;
	}

	size = snprintf(NULL, 0, "p256ecdsa=%s", token->public_key);
	headers->crypto_key = calloc(size + 1, 1);
	if(!headers->crypto_key)
	{
		ret = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}
	snprintf(headers->crypto_key, size + 1, "p256ecdsa=%s", token->public_key);

	size = snprintf(NULL, 0, "WebPush %s", token->token);
	headers->authorization = calloc(size + 1, 1);
	if(!headers->authorization)
	{
		ret = ECE_ERROR_OUT_OF_MEMORY;
		goto end;
	}
	snprintf(headers->authorization, size + 1, "WebPush %s", token->token);
end:
	if(ret != ECE_OK)
	{
		free(headers->authorization);
		free(headers->crypto_key);

		headers->authorization = NULL;
		headers->crypto_key = NULL;
	}

	return ret;
}

void free_push_http_headers(push_http_headers* headers)
{
	free(headers->authorization);
	free(headers->crypto_key);
	free(headers->crypto_key_payload);
	free(headers->encryption);

	memset(headers, 0, sizeof(push_http_headers));
}

