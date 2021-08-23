#ifndef PUSHA_WEB_PUSH_HPP__
#define PUSHA_WEB_PUSH_HPP__

#include <stdint.h>
#include "vapid.h"
#include <ece.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct{
	const char* endpoint;
	size_t		endpoint_len;
	uint8_t		p256dh[ECE_WEBPUSH_PUBLIC_KEY_LENGTH];
	uint8_t		auth[ECE_WEBPUSH_AUTH_SECRET_LENGTH];
}pusha_subscription;

typedef struct{
	const char*	endpoint;
	size_t		endpoint_len;
	char*		p256dh;
	char*		auth;
}pusha_subscription_base64;

bool decode_subscription(pusha_subscription* sub,
						const char* endpoint,
						size_t endpoint_len,
						const char* p256dh_base64,
						size_t p256dh_b64_len,
						const char* auth_base64,
						size_t auth_b64_len);

bool encode_subscription(pusha_subscription_base64* sub_b64,
							pusha_subscription* sub);

void free_pusha_subscription_base64(pusha_subscription_base64* sub_b64);

/**
 * Encrypted payload used to make push request with payload
 */
typedef struct {
	uint8_t		salt[ECE_SALT_LENGTH];		///< Salt.
	uint8_t		sender_public_key[ECE_WEBPUSH_PUBLIC_KEY_LENGTH];	///< Server public key
	uint8_t		*cipher_payload;			///< Encrpyted payload
	size_t		cipher_payload_len;			///< Length of the encrypted payload
}pusha_payload;

int make_pusha_payload(pusha_payload*,
						pusha_subscription*,
						const void* payload, size_t payload_len,
						size_t pad_len);
void free_pusha_payload(pusha_payload*);

/**
 * Information of the HTTP headers necessary to make a push request
 */
typedef struct{
	char* 		authorization;			///< HTTP Authorization header
	size_t		authorization_len;		///< HTTP Authorization header length
	char* 		crypto_key;				///< HTTP Crypto-Key header
	size_t		crypto_key_len;			///< HTTP Crypto-Key header length
	char* 		crypto_key_payload;		///< HTTP Crypto-Key header. Only used with payload (in conjuction with above header)
	size_t		crypto_key_payload_len;	///< HTTP Crypto-Key payload header length
	unsigned 	ttl;					///< HTTP TTL header. Time that the push request will keep at the push service
	char* 		encryption;				///< HTTP Encrpytion header. Only used with payload
	size_t		encryption_len;			///< HTTP Encrpytion header length
}pusha_http_headers;

void free_pusha_http_headers(pusha_http_headers*);

int make_pusha_http_headers(pusha_http_headers* headers,
					vapid* token,
					pusha_payload* pp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_WEB_PUSH_HPP__ */
