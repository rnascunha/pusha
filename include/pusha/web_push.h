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
	uint8_t		p256dh[ECE_WEBPUSH_PUBLIC_KEY_LENGTH];
	uint8_t		auth[ECE_WEBPUSH_AUTH_SECRET_LENGTH];
}pusha_subscription;

typedef struct{
	const char*	endpoint;
	char*		p256dh;
	char*		auth;
}pusha_subscription_base64;

bool decode_subscription(pusha_subscription* sub,
						const char* endpoint,
						const char* p256dh_base64,
						const char* auth_base64);

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
	char* 		crypto_key;				///< HTTP Crypto-Key header
	char* 		crypto_key_payload;		///< HTTP Crypto-Key header. Only used with payload (in conjuction with above header)
	unsigned 	ttl;					///< HTTP TTL header. Time that the push request will keep at the push service
	char* 		encryption;				///< HTTP Encrpytion header. Only used with payload
}pusha_http_headers;

void free_pusha_http_headers(pusha_http_headers*);

int make_pusha_http_headers(pusha_http_headers* headers,
					vapid* token,
					pusha_payload* pp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_WEB_PUSH_HPP__ */
