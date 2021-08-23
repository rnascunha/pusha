#ifndef PUSHA_MAIN_H__
#define PUSHA_MAIN_H__

#include "pusha/error.h"
#include "pusha/helper.h"
#include "pusha/ec_keys.h"
#include "pusha/vapid.h"
#include "pusha/web_push.h"
#include "pusha/http.h"
#include "pusha/debug.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \brief Create HTTP headers and encrypt payload
 *
 * @param headers[out]		holds HTTP headers necessary to make a push request
 * @param pp[out]			holds payload encrypt data necessary to make push request. Can be NULL if no payload
 * @param key[in]			EC key to encrypt/decrypt
 * @param endpoint[in]		Endpoint of user (received with subscription)
 * @param subscriber[in]	Contact information (a URL or a main, e.g "mailto:email@company.com")
 * @param p256dh[in]		Server public key (received with subscription)
 * @param auth[in]			Authentication secret (received with subscription)
 * @param expiration[in]	Time the push request is still valid
 * @param payload[in]		Payload of request (can be NULL if no payload)
 * @param payload_len[in]	Payload len (0 if no payload)
 * @return operation success or failure
 * @retval 0 success
 * @retval Other failure
 */
int pusha_notify(pusha_http_headers* headers,
			pusha_payload* pp,
			EC_KEY*	key,
			const char* endpoint,
			const char* subscriber,
			const char* p256dh,
			const char* auth,
			unsigned expiration,
			const void* payload,
			size_t payload_len);

/**
 * \brief Create HTTP headers and encrypt payload
 *
 * @param req[out]
 * @param key[in]			EC key to encrypt/decrypt
 * @param endpoint[in]		Endpoint of user (received with subscription)
 * @param subscriber[in]	Contact information (a URL or a main, e.g "mailto:email@company.com")
 * @param p256dh[in]		Server public key (received with subscription)
 * @param auth[in]			Authentication secret (received with subscription)
 * @param expiration[in]	Time the push notification is still valid
 * @param ttl				Time the push request will keep at the push service
 * @param payload[in]		Payload of request (can be NULL if no payload)
 * @param payload_len[in]	Payload len (0 if no payload)
 * @param ver				HTTP version (0: 1.1, 1: 2)
 * @return operation success or failure
 * @retval 0 success
 * @retval Other failure
 */
int pusha_notify_http(pusha_http_request* req,
			EC_KEY*	key,
			const char* endpoint,
			const char* subscriber,
			const char* p256dh,
			const char* auth,
			unsigned expiration,
			unsigned ttl,
			const void* payload,
			size_t payload_len,
			Pusha_HTTP_Version ver);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_MAIN_H__ */
