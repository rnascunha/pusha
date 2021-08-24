#ifndef PUSHA_VAPID_H__
#define PUSHA_VAPID_H__

#include <stdbool.h>
#include <stdint.h>
#include <openssl/ec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
	char* public_key;
	char* private_key;
	char* token;
}vapid;

bool generate_vapid(vapid*,
				const char* audit,
				size_t audit_len,
				const char* sub,
				size_t sub_len,
				uint32_t exp,
				EC_KEY* key);

void free_vapid(vapid*);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* PUSHA_VAPID_H__ */
