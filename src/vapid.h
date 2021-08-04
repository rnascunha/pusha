#ifndef PUSHA_VAPID_HPP__
#define PUSHA_VAPID_HPP__

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct vapid{
	char* public_key;
	char* private_key;
	char* token;
};

bool make_vapid(struct vapid*, const char* audit, const char* sub, uint32_t exp, const char* b64_priv_key);

void destroy_vapid(struct vapid*);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* PUSHA_VAPID_HPP__ */
