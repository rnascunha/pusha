#ifndef PUSHA_WEB_PUSH_HPP__
#define PUSHA_WEB_PUSH_HPP__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int
make_web_push(const char* endpoint,
				const char* p256dh,
				const char* auth,
				struct vapid* token,
				const char* plaintext);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_WEB_PUSH_HPP__ */
