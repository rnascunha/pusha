#ifndef PUSHA_HELPER_HPP__
#define PUSHA_HELPER_HPP__

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

size_t host_path_separator(const char* endpoint, char** host_start);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_HELPER_HPP__ */
