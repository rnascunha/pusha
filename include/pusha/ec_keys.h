#ifndef PUSHA_EC_KEY_HPP__
#define PUSHA_EC_KEY_HPP__

#include <openssl/ec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

EC_KEY* generate_keys();
void free_key(EC_KEY*);

EC_KEY* import_private_key_base64(const char* b64_string);
EC_KEY* import_private_key(const char* b64PrivKeyPemFormat);
EC_KEY* import_private_key_pem_file(const char* path);

char* export_private_key(EC_KEY* key);
char* export_public_key(EC_KEY* key);

int export_private_key_pem(EC_KEY* key, const char* path);
int export_public_key_pem(EC_KEY* key, const char* path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUSHA_EC_KEY_HPP__ */
