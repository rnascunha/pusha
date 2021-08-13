#include "pusha/ec_keys.h"
#include "ece.h"
#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/obj_mac.h>

#include "pusha/error.h"

EC_KEY* generate_keys()
{
	EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!key)
	{
		return NULL;
	}

	if (EC_KEY_generate_key(key) != 1)
	{
		EC_KEY_free(key);
		return NULL;
	}
	return key;
}

void free_key(EC_KEY* key)
{
	EC_KEY_free(key);
}

EC_KEY* import_private_key2(const char* b64_string)
{
	printf("1\n");
	uint8_t octo[ECE_WEBPUSH_PRIVATE_KEY_LENGTH];
	size_t size = ece_base64url_decode(b64_string, strlen(b64_string), ECE_BASE64URL_REJECT_PADDING, octo, ECE_WEBPUSH_PRIVATE_KEY_LENGTH);
	printf("Size: %zu\n", size);
	if(!size)
	{
		return NULL;
	}

	printf("2\n");
	EC_KEY* key = EC_KEY_new();
	if(!key) return NULL;

	printf("3\n");
	if(!EC_KEY_oct2priv(key, octo, ECE_WEBPUSH_PRIVATE_KEY_LENGTH))
//	if(!EC_KEY_oct2key(key, octo, ECE_WEBPUSH_PRIVATE_KEY_LENGTH, NULL))
	{
		EC_KEY_free(key);
		return NULL;
	}

	printf("4\n");
	return key;
}

EC_KEY*
import_private_key(const char* b64PrivKeyPemFormat)
{
	size_t pv_key_len = strlen(b64PrivKeyPemFormat);
	BIO *mem = BIO_new(BIO_s_mem());
	if ((size_t)BIO_write(mem, b64PrivKeyPemFormat, pv_key_len) != pv_key_len)
	{
		return NULL;
	}

	EC_KEY *EC_KEY_ptr = PEM_read_bio_ECPrivateKey(mem , NULL, NULL, NULL);
	BIO_free_all(mem);

	if(EC_KEY_ptr == NULL)
	{
		return NULL;
	}

	if(EC_KEY_check_key(EC_KEY_ptr) == 0)
	{
		EC_KEY_free(EC_KEY_ptr);
	    return NULL;
	}
	return EC_KEY_ptr;
}

EC_KEY* import_private_key_pem_file(const char* path)
{
	FILE* fp = fopen(path, "rb");
	if(!fp)
	{
		return NULL;
	}
	EC_KEY *EC_KEY_ptr = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if(EC_KEY_ptr == NULL)
	{
		return NULL;
	}

	if(EC_KEY_check_key(EC_KEY_ptr) == 0)
	{
		EC_KEY_free(EC_KEY_ptr);
		return NULL;
	}

	return EC_KEY_ptr;
}

char* export_private_key(EC_KEY* key)
{
	uint8_t rawPrivKey[ECE_WEBPUSH_PRIVATE_KEY_LENGTH];
	if (!EC_KEY_priv2oct(key, rawPrivKey, ECE_WEBPUSH_PRIVATE_KEY_LENGTH))
	{
		return NULL;
	}
	size_t b64PrivKeyLen =
	ece_base64url_encode(rawPrivKey, ECE_WEBPUSH_PRIVATE_KEY_LENGTH,
						 ECE_BASE64URL_OMIT_PADDING, NULL, 0);
	if (!b64PrivKeyLen)
	{
		return NULL;
	}

	char* b64PrivKey = malloc(b64PrivKeyLen + 1);
	if (!b64PrivKey)
	{
		return NULL;
	}
	ece_base64url_encode(rawPrivKey, ECE_WEBPUSH_PRIVATE_KEY_LENGTH,
					   ECE_BASE64URL_OMIT_PADDING, b64PrivKey, b64PrivKeyLen);
	b64PrivKey[b64PrivKeyLen] = '\0';

	return b64PrivKey;
}

int export_private_key_pem(EC_KEY* key, const char* path)
{
	if(!key)
	{
		return PUSHA_ERROR_INVALID_KEY;
	}
	FILE* fp = NULL;

	fp = fopen(path, "wb");
	if(!fp)
	{
		return PUSHA_ERROR_OPEN_FILE;
	}
	if(!PEM_write_ECPrivateKey(fp, key, NULL, NULL, 0, NULL, NULL))
	{
		fclose(fp);
		return PUSHA_ERROR_WRITE_KEY;
	}
	fclose(fp);

	return ECE_OK;
}

int export_public_key_pem(EC_KEY* key, const char* path)
{
	if(!key)
	{
		return PUSHA_ERROR_INVALID_KEY;
	}
	FILE* fp = NULL;

	fp = fopen(path, "wb");
	if(!fp)
	{
		return PUSHA_ERROR_OPEN_FILE;
	}
	if(!PEM_write_EC_PUBKEY(fp, key))
	{
		fclose(fp);
		return PUSHA_ERROR_WRITE_KEY;
	}
	fclose(fp);

	return ECE_OK;
}

char* export_public_key(EC_KEY* key)
{
	uint8_t rawPubKey[ECE_WEBPUSH_PUBLIC_KEY_LENGTH];
	if (!EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
						  POINT_CONVERSION_UNCOMPRESSED, rawPubKey,
						  ECE_WEBPUSH_PUBLIC_KEY_LENGTH, NULL))
	{
		return NULL;
	}
	size_t b64PubKeyLen =
	ece_base64url_encode(rawPubKey, ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
						 ECE_BASE64URL_OMIT_PADDING, NULL, 0);
	char* b64PubKey = malloc(b64PubKeyLen + 1);
	if (!b64PubKey)
	{
		return NULL;
	}
	ece_base64url_encode(rawPubKey, ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
					   ECE_BASE64URL_OMIT_PADDING, b64PubKey, b64PubKeyLen);
	b64PubKey[b64PubKeyLen] = '\0';

	return b64PubKey;
}
