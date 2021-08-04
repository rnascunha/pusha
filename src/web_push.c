#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vapid.h"
#include <ece.h>

int
make_web_push(const char* endpoint,
				const char* p256dh,
				const char* auth,
				struct vapid* token,
				const char* plaintext)
{
	size_t plaintextLen = strlen(plaintext);

	size_t padLen = 0;

	uint8_t rawRecvPubKey[ECE_WEBPUSH_PUBLIC_KEY_LENGTH];
	size_t rawRecvPubKeyLen =
	ece_base64url_decode(p256dh, strlen(p256dh), ECE_BASE64URL_REJECT_PADDING,
						 rawRecvPubKey, ECE_WEBPUSH_PUBLIC_KEY_LENGTH);
	assert(rawRecvPubKeyLen > 0);
	uint8_t authSecret[ECE_WEBPUSH_AUTH_SECRET_LENGTH];
	size_t authSecretLen =
	ece_base64url_decode(auth, strlen(auth), ECE_BASE64URL_REJECT_PADDING,
						 authSecret, ECE_WEBPUSH_AUTH_SECRET_LENGTH);
	assert(authSecretLen > 0);

	size_t ciphertextLen = ece_aesgcm_ciphertext_max_length(
							ECE_WEBPUSH_DEFAULT_RS, padLen, plaintextLen);
	assert(ciphertextLen > 0);
	uint8_t* ciphertext = calloc(ciphertextLen, sizeof(uint8_t));
	assert(ciphertext);

	// Encrypt the plaintext and fetch encryption parameters for the headers.
	// `salt` holds the encryption salt, which we include in the `Encryption`
	// header. `rawSenderPubKey` holds the ephemeral sender, or app server,
	// public key, which we include as the `dh` parameter in the `Crypto-Key`
	// header. `ciphertextLen` is an in-out parameter set to the actual ciphertext
	// length.
	uint8_t salt[ECE_SALT_LENGTH];
	uint8_t rawSenderPubKey[ECE_WEBPUSH_PUBLIC_KEY_LENGTH];
	int err = ece_webpush_aesgcm_encrypt(
		rawRecvPubKey, rawRecvPubKeyLen,
		authSecret, authSecretLen,
		ECE_WEBPUSH_DEFAULT_RS, padLen,
		plaintext, plaintextLen,
		salt, ECE_SALT_LENGTH,
		rawSenderPubKey, ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
		ciphertext, &ciphertextLen);
	assert(err == ECE_OK);

	// Build the `Crypto-Key` and `Encryption` HTTP headers. First, we pass
	// `NULL`s for `cryptoKeyHeader` and `encryptionHeader`, and 0 for their
	// lengths, to calculate the lengths of the buffers we need. Then, we
	// allocate, write out, and null-terminate the headers.
	size_t cryptoKeyHeaderLen = 0;
	size_t encryptionHeaderLen = 0;
	err = ece_webpush_aesgcm_headers_from_params(
						salt, ECE_SALT_LENGTH,
						rawSenderPubKey, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_WEBPUSH_DEFAULT_RS,
						NULL, &cryptoKeyHeaderLen,
						NULL, &encryptionHeaderLen);
	assert(err == ECE_OK);
	// Allocate an extra byte for the null terminator.
	char* cryptoKeyHeader = calloc(cryptoKeyHeaderLen + 1, 1);
	assert(cryptoKeyHeader);
	char* encryptionHeader = calloc(encryptionHeaderLen + 1, 1);
	assert(encryptionHeader);
	err = ece_webpush_aesgcm_headers_from_params(
						salt, ECE_SALT_LENGTH,
						rawSenderPubKey, ECE_WEBPUSH_PUBLIC_KEY_LENGTH, ECE_WEBPUSH_DEFAULT_RS,
						cryptoKeyHeader, &cryptoKeyHeaderLen,
						encryptionHeader, &encryptionHeaderLen);
	assert(err == ECE_OK);
	cryptoKeyHeader[cryptoKeyHeaderLen] = '\0';
	encryptionHeader[encryptionHeaderLen] = '\0';

	const char* filename = "aesgcm.bin";
	FILE* ciphertextFile = fopen(filename, "wb");
	assert(ciphertextFile);
	size_t ciphertextFileLen =
	fwrite(ciphertext, sizeof(uint8_t), ciphertextLen, ciphertextFile);
	assert(ciphertextLen == ciphertextFileLen);
	fclose(ciphertextFile);

	printf("curl -v -X POST -H \"Authorization: WebPush %s\" -H \"Content-Encoding: aesgcm\" -H \"Crypto-Key: "
		 "keyid=%s;p256ecdsa=%s;%s\" -H \"Encryption: %s\" -H \"TTL: 60\" --data-binary @%s %s\n",
		 token->token, p256dh, token->public_key,
		 cryptoKeyHeader, encryptionHeader, filename, endpoint);

	free(ciphertext);
	free(cryptoKeyHeader);
	free(encryptionHeader);

	return 0;
}
