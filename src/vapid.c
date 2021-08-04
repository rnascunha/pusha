#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

#include <ece.h>
#include <ece/keys.h>

#include "vapid.h"

#define VAPID_HEADER "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"
#define VAPID_HEADER_LENGTH 27

static const char vapid_hex_table[] = "0123456789abcdef";

// Indicates whether `c` is an ASCII control character, and must be escaped
// to appear in a JSON string.
static inline bool
vapid_json_escape_is_control(char c)
{
	return c >= '\0' && c <= '\x1f';
}

// Returns an escaped literal for a control character, double quote, or reverse
// solidus; `\0` otherwise.
static inline char
vapid_json_escape_literal(char c)
{
	switch (c)
	{
		case '\b':
			return 'b';
		case '\n':
			return 'n';
		case '\f':
			return 'f';
		case '\r':
			return 'r';
		case '\t':
			return 't';
		case '"':
		case '\\':
			return c;
	}
	return '\0';
}

// Writes a Unicode escape sequence for a control character.
static inline size_t
vapid_json_escape_unicode(char c, char* result)
{
	result[0] = '\\';
	result[1] = 'u';
	result[2] = '0';
	result[3] = '0';
	result[4] = vapid_hex_table[(c >> 4) & 0xf];
	result[5] = vapid_hex_table[c & 0xf];
	return 6;
}

// Returns the length of `str` as a JSON string, including room for double
// quotes and escape sequences for special characters.
static size_t
vapid_json_quoted_length(const char* str, size_t strLen) {
  // 2 bytes for the opening and closing quotes.
  size_t len = 2;
  for (size_t i = 0; i < strLen; i++) {
    if (vapid_json_escape_literal(str[i])) {
      // 2 bytes: "\", followed by the escaped literal.
      len += 2;
    } else if (vapid_json_escape_is_control(str[i])) {
      // 6 bytes: "\u", followed by a four-byte Unicode escape sequence.
      len += 6;
    } else {
      len++;
    }
  }
  return len;
}

// Converts `str` into a double-quoted JSON string and escapes all special
// characters. This is the only JSON encoding we'll need to do, since our claims
// object contains two strings and a number.
static char*
vapid_json_quote(const char* str, size_t strLen)
{
	size_t quotedLen = vapid_json_quoted_length(str, strLen);
	char* quotedStr = malloc(quotedLen + 1);
	if (!quotedStr)
	{
		return NULL;
	}
	char* result = quotedStr;
	*result++ = '"';
	for (size_t i = 0; i < strLen; i++)
	{
		char escLiteral = vapid_json_escape_literal(str[i]);
		if (escLiteral)
		{
			// Some special characters have escaped literal forms.
			*result++ = '\\';
			*result++ = escLiteral;
		}
		else if (vapid_json_escape_is_control(str[i]))
		{
			// Other control characters need Unicode escape sequences.
			result += vapid_json_escape_unicode(str[i], result);
		}
		else
		{
			*result++ = str[i];
		}
	}
	*result++ = '"';
	quotedStr[quotedLen] = '\0';
	return quotedStr;
}

// Builds and returns the signature base string. This is what we'll sign with
// our private key. The base string is *not* null-terminated.
static char*
vapid_build_signature_base(const char* aud, size_t audLen, uint32_t exp,
                           const char* sub, size_t subLen, size_t* sigBaseLen)
{
	char* quotedAud = NULL;
	char* quotedSub = NULL;
	char* payload = NULL;
	char* sigBase = NULL;

	// Build the payload, which contains the audience, expiry, and subject claims.
	// Since we only need to include three claims, and since this tool is meant to
	// show how Vapid works with few dependencies, we build our JSON string using
	// `sprintf`. I don't recommend this approach; it's almost always better to
	// use a proper serialization library.
	quotedAud = vapid_json_quote(aud, audLen);
	if (!quotedAud) {
	goto end;
	}
	quotedSub = vapid_json_quote(sub, subLen);
	if (!quotedSub) {
	goto end;
	}
	int payloadLen =
	snprintf(NULL, 0, "{\"aud\":%s,\"exp\":%" PRIu32 ",\"sub\":%s}", quotedAud,
			 exp, quotedSub);
	if (payloadLen <= 0) {
	goto end;
	}
	// Allocate an extra byte for the null terminator, which `sprintf` appends.
	payload = malloc((size_t) payloadLen + 1);
	if (!payload) {
	goto end;
	}
	if (sprintf(payload, "{\"aud\":%s,\"exp\":%" PRIu32 ",\"sub\":%s}", quotedAud,
			  exp, quotedSub) <= 0) {
	goto end;
	}

	// Determine the Base64url-encoded sizes of the header and payload, and
	// allocate a buffer large enough to hold the encoded strings and a `.`
	// separator.
	size_t b64HeaderLen = ece_base64url_encode(
	VAPID_HEADER, VAPID_HEADER_LENGTH, ECE_BASE64URL_OMIT_PADDING, NULL, 0);
	size_t b64PayloadLen = ece_base64url_encode(
	payload, (size_t) payloadLen, ECE_BASE64URL_OMIT_PADDING, NULL, 0);
	*sigBaseLen = b64HeaderLen + b64PayloadLen + 1;
	sigBase = malloc(*sigBaseLen);
	if (!sigBase) {
	goto end;
	}

	// Finally, write the encoded header, a `.`, and the encoded payload.
	ece_base64url_encode(VAPID_HEADER, VAPID_HEADER_LENGTH,
					   ECE_BASE64URL_OMIT_PADDING, sigBase, b64HeaderLen);
	sigBase[b64HeaderLen] = '.';
	ece_base64url_encode(payload, (size_t) payloadLen, ECE_BASE64URL_OMIT_PADDING,
					   &sigBase[b64HeaderLen + 1], b64PayloadLen);

end:
	free(quotedAud);
	free(quotedSub);
	free(payload);
	return sigBase;
}

// Signs a signature base string with the given `key`, and returns the raw
// signature.
static uint8_t*
vapid_sign(EC_KEY* key, const void* sigBase, size_t sigBaseLen,
           size_t* sigLen)
{
	ECDSA_SIG* sig = NULL;
	const BIGNUM* r;
	const BIGNUM* s;
	uint8_t* rawSig = NULL;

	// Our algorithm is "ES256", so we compute the SHA-256 digest.
	uint8_t digest[SHA256_DIGEST_LENGTH];
	SHA256(sigBase, sigBaseLen, digest);

	// OpenSSL has an `ECDSA_sign` function that writes a DER-encoded ASN.1
	// structure. We use `ECDSA_do_sign` instead because we want to write
	// `s` and `r` directly.
	sig = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, key);
	if (!sig) {
	goto end;
	}
	ECDSA_SIG_get0(sig, &r, &s);

	size_t rLen = (size_t) BN_num_bytes(r);
	size_t sLen = (size_t) BN_num_bytes(s);
	*sigLen = rLen + sLen;
	rawSig = calloc(*sigLen, sizeof(uint8_t));
	if (!rawSig) {
	goto end;
	}

	BN_bn2bin(r, rawSig);
	BN_bn2bin(s, &rawSig[rLen]);

end:
	ECDSA_SIG_free(sig);
	return rawSig;
}

// Builds a signed Vapid token to include in the `Authorization` header. The
// token is null-terminated.
static char*
vapid_build_token(EC_KEY* key, const char* aud, size_t audLen, uint32_t exp,
                  const char* sub, size_t subLen)
{
	char* sigBase = NULL;
	uint8_t* sig = NULL;
	char* token = NULL;

	// Build and sign the signature base string.
	size_t sigBaseLen;
	sigBase =
	vapid_build_signature_base(aud, audLen, exp, sub, subLen, &sigBaseLen);
	if (!sigBase) {
	goto error;
	}
	size_t sigLen;
	sig = vapid_sign(key, sigBase, sigBaseLen, &sigLen);
	if (!sig) {
	goto error;
	}

	// The token comprises the base string, another `.`, and the encoded
	// signature. First, we grow the base string to hold the `.`, signature, and
	// null terminator.
	size_t b64SigLen =
	ece_base64url_encode(sig, sigLen, ECE_BASE64URL_OMIT_PADDING, NULL, 0);
	size_t tokenLen = sigBaseLen + 1 + b64SigLen;
	token = realloc(sigBase, tokenLen + 1);
	if (!token) {
	goto error;
	}
	sigBase = NULL;

	// Then, we append the signature, and null-terminate the string.
	token[sigBaseLen] = '.';
	ece_base64url_encode(sig, sigLen, ECE_BASE64URL_OMIT_PADDING,
					   &token[sigBaseLen + 1], b64SigLen);
	token[tokenLen] = '\0';
	goto end;

error:
	free(token);
	token = NULL;

end:
	free(sigBase);
	free(sig);
	return token;
}

static EC_KEY*
vapid_import_private_key(const char* b64PrivKeyPemFormat)
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
	      return NULL;
	 }
	 return EC_KEY_ptr;
}

static EC_KEY*
vapid_generate_keys()
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

static char*
vapid_export_private_key(EC_KEY* key)
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

static char*
vapid_export_public_key(EC_KEY* key)
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

bool make_vapid(struct vapid* vapid_token,
				const char* audience, const char* subscriber, uint32_t expiration, const char* b64_pem_priv_key)
{
	bool ok = true;

	const char* aud = audience;
	uint32_t exp = expiration;
	const char* sub = subscriber;
	EC_KEY* key = NULL;

	if (!b64_pem_priv_key)
	{
		printf("Generating keys...\n");
		key = vapid_generate_keys();
		if (!key)
		{
			fprintf(stderr, "vapid: Error generating EC keys\n");
			ok = false;
			goto end;
		}
	}
	else
	{
		printf("Importing keys...\n");
		key = vapid_import_private_key(b64_pem_priv_key);
		if (!key)
		{
			fprintf(stderr, "vapid: Invalid EC private key\n");
			ok = false;
			goto end;
		}
	}

	vapid_token->private_key = vapid_export_private_key(key);
	if (!vapid_token->private_key)
	{
		fprintf(stderr, "vapid: Error exporting private key\n");
		ok = false;
		goto end;
	}

	vapid_token->public_key = vapid_export_public_key(key);
	if (!vapid_token->public_key)
	{
		fprintf(stderr, "vapid: Error exporting public key\n");
		ok = false;
		goto end;
	}

	vapid_token->token = vapid_build_token(key, aud, strlen(aud), exp, sub, strlen(sub));
	if (!vapid_token->token)
	{
		fprintf(stderr, "vapid: Error signing token\n");
		ok = false;
		goto end;
	}

	printf("Private key: %s\n", vapid_token->private_key);
	printf("Public key: %s\n", vapid_token->public_key);
	printf("Expiry: %" PRIu32 "\n", exp);
	printf("Token: %s\n", vapid_token->token);

end:
	if(!ok)
	{
		EC_KEY_free(key);
		destroy_vapid(vapid_token);
	}

	return ok;
}

void destroy_vapid(struct vapid* token)
{
	free(token->public_key);
	free(token->private_key);
	free(token->token);

	token->public_key = NULL;
	token->private_key = NULL;
	token->token = NULL;
}

