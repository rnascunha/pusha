#ifndef PUSHA_ERROR_HPP__
#define PUSHA_ERROR_HPP__

#include <system_error>
#include "pusha/error.h"

namespace pusha{

enum class errc{
	out_of_memory = ECE_ERROR_OUT_OF_MEMORY,
	invalid_key = PUSHA_ERROR_INVALID_KEY,
	open_file = PUSHA_ERROR_OPEN_FILE,
	write_key = PUSHA_ERROR_WRITE_KEY,
	encode_sub64 = PUSHA_ERROR_ENCODE_SUB64,
	wrong_arguments = PUSHA_ERROR_WRONG_ARGUMENTS,
	invalid_endpoint = PUSHA_ERROR_INVALID_ENDPOINT,
	decode_subscription = PUSHA_ERROR_DECODE_SUBSCRIPTION,
	generate_vapid = PUSHA_ERROR_GENERATE_VAPID,
	make_payload = PUSHA_ERROR_MAKE_PAYLOAD,
	make_http_headers = PUSHA_ERROR_MAKE_HTTP_HEADERS,
	make_kttp_request = PUSHA_ERROR_MAKE_HTTP_REQUEST,
	serialize_http_request = PUSHA_ERROR_SERIALIZE_HTTP_REQUEST,
	connect = PUSHA_ERROR_CONNECT,
	ssl_create = PUSHA_ERROR_SSL_CREATE,
	ssl_connect = PUSHA_ERROR_SSL_CONNECT,
	ssl_send = PUSHA_ERROR_SSL_SEND,
	ssl_receive = PUSHA_ERROR_SSL_RECEIVE,
};

struct Message_Err_Category : public std::error_category{
	const char* name() const noexcept;
	std::string message(int ev) const;
};

const Message_Err_Category the_Message_Err_Category {};

}//pusha

std::error_code make_error_code(pusha::errc e);

#endif /* PUSHA_ERROR_HPP__ */
