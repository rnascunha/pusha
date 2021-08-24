#include "pusha/error.hpp"

namespace pusha{

const char* Message_Err_Category::name() const noexcept
{
	return "pusha";
}

std::string Message_Err_Category::message(int ev) const
{
	switch(static_cast<errc>(ev))
	{
		case errc::out_of_memory: return "out of memory";
		case errc::invalid_key: return "invalid key";
		case errc::open_file: return "open file";
		case errc::write_key: return "write key";
		case errc::encode_sub64:	return "encode sub64";
		case errc::wrong_arguments: return "wrong arguments";
		case errc::invalid_endpoint: return "invalid endpoint";
		case errc::decode_subscription: return "decode subscription";
		case errc::generate_vapid: return "generate vapid";
		case errc::make_payload: return "make payload";
		case errc::make_http_headers: return "make http headers";
		case errc::make_kttp_request: return "make http request";
		case errc::serialize_http_request: return "serialize http request";
		case errc::connect: return "connect";
		case errc::ssl_create: return "ssl_create";
		case errc::ssl_connect: return "ssl_connect";
		case errc::ssl_send: return "ssl_send";
		case errc::ssl_receive: return "ssl_receive";
		default:
			return "(unrecognized error)";
	}
}

}//pusha

std::error_code make_error_code(pusha::errc e)
{
  return {static_cast<int>(e), pusha::the_Message_Err_Category};
}
