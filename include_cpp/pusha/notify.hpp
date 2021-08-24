#ifndef PUSHA_NOTIFY_HPP__
#define PUSHA_NOTIFY_HPP__

#include <cstdlib>
#include <string_view>

#include "pusha/http.h"
#include "pusha/ec_keys.hpp"
#include "pusha/error.hpp"

namespace pusha{

class notify{
	public:
		notify(key const&, std::string_view const& subcriber);
		notify(key&&, std::string_view const& subcriber);
		notify(EC_KEY* key, std::string_view const& subscriber);

		std::string_view subscriber() const noexcept;
		void subscriber(std::string_view const&) noexcept;

		int make(pusha_http_request& req,
				std::string_view const& endpoint,
				std::string_view const& p256dh,
				std::string_view const& auth,
				unsigned expiration, unsigned ttl,
				const void* payload = NULL, std::size_t payload_len = 0,
				Pusha_HTTP_Version ver = pusha_HTTPver_1_1) noexcept;

		int make(pusha_http_headers& headers,
				pusha_payload* pp,
				std::string_view const& endpoint,
				std::string_view const& p256dh,
				std::string_view const& auth,
				unsigned expiration,
				const void* payload = NULL, std::size_t payload_len = 0
				) noexcept;
	private:
		std::string_view 	sub_;
		key					key_;
};

}//pusha

#endif /* PUSHA_NOTIFY_HPP__ */
