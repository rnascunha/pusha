#include "pusha/notify.hpp"
#include "pusha.h"

namespace pusha{

notify::notify(key const& ec_key, std::string_view const& subscriber)
	: sub_(subscriber), key_(ec_key){}

notify::notify(key&& ec_key, std::string_view const& subscriber)
	: sub_(subscriber), key_(std::move(ec_key))
{}

notify::notify(EC_KEY* key, std::string_view const& subscriber)
	: sub_(subscriber), key_(key)
{}

std::string_view notify::subscriber() const noexcept
{
	return sub_;
}

void notify::subscriber(std::string_view const& new_subscriber) noexcept
{
	sub_ = new_subscriber;
}

int notify::make(pusha_http_request& req,
				std::string_view const& endpoint,
				std::string_view const& p256dh,
				std::string_view const& auth,
				unsigned expiration,
				unsigned ttl,
				const void* payload /* = NULL */,
				std::size_t payload_len /* = 0 */,
				Pusha_HTTP_Version ver /* = pusha_HTTPver_1_1 */) noexcept
{
	return pusha_notify_http(&req,
			key_.get_key(),
			endpoint.data(), endpoint.size(),
			sub_.data(), sub_.size(),
			p256dh.data(), p256dh.size(),
			auth.data(), auth.size(),
			expiration, ttl,
			payload, payload_len, ver);
}

int notify::make(pusha_http_headers& headers,
		pusha_payload* pp,
		std::string_view const& endpoint,
		std::string_view const& p256dh,
		std::string_view const& auth,
		unsigned expiration,
		const void* payload /* = NULL */, std::size_t payload_len /* = 0 */) noexcept
{
	return pusha_notify(&headers, pp,
				key_.get_key(),
				endpoint.data(), endpoint.size(),
				sub_.data(), sub_.size(),
				p256dh.data(), p256dh.size(),
				auth.data(), auth.size(),
				expiration,
				payload, payload_len);
}

}//pusha
