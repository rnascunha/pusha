#ifndef PUSHA_EC_KEY_HPP__
#define PUSHA_EC_KEY_HPP__

#include <string>
#include <system_error>
#include <filesystem>
#include <openssl/ec.h>

namespace pusha{

class key{
	public:
		key() noexcept;
		//Import from PEM file
		key(const std::filesystem::path&, std::error_code&) noexcept;
		//Import base64 url
		key(const char*, std::error_code&) noexcept;
		key(std::string const&, std::error_code&) noexcept;
		key(const key& ec_key) noexcept;
		key(key&& ec_key) noexcept;
		key(EC_KEY* key) noexcept;
		key(EC_KEY* key, std::error_code&) noexcept;

		~key();

		bool check() const noexcept;

		bool import(const std::filesystem::path&) noexcept;
		bool import(const char*) noexcept;
		bool import(std::string const&) noexcept;

		std::string_view export_private_key() const noexcept;
		std::string_view export_public_key() const noexcept;

		bool export_private_key(const std::filesystem::path&) const noexcept;
		bool export_public_key(const std::filesystem::path&) const noexcept;

		EC_KEY const* get_key() const noexcept;
		EC_KEY* get_key() noexcept;

		key& operator=(key const& key) noexcept;
		key& operator=(key&& key) noexcept;

		static key generate(std::error_code& ec) noexcept;
		static key generate() noexcept;
	private:
		EC_KEY* key_ = NULL;
};

}//pusha

#endif /* PUSHA_EC_KEY_HPP__ */
