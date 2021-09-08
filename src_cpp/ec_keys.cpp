#include "pusha/ec_keys.hpp"
#include "pusha/ec_keys.h"
#include "pusha/error.hpp"
#include <iostream>

namespace pusha{

key::key() noexcept{}

//Import from PEM file
key::key(const std::filesystem::path& path, std::error_code& ec) noexcept
{
	if(!import(path)) ec = make_error_code(std::errc::invalid_argument);
}

//Import base64 url
key::key(const char* b64key, std::error_code& ec) noexcept
{
	if(!import(b64key)) ec = make_error_code(std::errc::invalid_argument);
}

key::key(std::string const& b64key, std::error_code& ec) noexcept
{
	if(!import(b64key)) ec = make_error_code(std::errc::invalid_argument);
}

key::key(const key& ec_key) noexcept
{
	key_ = EC_KEY_dup(ec_key.get_key());
}

key::key(key&& ec_key) noexcept
{
	if(!ec_key.get_key()) return;
	key_ = EC_KEY_dup(ec_key.get_key());
	EC_KEY_free(ec_key.get_key());
	ec_key.key_ = NULL;
}

key::key(EC_KEY* key) noexcept
	: key_(key)
{}

key::key(EC_KEY* key, std::error_code& ec) noexcept
	: key_(key)
{
	if(!check())
	{
		ec = make_error_code(errc::invalid_key);
		key_ = NULL;
	}
}

key::~key()
{
	EC_KEY_free(key_);
}

bool key::check() const noexcept
{
	return EC_KEY_check_key(key_) == 1;
}

bool key::import(const std::filesystem::path& path) noexcept
{
	key_ = import_private_key_pem_file(path.c_str());
	return key_ ? true : false;
}

bool key::import(const char* b64key) noexcept
{
	key_ = import_private_key_base64(b64key);
	return key_ ? true : false;
}

bool key::import(std::string const& b64key) noexcept
{
	return import(b64key.c_str());
}

std::string_view key::export_private_key() const noexcept
{
	return std::string_view{::export_private_key(key_)};
}

std::string_view key::export_public_key() const noexcept
{
	return std::string_view{::export_public_key(key_)};
}

bool key::export_private_key(std::filesystem::path const& path) const noexcept
{
	return ::export_private_key_pem(key_, path.c_str()) == ECE_OK;
}

bool key::export_public_key(std::filesystem::path const& path) const noexcept
{
	return ::export_public_key_pem(key_, path.c_str()) == ECE_OK;
}

EC_KEY const* key::get_key() const noexcept
{
	return key_;
}

EC_KEY* key::get_key() noexcept
{
	return key_;
}

key& key::operator=(key const& key) noexcept
{
	EC_KEY_copy(this->key_, key.key_);
	return *this;
}

key& key::operator=(key&& key) noexcept
{
	EC_KEY_copy(this->key_, key.key_);
	EC_KEY_free(key.key_);
	key.key_ = NULL;
	return *this;
}

key key::generate() noexcept
{
	std::error_code ec;
	return key{generate_keys(), ec};
}

key key::generate(std::error_code& ec) noexcept
{
	return key{generate_keys(), ec};
}

}//pusha
