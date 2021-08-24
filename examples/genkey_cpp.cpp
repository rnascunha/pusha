#include <cstdio>
#include "pusha/ec_keys.hpp"
#include "ece.h"
#include <openssl/ec.h>
#include <cstring>

int output_base64(pusha::key const& key, std::string_view& privatek, std::string_view& publick) noexcept
{
	privatek = key.export_private_key();
	if(privatek.empty())
	{
		fprintf(stderr, "Failed export private key");
		return 0;
	}

	publick = key.export_public_key();
	if(publick.empty())
	{
		fprintf(stderr, "Failed export public key\n");
		return 0;
	}

	return 1;
}

int output_pem_file(pusha::key const& key,
		std::filesystem::path const& private_file,
		std::filesystem::path const& public_file) noexcept
{
	if(!private_file.empty())
	{
		if(!key.export_private_key(private_file))
		{
			fprintf(stderr, "Error exporting private key to PEM file\n");
			return 0;
		}
	}

	if(!public_file.empty())
	{
		if(!key.export_public_key(public_file))
		{
			fprintf(stderr, "Error exporting public key to PEM file\n");
			return 0;
		}
	}

	return 1;
}

static void usage(const char* program)
{
	std::printf("Usage:\n\t%s -h|[-p <private_pem_file>] [-u <public_pem_file>]\n", program);
	std::printf("Where:\n");
	std::printf("\t-h\tprint this help message\n");
	std::printf("\t-p\toutput private key to pem file specified\n");
	std::printf("\t-u\toutput public key to pem file specified\n");
}

int main(int argc, char** argv)
{
	int ret = 0;
	std::string_view privatek, publick;
	std::filesystem::path pem_priv_file, pem_pub_file;

	int i = 1;
	argc--;
	while(argc--)
	{
		if(std::strcmp(argv[i], "-h") == 0)
		{
			usage(argv[0]);
			return 0;
		}
		else if(std::strcmp(argv[i], "-p") == 0)
		{
			if(argc == 0)
			{
				std::fprintf(stderr, "'-p' option must have a argument\n");
				usage(argv[0]);
				return 1;
			}
			pem_priv_file = argv[++i];
			argc--;
		}
		else if(strcmp(argv[i], "-u") == 0)
		{
			if(argc == 0)
			{
				std::fprintf(stderr, "'-u' option must have a argument\n");
				usage(argv[0]);
				return 1;
			}
			pem_pub_file = argv[++i];
			argc--;
		}
		else
		{
			std::fprintf(stderr, "Ignoring argument '%s'\n", argv[i]);
		}
		i++;
	}

	std::error_code ec;
	pusha::key ec_key = pusha::key::generate(ec);
	if(ec)
	{
		fprintf(stderr, "Error generating keys\n");
		ret = 2;
		goto end;
	}

	if(!output_base64(ec_key, privatek, publick))
	{
		ret = 3;
		goto end;
	}
	printf("Private: %.*s\nPublic: %.*s\n",
			(int)privatek.size(), privatek.data(),
			(int)publick.size(), publick.data());

	output_pem_file(ec_key, pem_priv_file, pem_pub_file);
end:
	return ret;
}
