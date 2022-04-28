#include <cstdio>
#include "pusha.hpp"
#include <cstring>

#include <system_error>
#include <filesystem>

#define SUBSCRIBER "mailto:email@company.com"

int main(int argc, char** argv)
{
	printf("-2\n");
	auto a = std::move((int)NULL);
	printf("-1\n");

	std::error_code ec;
	pusha::key key0{std::filesystem::path{"test.pem"}, ec};
	pusha::notify push{std::move(key0), SUBSCRIBER};

	printf("00\n");

	if(ec)
	{
		printf("%d / %s\n", ec.value(), ec.message().c_str());
	}

//	printf("1\n");
//	pusha::key key1, key2 = pusha::key::generate();
//	printf("2\n");
//	pusha::key key3{std::move(key2)};
//
//	printf("3\n");
//	key1 = std::move(key3);
//	printf("4\n");

	return 0;
}
