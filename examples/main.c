#include <stdio.h>
#include <time.h>

#include "vapid.h"
#include "web_push.h"

static void usage()
{
	printf("\t./curl_pusha '<push_message>'\n");
}

int main(int argc, char** argv)
{
	if(argc != 2)
	{
		printf("Wrong number of arguments. Usage:\n");
		usage();
		return 1;
	}

	const char* endpoint = "https://fcm.googleapis.com/fcm/send/cB7YJvUrAjs:APA91bH-54YYctca5NqDPIoN-975QHOUyZVpsd2frbvafcnKfwPyjyYAFxChGaOJaVjl4nAtRiSB-GfU9f52rQd6eVTPxl5LjkjJjTMew34cEHiNkRwaCfVFlEXhQjhnyCMqba8OaAn3";
	const char* p256dh = "BAI1ogkHBBWOyKlIHYFPZQTZciINDghDgxi267OgyM37ZtGAj0ngzBkLsL0cq33F4Lk2kXkWJXMrubS-ZZMfwJk";
	const char* auth = "WByir7Yc0_Uhgp50INJ0yg";
	const void* plaintext = argv[1];

	const char* endpoint_host = "https://fcm.googleapis.com";
	const char* sub = "mailto:rnascunha@gmail.com";
	uint32_t exp = time(NULL) + (12 * 60 * 60); //12h
	const char* pem_priv_key = "-----BEGIN EC PRIVATE KEY-----\n"
							"MHcCAQEEIIPvOncbNzJrJz8JWWE6JqilVwvuqGdRQPogo8r/wUbNoAoGCCqGSM49\n"
							"AwEHoUQDQgAEVdtf/uBlVRBllcS774qmVTq637EMhsYH/7MzX16RDwgruI6y2Mog\n"
							"BbVMoDnachGg1+vv9EGjqQ9Ioylxicrqfw==\n"
							"-----END EC PRIVATE KEY-----";

	struct vapid token;
	if(!make_vapid(&token, endpoint_host, sub, exp, pem_priv_key))
	{
		printf("Invalid VAPID token generated...\n");
		return 1;
	}
	printf("Making push request...\n");
	make_web_push(endpoint, p256dh, auth, &token, plaintext);

	destroy_vapid(&token);
	return 0;
}


