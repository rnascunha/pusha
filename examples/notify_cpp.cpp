/**
 * This examples shows how to use the 'notify' class, the most direct
 * way to create the HTTP headers and encrypt any payload necessary to make a push
 * request.
 *
 * To use this example you must have a private key in a file with PEM format. If
 * you don't have one, create using the 'genkey' tool, like this:
 *
 * ./genkey -p priv.pem
 *
 * This will print a public and private key in base64 format, and create a file
 * named 'priv.pem' (change the variable 'private_key_pem_file' in this example
 * to the name of your file). The public key you will use at your website.
 *
 * Also change the variables 'subscriber', 'p256dh', 'auth' and 'endpoint' to
 * the appropriate of your environment.
 *
 * If everything works correctly, this example will print the headers of a HTTP
 * request and the encrypted payload.
 */

#include <time.h>	//time
#include <string.h> //strlen
#include <stdio.h>	//fprintf
#include <filesystem>
#include "pusha.hpp"

/**
 * Uncomment this define to make a push request without payload
 */
//#define WITHOUT_PAYLOAD

/**
 * Show how to use other notify interface
 */
//#define USE_OTHER_INTERFACE

int main()
{
	/**
	 * Change the following variable to your case
	 */
	std::string_view subscriber{"mailto:email@company.com"},	//Your contact
				//The follow 3 information you get when subscribe (allow) to receive a push message
				p256dh{"BEEsArqCAa8j9yBp5JwQYFJyEzdFBUQHw1oOb4_ucrkiA1vy44Y429mH734ve53bFQ2yYnQ0BXQts-kZl_F5I8A"},
				auth{"0AZOLIFaBr1aqk2D-Rmptg"},
				endpoint{"https://fcm.googleapis.com/fcm/send/eYcBt_gjfMQ:APA91bFQeZolEdNtJNdZL-5cyCD_4ipI6XY4Q2xa2fxqlbkgTEbzOEzk5zRZC-VSQHd8cN-dDaXKaYSErQaH07atQlTFOLOf91yr5fBhcj9KaEY4z2RL6WvztOt-3zS7MQ17ic9b7MYM"};
	/**
	 * Setting the expiration time to 12h
	 */
	unsigned expiration = time(NULL) + 12 * 60 * 60;

	/**
	 * You can make a push request with or without payload. If you don't need payload,
	 * just set this variable to NULL
	 */
#ifndef WITHOUT_PAYLOAD
	const char* payload = "My first push";
#else
	const char* payload = NULL;
#endif /* WITHOUT_PAYLOAD */
	size_t payload_len = payload ? strlen(payload) : 0;

	/**
	 * Our keys was generated using the following command:
	 *
	 * ./genkey -p priv.pem
	 *
	 * This command will show the public and private key in a base64 format, and also
	 * output the private key in PEM format to a file. We are going to read the private
	 * key from the file
	 */
	const char* private_key_pem_file = "priv.pem";

	/**
	 * This will hold our EC keys
	 *
	 * Let's import our key from the file
	 */
	std::error_code ec;
	pusha::key ec_key{std::filesystem::path{private_key_pem_file}, ec};
	/**
	 * Checking if imported successfully
	 */
	if(ec)
	{
		std::fprintf(stderr, "Error importing private key [err=%d]\n", 1);
		return 1;
	}

	pusha::notify push{std::move(ec_key), subscriber};

	/**
	 * Now we can make our push request
	 */
#ifndef USE_OTHER_INTERFACE
	pusha_http_request req;
	int err = push.make(req,
			endpoint,
			p256dh,
			auth,
			expiration, 60 /* ttl */,
			payload, payload_len);
#else /* USE_OTHER_INTERFACE */
	pusha_http_headers headers = {};
	pusha_payload pp = {};
	int err = push.make(headers,
			&pp,
			endpoint,
			p256dh,
			auth,
			expiration,
			payload, payload_len);
#endif /* USE_OTHER_INTERFACE */
	if(err)
	{
		fprintf(stderr, "Error creating http request [err=%d]\n", err);
		goto end;
	}

	/**
	 * Now we can make our push request with all the info calculated.
	 *
	 * Here we are going to print this information simulating a HTTP request
	 */
#ifndef USE_OTHER_INTERFACE
	print_http_request2(&req);
#else /* USE_OTHER_INTERFACE */
	print_http_request(endpoint.data(),
						endpoint.size(),
						&headers,
						pp.cipher_payload, pp.cipher_payload_len);
#endif /* USE_OTHER_INTERFACE */

end:
	/**
	 * Freeing any memory allocated
	 */
#ifndef USE_OTHER_INTERFACE
	free_http_request(&req);
#else /* USE_OTHER_INTERFACE */
	free_pusha_http_headers(&headers);
	free_pusha_payload(&pp);
#endif /* USE_OTHER_INTERFACE */

	return err;
}
