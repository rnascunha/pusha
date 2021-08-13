/**
 * This examples shows how to use the 'pusha' function, the most direct way to
 * create the HTTP headers and encrypt any payload necessary to make a push
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
 * If everything work correctly, this example will print the headers of a HTTP
 * request and the encrypted payload.
 */

#include <time.h>	//time
#include <string.h> //strlen
#include <stdio.h>	//fprintf
#include "pusha.h"

/**
 * Uncomment this define to make a push request without payload
 */
//#define WITHOUT_PAYLOAD
/**
 * Uncomment this define to print a 'curl' command so you can send a push request
 */
//#define CURL_OUTPUT

int main()
{
	/**
	 * Change the following variable to your case
	 */
	const char *subscriber = "mailto:email@company.com",	//Your contact
				//The follow 3 information you get when subscribe (allow) to receive a push message
				*p256dh = "BEEsArqCAa8j9yBp5JwQYFJyEzdFBUQHw1oOb4_ucrkiA1vy44Y429mH734ve53bFQ2yYnQ0BXQts-kZl_F5I8A",
				*auth = "0AZOLIFaBr1aqk2D-Rmptg",
				*endpoint = "https://fcm.googleapis.com/fcm/send/eYcBt_gjfMQ:APA91bFQeZolEdNtJNdZL-5cyCD_4ipI6XY4Q2xa2fxqlbkgTEbzOEzk5zRZC-VSQHd8cN-dDaXKaYSErQaH07atQlTFOLOf91yr5fBhcj9KaEY4z2RL6WvztOt-3zS7MQ17ic9b7MYM";
	/**
	 * Setting the expiration time to 12h
	 */
	unsigned expiration = time(NULL) + 12 * 60 * 60;
	/**
	 * HTTP TTL header
	 */
	unsigned ttl = 60;

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
	EC_KEY* key = import_private_key_pem_file(private_key_pem_file);;
	/**
	 * Checking if imported successfully
	 */
	if(!key)
	{
		fprintf(stderr, "Error importing private key [err=%d]\n", 1);
		return 1;
	}

	/**
	 * Now we can make our push request
	 */
	/**
	 * This variable is just needed if you are going to send  some payload
	 * with the push message (payload != NULL). It will hold the encrypted
	 * payload and some other info needed
	 */
	push_payload pp = {};
	/**
	 * This will hold the HTTP headers processed
	 */
	push_http_headers headers = {};
	headers.ttl = ttl;

	int err = pusha(&headers,
			payload_len ? &pp : NULL,
			key,
			endpoint,
			subscriber,
			p256dh,
			auth,
			expiration,
			payload,
			payload_len);

	if(err != ECE_OK)
	{
		fprintf(stderr, "Error creating push message [err=%d]\n", err);
		goto end;
	}

	/**
	 * Now we can make our push request with all the info calculated.
	 *
	 * Here we are going to print this information simulating a HTTP request
	 */
#ifndef CURL_OUTPUT
	print_http_request(endpoint, &headers, payload_len ? pp.cipher_payload : NULL, payload_len);
#else
	char* out = curl_output(endpoint, &headers, payload_len ? pp.cipher_payload : NULL, payload_len);
	if(!out)
	{
		err = 2;
		fprintf(stderr, "Error creating output [%d]\n", err);
		goto end;
	}
	printf("%s\n", out);
	free(out);
#endif /* CURL_OUTPUT */
end:
	/**
	 * Freeing any memory allocated
	 */
	free_push_payload(&pp);
	free_push_http_headers(&headers);

	return err;
}
