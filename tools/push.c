#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "pusha.h"

void usage(const char* program)
{
	printf("Usage:\n\t%s -h|(-p <pem_priv_file>|-b <base64_priv_key>) [-v]\n\t\t[-m <message>] "
						"[-e <expire_time_seconds>]\n\t\t"
						"[-o send|curl|print] [-l <ttl>]\n\t\t"
						"<sub> <p256dh> <auth> <endpoint>\n", program);
	printf("\nWhere:\n");
	printf("\t<sub>\tvapid subscriber (e.g. mainto:email@company.com)\n");
	printf("\t<p256dh>\tpublic server key (received at push subscription)\n");
	printf("\t<auth>\tauthentication secret (received at push subscription)\n");
	printf("\t<endpoint>\tendpoint (received at push subscription)\n");
	printf("\t-v\tverbose mode\n");
	printf("\t-h\tthis help message\n");
	printf("\t-p\tpem file with EC private key (don't use with '-b')\n");
	printf("\t-b\tbase64 encoded private key (don't use with '-p')\n");
	printf("\t-e\tseconds to expire time (default 12h, i.e, 12 * 60 * 60)\n");
	printf("\t-o\tset output type. Options: 'send' (default), 'curl' or 'print'\n");
	printf("\t-l\tset http ttl value (default = 0)\n");
	printf("\t-m\tmessage payload to send\n");
}

enum Output{
	output_send = 0,
	output_curl,
	output_print
};

int main(int argc, char** argv)
{
	int ret = 0, verbose = 0;
	EC_KEY* key = NULL;
	uint32_t exp = time(NULL) + (12 * 60 * 60); //12h
	char* sub = NULL, *p256dh = NULL, *auth = NULL,
		*endpoint = NULL, *payload = NULL;

	enum Output output = output_send;

	vapid token = {0,};
	push_payload pp = {0,}; ///* Used only if payload != NULL
	push_http_headers headers = {0,};

	int i = 1, pos_arg = 0;
	argc--;
	while(argc)
	{
		//Checking if is a positional argument
		if(argv[i][0] != '-')
		{
			//is a positional argument
			switch(pos_arg)
			{
				case 0:
					sub = argv[i];
					break;
				case 1:
					p256dh = argv[i];
					break;
				case 2:
					auth = argv[i];
					break;
				case 3:
					endpoint = argv[i];
					break;
				default:
					PUSHA_ERROR("Invalid position argument. 4 mandatory [%d]\n", pos_arg + 1);
					break;
			}
			pos_arg++;
		}
		else if(strcmp(argv[i], "-h") == 0)
		{
			usage(argv[0]);
			goto end;
		}
		else if(strcmp(argv[i], "-p") == 0)
		{
			//PEM file private key
			if(argc == 1)
			{
				PUSHA_ERROR("'-p' option must have a argument\n");
				usage(argv[0]);
				ret = 1;
				goto end;
			}
			if(key)
			{
				PUSHA_ERROR("Private key already set. Use option '-p' or '-b'\n");
				usage(argv[0]);
				ret = 1;
				goto end;
			}

			key = import_private_key_pem_file(argv[++i]);
			if(!key)
			{
				PUSHA_ERROR("Error importing private key from file '%s'\n", argv[i]);
				ret = 1;
				goto end;
			}
			argc--;
		}
		else if(strcmp(argv[i], "-b") == 0)
		{
			//Base64 private key
			if(argc == 1)
			{
				PUSHA_ERROR("'-b' option must have a argument\n");
				usage(argv[0]);
				return 1;
			}
			if(key)
			{
				PUSHA_ERROR("Private key already set. Use option '-p' or '-b'\n");
				usage(argv[0]);
				ret = 1;
				goto end;
			}
			key = import_private_key_base64(argv[++i]);
			if(!key)
			{
				PUSHA_ERROR("Error importing private key [%s]\n", argv[i]);
				ret = 1;
				goto end;
			}
			argc--;
		}
		else if(strcmp(argv[i], "-e") == 0)
		{
			//expiration time
			if(argc == 1)
			{
				PUSHA_ERROR("'-e' option must have a argument\n");
				usage(argv[0]);
				ret = 1;
				goto end;
			}
			long sec = strtoul(argv[++i], NULL, 10);
			if(!sec)
			{
				PUSHA_ERROR("Invalid expiration time\n");
				ret = 1;
				goto end;
			}
			exp = time(NULL) + sec;
			argc--;
		}
		else if(strcmp(argv[i], "-m") == 0)
		{
			//message payload
			if(argc == 1)
			{
				PUSHA_ERROR("'-m' option must have a argument\n");
				usage(argv[0]);
				ret = 1;
				goto end;
			}
			payload = argv[++i];
			argc--;
		}
		else if(strcmp(argv[i], "-v") == 0)
		{
			//set verbose mode
			verbose = 1;
		}
		else if(strcmp(argv[i], "-o") == 0)
		{
			//Check output type
			if(argc == 1)
			{
				PUSHA_ERROR("'-o' option must have a argument\n");
				usage(argv[0]);
				ret = 1;
				goto end;
			}
			if(strcmp(argv[++i], "print") == 0)
			{
				output = output_print;
			}
			else if(strcmp(argv[i], "curl") == 0)
			{
				output = output_curl;
			}
			argc--;
		}
		else if(strcmp(argv[i], "-l") == 0)
		{
			//set HTTP TTL value
			if(argc == 1)
			{
				PUSHA_ERROR("'-l' option must have a argument\n");
				usage(argv[0]);
				ret = 1;
				goto end;
			}
			long ttl = strtoul(argv[++i], NULL, 10);
			if(!ttl)
			{
				PUSHA_ERROR("Invalid expiration time\n");
				ret = 1;
				goto end;
			}
			headers.ttl = ttl;
			argc--;
		}
		else
		{
			PUSHA_ERROR("Ignoring argument '%s'\n", argv[i]);
		}
		i++;
		argc--;
	}

	if(pos_arg < 4)
	{
		PUSHA_ERROR("Not enough arguments [%d]\n", pos_arg);
		usage(argv[0]);
		return 1;
	}

	if(!key)
	{
		PUSHA_ERROR("Private key not set\n");
		ret = 1;
		goto end;
	}

	/**
	 * To generate the vapid token, we must pass just the host from the subscription
	 * endpoint. This function will return the exact position.
	 */
	size_t sep = host_path_separator(endpoint, NULL);
	if(!sep)
	{
		PUSHA_ERROR("Invalid endpoint\n");
		ret = 1;
		goto end;
	}

	if(verbose)
	{
		PUSHA_PRINT(verbose, "-------Arguments------\n");
		PUSHA_PRINT(verbose, "+ Subscribe: %s\n"
				"+ pd256h: %s\n"
				"+ auth: %s\n"
				"+ expiration time: %u\n"
				"+ ttl: %u\n"
				"+ output: %s\n"
				"+ endpoint: %s\n"
				"+ host[%zu]: %.*s\n"
				"+ payload: %s\n",
				sub, p256dh, auth, exp, headers.ttl,
				output == output_print ? "print" : (output == output_curl ? "curl" : "send"),
				endpoint, sep, (int)sep, endpoint,
				payload ? payload : "<no payload>");
		PUSHA_PRINT(verbose, "----------------------\n");
	}

	/**
	 * End of reading arguments from command line
	 */

	PUSHA_PRINT(verbose, "* Decoding subscription...\n");
	push_subscription nsub = {};
	if(!decode_subscription(&nsub, endpoint, p256dh, auth))
	{
		PUSHA_ERROR("*- Error decoding subscription...\n");
		ret = 1;
		goto end;
	}
	PUSHA_PRINT(verbose, "*+ Subscription decoded\n");

	PUSHA_PRINT(verbose, "* Generating VAPID token...\n");
	if(!generate_vapid(&token, endpoint, sep, sub, strlen(sub), exp, key))
	{
		PUSHA_ERROR("*- Error generating VAPID token\n");
		ret = 1;
		goto end;
	}
	PUSHA_PRINT(verbose, "*+ VAPID token generated...\n");

	if(payload)
	{
		PUSHA_PRINT(verbose, "* Push request with payload\n");
		PUSHA_PRINT(verbose, "* Encoding push payload...\n");
		int err = make_push_payload(&pp, &nsub, payload, strlen(payload), 0);
		if(err != ECE_OK)
		{
			PUSHA_ERROR("*- Error set push payload...[%d]\n", err);
			ret = 1;
			goto end;
		}
		PUSHA_PRINT(verbose, "*+ Push payload encoded success...\n");
		PUSHA_PRINT(verbose, "* Making HTTP headers...\n");
		if(make_push_http_headers(&headers, &token, &pp) != ECE_OK)
		{
			PUSHA_ERROR("*- Error making HTTP headers...\n");
			ret = 1;
			goto end;
		}
		PUSHA_PRINT(verbose, "*+ HTTP headers created\n");
	}
	else
	{
		PUSHA_PRINT(verbose, "* Push request WITHOUT payload\n");
		PUSHA_PRINT(verbose, "* Making HTTP headers...\n");
		if(make_push_http_headers(&headers, &token, NULL) != ECE_OK)
		{
			PUSHA_ERROR("*- Error making HTTP headers...\n");
			ret = 1;
			goto end;
		}
		PUSHA_PRINT(verbose, "*+ HTTP headers created\n");
	}

	PUSHA_PRINT(verbose, "* Creating output...\n");
	switch(output)
	{
		case output_print:
				printf("\n");
				PUSHA_PRINT(verbose, "* Printing HTTP request:\n");
				print_http_request(endpoint, &headers, payload ? pp.cipher_payload : NULL, payload ? pp.cipher_payload_len : 0);
			break;
		case output_curl:
			{
				char* curlo = curl_output(endpoint, &headers,
						payload ? pp.cipher_payload : NULL, payload ? pp.cipher_payload_len : 0);
				if(curlo)
				{
					PUSHA_PRINT(verbose, "* CURL Output:");
					printf("\n%s\n", curlo);
					PUSHA_PRINT(verbose, "\n*+ Output created\n");
					free(curlo);
				}
				else{
					PUSHA_PRINT(verbose, "\n*- Output create FAILED\n");
				}
			}
			break;
		default:
		{
			PUSHA_PRINT(verbose, "* Sending push request...\n");
			send_web_push(endpoint, &headers,
					pp.cipher_payload_len ?
					pp.cipher_payload : 0, pp.cipher_payload_len,
					verbose);
		}
			break;
	}
end:
	free_push_payload(&pp);
	free_vapid(&token);
	EC_KEY_free(key);
	free_push_http_headers(&headers);
	return ret;
}
