/**
 * Export public key providing a EC private key.
 *
 * Key can be exported in base64url encoded or PEM file.
 */

#include <stdio.h>
#include <string.h>
#include "pusha/ec_keys.h"

void usage(const char* program)
{
	printf("Usage:\n");
	printf("\t%s -h|<priv_key_pem_file|base64url_priv_key> [<export_pem_file>]\n", program);
	printf("Where:\n");
	printf("\t-h\tThis help message.\n");
	printf("\t<priv_key_pem_file>\n\t\tPEM file with private key to be exported.\n");
	printf("\t<base64url_priv_key>\n\t\tBase64url encoded privated key to be exported.\n");
	printf("\t<export_pem_file>\n\t\tIf provided, export public key to file name.\n");
}


int main(int argc, char** argv)
{
	if(argc != 2 && argc != 3)
	{
		fprintf(stderr, "ERROR! Wrong number of arguments! [%d]\n", argc);
		usage(argv[0]);
		return 1;
	}

	if(strcmp(argv[1], "-h") == 0)
	{
		usage(argv[0]);
		return 0;
	}

	EC_KEY* key = import_private_key_pem_file(argv[1]);
	if(!key)
	{
		key = import_private_key_base64(argv[1]);
		if(!key)
		{
			fprintf(stderr, "ERROR! Invalid argument!\n'%s' is not a valid PEM file or base64url encoded key.\n", argv[1]);
			return 2;
		}
	}

	if(EC_KEY_check_key(key) == 0)
	{
		fprintf(stderr, "ERROR! Key provided is not valid! [%s]\n", argv[1]);
		return 3;
	}

	const char* public_key = export_public_key(key);
	if(!public_key)
	{
		fprintf(stderr, "ERROR exporting public key.\n");
		return 4;
	}

	printf("Public: %s\n", public_key);

	if(argc == 3)
	{
		if(export_public_key_pem(key, argv[2]) != 0)
		{
			fprintf(stderr, "ERROR exporting to PEM file! [%s]\n", argv[2]);
			return 5;
		}
	}

	return 0;
}
