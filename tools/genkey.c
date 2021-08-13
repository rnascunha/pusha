#include <stdio.h>
#include "pusha/ec_keys.h"
#include "ece.h"
#include <openssl/ec.h>
#include <string.h>

int output_base64(EC_KEY* key, char** private, char** public)
{
	if(!key)
	{
		fprintf(stderr, "Invalid key\n");
		return 0;
	}

	*private = export_private_key(key);
	if(!*private)
	{
		fprintf(stderr, "Failed export private key");
		return 0;
	}

	*public = export_public_key(key);
	if(!*public)
	{
		fprintf(stderr, "Failed export public key\n");
		return 0;
	}

	return 1;
}

int output_pem_file(EC_KEY* key, const char* private_file, const char* public_file)
{
	if(!key)
	{
		fprintf(stderr, "Invalid key\n");
		return 0;
	}

	int ret;
	if(private_file)
	{
		ret = export_private_key_pem(key, private_file);
		if(ret != ECE_OK)
		{
			fprintf(stderr, "Error exporting private key to PEM file [%d]\n", ret);
			return 0;
		}
	}

	if(public_file)
	{
		ret = export_public_key_pem(key, public_file);
		if(ret != ECE_OK)
		{
			fprintf(stderr, "Error exporting public key to PEM file [%d]\n", ret);
			return 0;
		}
	}

	return 1;
}

static void usage(const char* program)
{
	printf("Usage:\n\t%s -h|[-p private_pem_file] [-u public_pem_file]\n", program);
	printf("Where:\n");
	printf("\t-h\tprint this help message\n");
	printf("\t-p\toutput private key to pem file specified\n");
	printf("\t-u\toutput public key to pem file specified\n");
}

int main(int argc, char** argv)
{
	int ret = 0;
	char *private = NULL, *public = NULL,
		*pem_priv_file = NULL, *pem_pub_file = NULL;

	int i = 1;
	argc--;
	while(argc--)
	{
		if(strcmp(argv[i], "-h") == 0)
		{
			usage(argv[0]);
			return 0;
		}
		else if(strcmp(argv[i], "-p") == 0)
		{
			if(argc == 0)
			{
				fprintf(stderr, "'-p' option must have a argument\n");
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
				fprintf(stderr, "'-u' option must have a argument\n");
				usage(argv[0]);
				return 1;
			}
			pem_pub_file = argv[++i];
			argc--;
		}
		else
		{
			fprintf(stderr, "Ignoring argument '%s'\n", argv[i]);
		}
		i++;
	}

	EC_KEY* key = generate_keys();
	if(!key)
	{
		fprintf(stderr, "Error generating keys");
		ret = 2;
		goto end;
	}

	if(!output_base64(key, &private, &public))
	{
		ret = 3;
		goto end;
	}
	printf("Private: %s\nPublic: %s\n", private, public);

	output_pem_file(key, pem_priv_file, pem_pub_file);
end:
	free(private);
	free(public);
	free_key(key);

	return ret;
}
