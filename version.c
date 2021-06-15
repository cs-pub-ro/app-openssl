/*openssl_version.c*/

#include <openssl/ssl.h>

int main(void)
{
	printf("OpenSSL version: %s\n", OpenSSL_version(SSLEAY_VERSION));
	return 0;
}
