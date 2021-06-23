/* https://stackoverflow.com/a/50791866/4804196 */

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define KEYFILE			"private.pem"
#define SIGFILE			"signature.dat"
#define ED25519_SIGSIZE		64

static const char private_key_buf[] = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIE5W6qB5AHqcU8ZySRanv2ZUxFiT9RASWc8MtYzOI8ID\n-----END PRIVATE KEY-----";
static const char public_key_buf[]  = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA35z7NBOUc8wK2XIFRpi9zCLeZK0BkhJ6M2OG/kfbKwk=\n-----END PUBLIC KEY-----";
static const char message_to_sign[] = "loremipsum";

// bench_start returns a timestamp for use to measure the start of a benchmark
// run.
__attribute__ ((always_inline)) static inline uint64_t bench_start(void)
{
  unsigned  cycles_low, cycles_high;
  asm volatile( "CPUID\n\t" // serialize
                "RDTSC\n\t" // read clock
                "MOV %%edx, %0\n\t"
                "MOV %%eax, %1\n\t"
                : "=r" (cycles_high), "=r" (cycles_low)
                :: "%rax", "%rbx", "%rcx", "%rdx" );
  return ((uint64_t) cycles_high << 32) | cycles_low;
}

// bench_end returns a timestamp for use to measure the end of a benchmark run.
__attribute__ ((always_inline)) static inline uint64_t bench_end(void)
{
  unsigned  cycles_low, cycles_high;
  asm volatile( "RDTSCP\n\t" // read clock + serialize
                "MOV %%edx, %0\n\t"
                "MOV %%eax, %1\n\t"
                "CPUID\n\t" // serialize -- but outside clock region!
                : "=r" (cycles_high), "=r" (cycles_low)
                :: "%rax", "%rbx", "%rcx", "%rdx" );
  return ((uint64_t) cycles_high << 32) | cycles_low;
}

static EVP_PKEY *read_secret_key_from_file(const char *fname)
{
	EVP_PKEY *key = NULL;
	FILE *fp;

	fp = fopen(fname, "r");
	if (fp == NULL) {
		perror("fopen");
		return NULL;
	}

	key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	return key;
}

static EVP_PKEY *read_secret_key_from_buffer(const char *buffer)
{
	EVP_PKEY *key = NULL;
	BIO *bufio;
	char err_buf[512];

	bufio = BIO_new_mem_buf(buffer, -1);
	if (bufio == NULL) {
		fprintf(stderr, "BIO_new_mem_buf: %s\n", ERR_error_string(ERR_get_error(), err_buf));
		goto out;
	}
	key = PEM_read_bio_PrivateKey(bufio, NULL, NULL, NULL);
	if (key == NULL)
		fprintf(stderr, "PEM_read_bio_PrivateKey: %s", ERR_error_string(ERR_get_error(), err_buf));

	BIO_free(bufio);
out:
	return key;
}

static EVP_PKEY *read_public_key_from_buffer(const char *buffer) {
	EVP_PKEY *key = NULL;
	BIO *bufio;
	char err_buf[512];

	bufio = BIO_new_mem_buf(buffer, -1);
	if (bufio == NULL) {
		fprintf(stderr, "BIO_new_mem_buf: %s\n", ERR_error_string(ERR_get_error(), err_buf));
		goto out;
	}
	key = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
	if (key == NULL)
		fprintf(stderr, "PEM_read_bio_PrivateKey: %s", ERR_error_string(ERR_get_error(), err_buf));

	BIO_free(bufio);
out:
	return key;
}

static void print_hex(const void *buffer, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("\\x%02x", *((unsigned char *) buffer + i));
	printf("\n");
}

static int write_signature_to_file(const char *fname, unsigned char *sig, size_t slen)
{
	FILE *fp;

	fp = fopen(fname, "w");
	if (fp == NULL) {
		perror("fopen");
		return 0;
	}
	fwrite(sig, 1, slen, fp);
	fclose(fp);

	return 1;
}

static int do_sign(EVP_PKEY *key, const unsigned char *msg, const size_t mlen,
		unsigned char *sig, size_t *slen)
{
	EVP_MD_CTX *mdctx = NULL;
	char err_buf[512];
	int ret = 0;

	/* Create the Message Digest Context. */
	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL) {
		perror("EVP_MD_CTX_create");
		goto err_md_create;
	}

	/*
	 * Initialize the DigestSign operation.
	 * No message digest algorithm and no engine for ed25519.
	 */
	ret = EVP_DigestSignInit(mdctx, NULL, NULL, NULL, key);
	if (ret != 1) {
		fprintf(stderr, "EVP_DigestSignInit: %s\n", ERR_error_string(ERR_get_error(), err_buf));
		goto err_digest;
	}

	/* Do the DigestSign operation. */
	ret = EVP_DigestSign(mdctx, sig, slen, msg, mlen);
	if (ret != 1) {
		fprintf(stderr, "EVP_DigestSign: %s\n", ERR_error_string(ERR_get_error(), err_buf));
		goto err_digest;
	}

	/* Success */
	return 1;

err_digest:
	EVP_MD_CTX_destroy(mdctx);
err_md_create:
	return ret;
}

static int do_verify(EVP_PKEY *pub_key, unsigned char *signature, size_t slen,
					  const unsigned char *message, size_t mlen, uint8_t *auth_status) {
	EVP_MD_CTX *mdctx = NULL;
	char err_buf[512];
	int ret = 0;

	/* Create the Message Digest Context. */
	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL) {
		perror("EVP_MD_CTX_create");
		goto err_md_create;
	}

	/*
	 * Initialize the DigestVerify operation.
	 * No message digest algorithm and no engine for ed25519.
	 */
	ret = EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pub_key);
	if (ret != 1) {
		fprintf(stderr, "EVP_DigestVerifyInit: %s\n", ERR_error_string(ERR_get_error(), err_buf));
		goto err_digest;
	}

	/* Do the DigestVerify operation. */
	ret = EVP_DigestVerify(mdctx, signature, slen, message, mlen);
	if (ret < 0) {
		goto err_digest;
	}

	if (ret == 1) {
		*auth_status = 1;
	} else {
		*auth_status = 0;
	}

	/* Success */
	return 1;
err_digest:
	EVP_MD_CTX_destroy(mdctx);
err_md_create:
	return ret;
}


int main(int argc, char **argv)
{	
	uint64_t overhead, t_start, t_end;
	uint8_t auth_status = 0;
	int ret;
	size_t iterations;
	size_t slen = ED25519_SIGSIZE;
	unsigned char msg[512];
	unsigned char sig[ED25519_SIGSIZE];
	EVP_PKEY *key;

	key = read_secret_key_from_buffer(private_key_buf);
	if (!key)
		exit(EXIT_FAILURE);

	fscanf(stdin, "%ld", &iterations);

	memset(msg, 0, 512);
	memcpy(msg, message_to_sign, sizeof(message_to_sign));

	overhead = 0;
	for (size_t i = 0; i < iterations; i++) {
		t_start = bench_start();
		ret = do_sign(key, msg, 512, sig, &slen);
		t_end = bench_end();
		if (ret != 1)
			exit(EXIT_FAILURE);
		overhead += t_end - t_start;
	}

	printf("\n[IT=%ld] Average Signing time: %lf\n", iterations, (1.0 * overhead) / (iterations * CLOCKS_PER_SEC));	



	// printf("Signature: ");
	// print_hex(sig, slen);
	// EVP_PKEY_free(key);

	key = read_public_key_from_buffer(public_key_buf);
	if (!key) {
		exit(EXIT_FAILURE);
	}

	overhead = 0;
	for (size_t i = 0; i < iterations; i++) {
		t_start = bench_start();
		ret = do_verify(key, sig, slen, msg, 512, &auth_status);
		t_end = bench_end();
		if (ret != 1)
			exit(EXIT_FAILURE);
		overhead += t_end - t_start;
	}
	
	printf("\n[IT=%ld] Average Verifying time: %lf\n", iterations, (1.0 * overhead) / (iterations * CLOCKS_PER_SEC));	

	EVP_PKEY_free(key);

	// if (auth_status) {
	// 	printf("Authentic signature!\n");
	// } else {
	// 	printf("Not an authentic signature!\n");
	// }


	return 0;
}
