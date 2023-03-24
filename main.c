
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslconf.h>
#include "C:\Program Files\OpenSSL-Win64\include\openssl\applink.c"

#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
#include <openssl/conf.h>
#endif

#define BASE64_LOGIN
#define BASE64_PASSWORD
const char HOST_NAME[] = "smtp.gmail.com";
const char HOST_PORT[] = "465";

void init_openssl_library(void)
{
	(void)SSL_library_init();
	SSL_load_error_strings();
	// ERR_load_crypto_strings();
	// OPENSSL_config(NULL);
#if defined (OPENSSL_THREADS)
	fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

void handleFailure(const char *s)
{
	printf("failed at %s\n", s);
	ERR_print_errors_fp(stdout);
	exit(1);
}

int main()
{
	long res = 1;

	SSL_CTX *ctx = NULL;
	BIO *web = NULL, *out = NULL;
	SSL *ssl = NULL;

	init_openssl_library();

	const SSL_METHOD *method = SSLv23_method();
	if (method == NULL) handleFailure("method");

	ctx = SSL_CTX_new(method);
	if (ctx == NULL) handleFailure("new ctx");

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	SSL_CTX_set_verify_depth(ctx, 4);

	const long flags
		= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(ctx, flags);

	res = SSL_CTX_load_verify_locations(ctx, "gmail-cert.pem", NULL);
	if (res != 1) handleFailure("verify locations");

	web = BIO_new_ssl_connect(ctx);
	if (web == NULL) handleFailure("new ssl connect");

	char *name = malloc(strlen(HOST_NAME) + strlen(HOST_PORT) + 1 + 1);
	if (name == NULL) handleFailure("malloc fail");
	strcpy(name, HOST_NAME);
	strcat(name, ":");
	strcat(name, HOST_PORT);
	res = BIO_set_conn_hostname(web, name);
	if (res != 1) handleFailure("set conn hostname");
	free(name);

	BIO_get_ssl(web, &ssl);
	if (ssl == NULL) handleFailure("get ssl");

	const char PREFERRED_CIPHERS[] = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
	res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
	if (res != 1) handleFailure("set cipher list");

	res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
	if (res != 1) handleFailure("set tlsext");

	res = X509_VERIFY_PARAM_set1_host(
		SSL_get0_param(ssl),
		HOST_NAME,
		strlen(HOST_NAME)
	);
	if (res != 1) handleFailure("set1_host() fail");

	out = BIO_new_fp(stdout, BIO_NOCLOSE);
	if (out == NULL) handleFailure("new fp");

	res = BIO_do_connect(web);
	if (res != 1) handleFailure("connect");

	res = BIO_do_handshake(web);
	if (res != 1) handleFailure("handshake");

	X509 *cert = SSL_get_peer_certificate(ssl);
	if (cert) X509_free(cert);
	if (cert == NULL) handleFailure("get peer cert");

	res = SSL_get_verify_result(ssl);
	if (res != X509_V_OK) handleFailure("verify result");

	int len = 0;
	char buff[4096];

	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);
	BIO_puts(web, "HELO localhost\r\n");
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	BIO_puts(web, "AUTH LOGIN\r\n");
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	BIO_puts(web, BASE64_LOGIN "\r\n");
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	BIO_puts(web, BASE64_PASSWORD "\r\n");
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	BIO_puts(web, "MAIL FROM:<mail@host.com>\r\n");
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	BIO_puts(web, "RCPT TO:<mail@host.me>\r\n");
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	BIO_puts(web, "DATA\r\n");
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	BIO_puts(
		web,
		"To: John Doe\r\n"
		"From: Doe John\r\n"
		"Subject: email from app\r\n"
		"email body\r\n"
		".\r\n"
	);
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	BIO_puts(web, "QUIT\r\n");
	BIO_puts(out, "\n");
	len = BIO_read(web, buff, sizeof(buff));
	BIO_write(out, buff, len);

	if (out) BIO_free(out);
	if (web != NULL) BIO_free_all(web);
	if (ctx != NULL) SSL_CTX_free(ctx);

	return 0;
}