#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 443

void init_ssl();
SSL_CTX *ssl_ctx();
int sock_listn();

int
sock_listn()
{
	int lfd;
	struct sockaddr_in adr;

	memset(&adr, 0, sizeof(adr)); /* Zero out the struct */

	adr.sin_family = AF_INET; /* IPv4 */
	adr.sin_addr.s_addr = htonl(INADDR_ANY); /* 0.0.0.0 */
	adr.sin_port = htons(PORT);

	if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) { /* IPv4, TCP, Default based on request */
		fprintf(stderr, "Failed to create socket\n");
		exit(-1);
	}
	if (bind(lfd, (struct sockaddr*) &adr, sizeof(adr)) < 0) {
		fprintf(stderr, "Failed to bind\n");
		exit(-1);
	}
	if (listen(lfd, 3) < 0) {
		fprintf(stderr, "Failed to listen\n");
		exit(-1);
	}
	return lfd;
}

SSL_CTX *
ssl_ctx(char *cert, char *key)
{
	const SSL_METHOD * m;
	SSL_CTX *ctx;

	m = SSLv23_server_method();
	if (!(ctx = SSL_CTX_new(m))) {
		fprintf(stderr, "Failed to create SSL context\n");
		exit(-1);
	}

	SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Failed to use %s as cert\n", cert);
		exit(-1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
		fprintf(stderr, "Failed to use %s as key\n", key);
		exit(-1);
    }
	return ctx;
}

void
init_ssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

int
main(int argc, char **argv)
{
	int lfd, cfd;
	SSL_CTX *ctx;

	if (argc < 3) {
		fprintf(stderr, "USAGE: %s <SSL-CERT> <SSL-PRIV-KEY>\n", argv[0]);
		exit(-1);
	}
	if (getuid()) {
		fprintf(stderr, "Run as root\n");
		exit(-1);
	}
	/* Setup SSL */
	init_ssl();
	ctx = ssl_ctx(argv[1], argv[2]);

	lfd = sock_listn();

	while (1) {
		SSL *ssl;
		const char reply[] = "testing\n";

		if ((cfd = accept(lfd, (struct sockaddr*) NULL, NULL)) < 0) {
			fprintf(stderr, "Failed to accept connections\n");
			exit(-1);
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, cfd);
		if (SSL_accept(ssl) == 1)
			SSL_write(ssl, reply, strlen(reply));
		else {
			fprintf(stderr, "Failed to accept SSL connections\n");
			exit(-1);
		}

		SSL_free(ssl);
		close(cfd);
	}
	/* Cleanup */
	close(lfd);
	SSL_CTX_free(ctx);
	EVP_cleanup();
}
